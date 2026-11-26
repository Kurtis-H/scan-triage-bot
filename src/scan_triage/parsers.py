"""Convert ZAP, Trivy and SARIF (Semgrep, Bandit, CodeQL, ...) reports into Findings.

All scanner output is treated as untrusted: it can contain text taken from the scanned
app or repo (page content, code, commit data), which may be crafted by an attacker.
"""

from __future__ import annotations

import html
import json
import os
import re
from urllib.parse import parse_qsl, urlsplit

from scan_triage.models import Finding, Severity

_TAG = re.compile(r"<[^>]+>")
_CWE = re.compile(r"CWE-(\d+)", re.I)
MAX_TEXT = 2000


class ParseError(Exception):
    pass


def _clean(text: str | None) -> str:
    """Strip HTML from scanner text and cap its length."""
    text = html.unescape(_TAG.sub(" ", text or ""))
    return re.sub(r"\s+", " ", text).strip()[:MAX_TEXT]


def detect_format(data: dict) -> str:
    if "runs" in data and ("$schema" in data or data.get("version") == "2.1.0"):
        return "sarif"
    if "site" in data and ("@version" in data or "@programName" in data):
        return "zap"
    if "Results" in data and ("SchemaVersion" in data or "ArtifactName" in data):
        return "trivy"
    raise ParseError("unrecognised report format (expected SARIF, ZAP JSON or Trivy JSON)")


def load_report(path: str) -> tuple[list[Finding], int]:
    """Returns (findings, number of findings dropped as false positives)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ParseError(f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(f"{path}: expected a JSON object")

    fmt = detect_format(data)
    findings, dropped = {"sarif": parse_sarif, "zap": parse_zap, "trivy": parse_trivy}[fmt](data)
    source = os.path.basename(path)
    for finding in findings:
        finding.sources.add(source)
    return findings, dropped


# --- OWASP ZAP (traditional JSON report, `-J report.json`) -------------------------

ZAP_RISK = {"0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM, "3": Severity.HIGH}
# ZAP confidence: 0 = false positive, 1 low, 2 medium, 3 high, 4 user confirmed
ZAP_CONFIDENCE = {"1": 0.6, "2": 0.85, "3": 1.0, "4": 1.0}


def _zap_location(instance: dict) -> str:
    """'GET http://localhost:8000/api/products?q=abc' -> 'GET /api/products?q'.
    Host and parameter values are dropped so the same issue on different environments or
    with different inputs is recognised as one issue."""
    parts = urlsplit(instance.get("uri", ""))
    params = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    path = (parts.path or "/") + ("?" + "&".join(params) if params else "")
    return f"{instance.get('method', 'GET').upper()} {path}"


def parse_zap(data: dict) -> tuple[list[Finding], int]:
    findings, dropped = [], 0
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            confidence = str(alert.get("confidence", "2"))
            if confidence == "0":
                dropped += 1
                continue
            locations = sorted({_zap_location(i) for i in alert.get("instances", [])}) or [
                "(site-wide)"
            ]
            cwe = str(alert.get("cweid", "")).strip()
            findings.append(
                Finding(
                    tool="zap",
                    rule_id=str(alert.get("pluginid") or alert.get("alertRef") or "unknown"),
                    title=_clean(alert.get("alert") or alert.get("name")),
                    severity=ZAP_RISK.get(str(alert.get("riskcode")), Severity.INFO),
                    locations=locations,
                    description=_clean(alert.get("desc")),
                    fix=_clean(alert.get("solution")),
                    cwe=f"CWE-{cwe}" if cwe and cwe not in ("-1", "0") else "",
                    confidence=ZAP_CONFIDENCE.get(confidence, 0.85),
                )
            )
    return findings, dropped


# --- Trivy (`trivy fs --format json`) ------------------------------------------------

TRIVY_SEV = {"UNKNOWN": Severity.INFO, "LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM,
             "HIGH": Severity.HIGH, "CRITICAL": Severity.CRITICAL}  # fmt: skip


def _trivy_sev(value: str | None) -> Severity:
    return TRIVY_SEV.get((value or "UNKNOWN").upper(), Severity.INFO)


def parse_trivy(data: dict) -> tuple[list[Finding], int]:
    findings = []
    for result in data.get("Results") or []:
        target = result.get("Target", "?")
        for v in result.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion") or ""
            cwes = v.get("CweIDs") or []
            pkg = f"{v.get('PkgName', '?')} {v.get('InstalledVersion', '')}".strip()
            findings.append(
                Finding(
                    tool="trivy",
                    rule_id=v.get("VulnerabilityID", "unknown"),
                    title=_clean(
                        f"{v.get('VulnerabilityID')}: {v.get('Title') or v.get('PkgName')}"
                    ),
                    severity=_trivy_sev(v.get("Severity")),
                    locations=[f"{target} ({pkg})"],
                    description=_clean(v.get("Description")),
                    fix=f"Upgrade {v.get('PkgName')} to {fixed}"
                    if fixed
                    else "No fixed version yet",
                    cwe=cwes[0] if cwes else "",
                    fix_available=bool(fixed),
                )
            )
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine")
            findings.append(
                Finding(
                    tool="trivy",
                    rule_id=m.get("ID") or m.get("AVDID", "unknown"),
                    title=_clean(m.get("Title")),
                    severity=_trivy_sev(m.get("Severity")),
                    locations=[f"{target}:{line}" if line else target],
                    description=_clean(m.get("Message") or m.get("Description")),
                    fix=_clean(m.get("Resolution")),
                )
            )
        for s in result.get("Secrets") or []:
            # Never copy the matched secret into a report that may be posted publicly.
            findings.append(
                Finding(
                    tool="trivy",
                    rule_id=s.get("RuleID", "secret"),
                    title=_clean(f"Exposed secret: {s.get('Title', s.get('RuleID', ''))}"),
                    severity=_trivy_sev(s.get("Severity")),
                    locations=[f"{target}:{s.get('StartLine', '?')}"],
                    description="A credential appears to be committed to the repository. "
                    "The matched value is intentionally not shown.",
                    fix="Rotate the credential, then remove it from the code and git history.",
                    cwe="CWE-798",
                )
            )
    return findings, 0


# --- SARIF 2.1.0 (Semgrep, Bandit, CodeQL, Trivy --format sarif, ...) -----------------

SARIF_LEVEL = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW,
               "none": Severity.INFO}  # fmt: skip


def _sarif_severity(result: dict, rule: dict) -> Severity:
    # GitHub's convention: a CVSS-style score in rule.properties["security-severity"].
    raw = (rule.get("properties") or {}).get("security-severity")
    try:
        if raw is None:
            raise ValueError("no security-severity")
        score = float(raw)
    except (TypeError, ValueError):
        level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
        return SARIF_LEVEL.get(level or "warning", Severity.MEDIUM)
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


def _sarif_location(result: dict) -> str:
    for loc in result.get("locations") or []:
        phys = loc.get("physicalLocation") or {}
        uri = (phys.get("artifactLocation") or {}).get("uri", "")
        line = (phys.get("region") or {}).get("startLine")
        if uri:
            return f"{uri.removeprefix('file://')}:{line}" if line else uri
    return "(unknown location)"


def parse_sarif(data: dict) -> tuple[list[Finding], int]:
    findings, dropped = [], 0
    for run in data.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = re.sub(r"\W+", "-", (driver.get("name") or "sarif").lower()).strip("-")
        rules = {r.get("id"): r for r in driver.get("rules") or []}
        for result in run.get("results") or []:
            if result.get("suppressions"):
                dropped += 1  # already suppressed in-source by the tool
                continue
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or "unknown"
            rule = rules.get(rule_id, {})
            tags = " ".join((rule.get("properties") or {}).get("tags") or [])
            cwe_match = _CWE.search(tags)
            title = (rule.get("shortDescription") or {}).get("text") or rule_id
            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    title=_clean(title),
                    severity=_sarif_severity(result, rule),
                    locations=[_sarif_location(result)],
                    description=_clean((result.get("message") or {}).get("text")),
                    fix=_clean((rule.get("help") or {}).get("text")),
                    cwe=f"CWE-{cwe_match.group(1)}" if cwe_match else "",
                )
            )
    return findings, dropped
