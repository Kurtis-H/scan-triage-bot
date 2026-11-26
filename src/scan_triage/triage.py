"""Deduplicate, score and rank findings with deterministic, explainable rules.

The AI never touches this: severity and ranking come only from the rules below, and every
score lists the reasons behind it, so a reviewer can check exactly why something ranked
where it did.
"""

from __future__ import annotations

import re

from scan_triage.models import Finding, Severity

BASE_SCORE = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 40,
    Severity.LOW: 15,
    Severity.INFO: 2,
}
NON_PROD_PATH = re.compile(
    r"(^|/)(tests?|spec|__tests__|examples?|docs?|fixtures?)(/|$)"
    r"|(^|/)requirements-dev[^/]*$|(^|/)dev-requirements[^/]*$",
    re.I,
)


def _file_of(location: str) -> str:
    """'app/main.py:80' -> 'app/main.py', 'requirements.txt (pkg)' -> 'requirements.txt'."""
    return re.sub(r"(:\d+)?( \(.*\))?$", "", location)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """1) Same fingerprint (same tool + rule, same place) -> one finding, merged sources.
    2) Different tools, same CWE at the same file:line -> one finding, noting both tools."""
    by_fp: dict[str, Finding] = {}
    for f in findings:
        existing = by_fp.get(f.fingerprint)
        if existing is None:
            by_fp[f.fingerprint] = f
            continue
        existing.sources |= f.sources
        existing.locations = sorted(set(existing.locations) | set(f.locations))
        if f.severity > existing.severity:
            existing.severity = f.severity
        existing.confidence = max(existing.confidence, f.confidence)

    first_at: dict[tuple[str, str], Finding] = {}
    out: list[Finding] = []
    # Highest severity first, so a merged finding keeps the most informative tool's details.
    for f in sorted(by_fp.values(), key=lambda x: -x.severity):
        if f.cwe and f.tool != "zap" and len(f.locations) == 1:
            key = (f.cwe, f.locations[0])
            first = first_at.get(key)
            if first is not None and first.tool != f.tool:
                first.also_reported_by |= {f.tool, *f.also_reported_by}
                first.sources |= f.sources
                first.severity = max(first.severity, f.severity)
                continue
            first_at.setdefault(key, f)
        out.append(f)
    return out


def score(f: Finding) -> Finding:
    reasons = [f"{f.severity.label} severity: base {BASE_SCORE[f.severity]}"]
    value = float(BASE_SCORE[f.severity])

    if f.confidence < 1.0:
        value *= f.confidence
        reasons.append(f"scanner confidence {f.confidence:.0%}: x{f.confidence:g}")

    files = [_file_of(loc) for loc in f.locations if not loc.startswith(("GET ", "POST ", "PUT ",
             "PATCH ", "DELETE ", "HEAD ", "OPTIONS ", "("))]  # fmt: skip
    if files and all(NON_PROD_PATH.search(p) for p in files):
        value *= 0.5
        reasons.append("only in test/dev/example files: x0.5")

    if f.fix_available:
        value += 10
        reasons.append("fixed version available (easy win): +10")

    tools = f.tools
    if len(tools) > 1:
        value += 10
        reasons.append(f"confirmed by {len(tools)} tools ({', '.join(tools)}): +10")

    if len(f.locations) > 1:
        bonus = min(len(f.locations) - 1, 5)
        value += bonus
        reasons.append(f"{len(f.locations)} locations: +{bonus}")

    f.score = max(0, min(100, round(value)))
    f.reasons = reasons
    return f


def rank(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        score(f)
    return sorted(
        findings, key=lambda f: (-f.score, -f.severity, f.tool, f.rule_id, f.locations[0])
    )
