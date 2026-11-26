"""Render the triage as Markdown (PR comment / job summary) or JSON."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field

from scan_triage.models import Finding, Severity
from scan_triage.suppress import Suppression

SEV_ICON = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟦",
    Severity.INFO: "⬜",
}


@dataclass
class Triage:
    active: list[Finding]
    suppressed: list[Finding] = field(default_factory=list)
    expired: list[Suppression] = field(default_factory=list)
    unused: list[Suppression] = field(default_factory=list)
    raw_count: int = 0
    false_positives: int = 0
    reports: list[str] = field(default_factory=list)


def md(text: str) -> str:
    """Escape untrusted scanner text for safe use inside markdown and HTML."""
    return (
        text.replace("\\", "\\\\")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("\n", " ")
    )


def _n(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _where(f: Finding) -> str:
    first = f"`{md(f.locations[0])}`"
    return first + (f" +{len(f.locations) - 1} more" if len(f.locations) > 1 else "")


def to_markdown(t: Triage, top: int = 10) -> str:
    counts = Counter(f.severity for f in t.active)
    sev_line = " · ".join(
        f"{SEV_ICON[s]} {counts[s]} {s.label}" for s in sorted(Severity, reverse=True) if counts[s]
    )
    lines = [
        "## 🛡️ Security scan triage",
        "",
        f"**{len(t.active)} findings to review** (from {t.raw_count} raw results across "
        f"{_n(len(t.reports), 'report')}) · {len(t.suppressed)} suppressed · "
        f"{_n(t.false_positives, 'false positive')} dropped",
        "",
        sev_line or "No active findings. 🎉",
        "",
    ]

    if t.expired:
        lines += ["### ⚠️ Expired suppressions (these findings are back)", ""]
        lines += [
            f"- `{md(s.label)}` expired {s.expires.isoformat()}: {md(s.reason)}" for s in t.expired
        ]
        lines.append("")

    if t.active:
        lines += [
            f"### Top {min(top, len(t.active))} by risk",
            "",
            "| # | Score | Severity | Finding | Where | Tools |",
            "|--:|--:|---|---|---|---|",
        ]
        for i, f in enumerate(t.active[:top], 1):
            lines.append(
                f"| {i} | **{f.score}** | {SEV_ICON[f.severity]} {f.severity.label} | "
                f"{md(f.title)} | {_where(f)} | {', '.join(f.tools)} |"
            )
        lines.append("")
        for i, f in enumerate(t.active[:top], 1):
            lines += [f"<details><summary>#{i} {md(f.title)}</summary>", ""]
            lines.append(f"- **Rule:** `{md(f.rule_key)}`{' · ' + md(f.cwe) if f.cwe else ''}")
            lines.append(f"- **Fingerprint:** `{f.fingerprint}`")
            lines.append(f"- **Why score {f.score}:** " + "; ".join(md(r) for r in f.reasons))
            if len(f.locations) > 1:
                lines.append("- **Locations:** " + ", ".join(f"`{md(loc)}`" for loc in f.locations))
            if f.fix:
                lines.append(f"- **Fix:** {md(f.fix[:400])}")
            if f.explanation:
                lines.append(
                    f"- **🤖 AI explanation** _(does not affect score)_: {md(f.explanation)}"
                )
            lines += ["", "</details>", ""]
        if len(t.active) > top:
            lines += [f"_...and {len(t.active) - top} lower-risk findings in the JSON report._", ""]

    if t.suppressed:
        lines += [f"<details><summary>{len(t.suppressed)} suppressed findings</summary>", ""]
        lines += [f"- {md(f.title)} ({_where(f)}): {md(f.suppressed_by)}" for f in t.suppressed]
        lines += ["", "</details>", ""]
    if t.unused:
        lines += ["### 🧹 Unused suppressions (safe to delete)", ""]
        lines += [f"- `{md(s.label)}`: {md(s.reason)}" for s in t.unused]
        lines.append("")

    lines.append(
        "<sub>Scores are rule-based and reproducible: base by severity, adjusted for scanner "
        "confidence, test-only code, available fixes and multi-tool agreement.</sub>"
    )
    return "\n".join(lines) + "\n"


def _finding_dict(f: Finding) -> dict:
    return {
        "fingerprint": f.fingerprint,
        "score": f.score,
        "severity": f.severity.label,
        "tool": f.tool,
        "tools": f.tools,
        "rule": f.rule_key,
        "cwe": f.cwe,
        "title": f.title,
        "locations": f.locations,
        "reasons": f.reasons,
        "fix": f.fix,
        "explanation": f.explanation,
        "sources": sorted(f.sources),
        "suppressed_by": f.suppressed_by,
    }


def to_json(t: Triage) -> str:
    return json.dumps(
        {
            "summary": {
                "active": len(t.active),
                "suppressed": len(t.suppressed),
                "raw": t.raw_count,
                "false_positives_dropped": t.false_positives,
                "by_severity": {s.label: sum(f.severity == s for f in t.active) for s in Severity},
                "reports": t.reports,
            },
            "findings": [_finding_dict(f) for f in t.active],
            "suppressed": [_finding_dict(f) for f in t.suppressed],
            "expired_suppressions": [s.label for s in t.expired],
            "unused_suppressions": [s.label for s in t.unused],
        },
        indent=2,
    )
