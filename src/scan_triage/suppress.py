"""Suppressions: reviewed decisions to accept a finding, which always expire.

Example `triage-suppressions.toml`:

    [[suppress]]
    rule = "zap:10055"                 # tool:rule_id, a CWE like "CWE-693", or...
    # fingerprint = "3f9a1c2b7d4e"     # ...one exact finding
    path = "app/legacy/*"              # optional glob on the finding's location
    reason = "unsafe-inline styles needed until the CSS refactor (TICKET-123)"
    expires = 2027-03-31               # required - no permanent suppressions

An expired suppression stops working, so the finding comes back and the report says why.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import date
from fnmatch import fnmatch

from scan_triage.models import Finding


class SuppressionError(Exception):
    pass


@dataclass
class Suppression:
    reason: str
    expires: date
    rule: str = ""
    fingerprint: str = ""
    path: str = ""
    used: int = 0

    @property
    def label(self) -> str:
        target = self.fingerprint or self.rule
        return f"{target}{' @ ' + self.path if self.path else ''}"

    def matches(self, f: Finding) -> bool:
        if self.fingerprint and self.fingerprint != f.fingerprint:
            return False
        if self.rule and self.rule.lower() not in (f.rule_key.lower(), f.cwe.lower()):
            return False
        if self.path and not any(fnmatch(loc, self.path) for loc in f.locations):
            return False
        return True


def load(path: str) -> list[Suppression]:
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SuppressionError(f"{path}: {exc}") from exc

    out = []
    for i, entry in enumerate(data.get("suppress", []), start=1):
        where = f"{path} entry #{i}"
        if not (entry.get("rule") or entry.get("fingerprint")):
            raise SuppressionError(f"{where}: needs 'rule' or 'fingerprint'")
        if not str(entry.get("reason", "")).strip():
            raise SuppressionError(f"{where}: needs a 'reason' (why is this acceptable?)")
        expires = entry.get("expires")
        if not isinstance(expires, date):
            raise SuppressionError(f"{where}: needs 'expires' as a date, e.g. expires = 2027-03-31")
        out.append(
            Suppression(
                reason=str(entry["reason"]).strip(),
                expires=expires,
                rule=str(entry.get("rule", "")),
                fingerprint=str(entry.get("fingerprint", "")),
                path=str(entry.get("path", "")),
            )
        )
    return out


def apply(
    findings: list[Finding], suppressions: list[Suppression], today: date | None = None
) -> tuple[list[Finding], list[Finding], list[Suppression], list[Suppression]]:
    """Returns (active findings, suppressed findings, expired suppressions, unused suppressions)."""
    today = today or date.today()
    live = [s for s in suppressions if s.expires >= today]
    expired = [s for s in suppressions if s.expires < today]

    active, suppressed = [], []
    for f in findings:
        rule = next((s for s in live if s.matches(f)), None)
        if rule:
            rule.used += 1
            f.suppressed_by = f"{rule.reason} (until {rule.expires.isoformat()})"
            suppressed.append(f)
        else:
            active.append(f)
    unused = [s for s in live if s.used == 0]
    return active, suppressed, expired, unused
