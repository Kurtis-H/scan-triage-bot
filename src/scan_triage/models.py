"""The common shape every scanner's output is converted into."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {value!r}; use one of {[s.name.lower() for s in cls]}"
            ) from None

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass
class Finding:
    tool: str  # "zap", "trivy", "semgrep", "bandit"...
    rule_id: str  # the tool's own rule/plugin/CVE id
    title: str
    severity: Severity
    locations: list[str]  # "path/to/file.py:42" or "GET /api/products"
    description: str = ""
    fix: str = ""
    cwe: str = ""  # "CWE-89"
    confidence: float = 1.0  # 0..1, from tools that report it (ZAP)
    fix_available: bool = False  # e.g. Trivy reports a fixed package version
    sources: set[str] = field(default_factory=set)  # report files this came from
    also_reported_by: set[str] = field(default_factory=set)  # other tools, after merging
    # Filled in by later stages:
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    explanation: str = ""
    suppressed_by: str = ""

    @property
    def rule_key(self) -> str:
        return f"{self.tool}:{self.rule_id}"

    @property
    def fingerprint(self) -> str:
        """Stable ID used for dedupe and suppressions. Survives re-runs and line shifts
        elsewhere in the file, but changes if the finding moves to a different location."""
        scope = self.rule_key if self.tool == "zap" else f"{self.rule_key}|{self.locations[0]}"
        return hashlib.sha256(scope.encode()).hexdigest()[:12]

    @property
    def tools(self) -> list[str]:
        return sorted({self.tool, *self.also_reported_by})
