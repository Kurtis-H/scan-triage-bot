"""Command-line entry point: `scan-triage reports/*.json reports/*.sarif`."""

from __future__ import annotations

import argparse
import glob
import os
import sys

from scan_triage import __version__, explain, suppress
from scan_triage.models import Finding, Severity
from scan_triage.parsers import ParseError, load_report
from scan_triage.report import Triage, to_json, to_markdown
from scan_triage.triage import deduplicate, rank

EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE = 0, 1, 2


def _expand(patterns: list[str]) -> list[str]:
    files: list[str] = []
    for pattern in patterns:
        if os.path.isdir(pattern):
            files += glob.glob(os.path.join(pattern, "*.json")) + glob.glob(
                os.path.join(pattern, "*.sarif")
            )
        else:
            files += glob.glob(pattern, recursive=True)
    return sorted(set(files))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="scan-triage",
        description="Merge ZAP, Trivy and SARIF reports into one deduplicated, ranked list.",
    )
    p.add_argument("reports", nargs="+", help="Report files, globs or directories")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--output", "-o", help="Write to a file instead of stdout")
    p.add_argument("--json-output", help="Also write the full JSON report here")
    p.add_argument("--top", type=int, default=10, help="Findings shown in detail (default 10)")
    p.add_argument("--suppressions", help="TOML suppressions file")
    p.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        help="Exit 1 if any unsuppressed finding is at or above this severity",
    )
    p.add_argument(
        "--explain",
        choices=["none", "fake", "ollama"],
        default="none",
        help="Add plain-English explanations from a local LLM (default none)",
    )
    p.add_argument("--explain-top", type=int, default=5)
    p.add_argument("--ollama-url", default=os.getenv("OLLAMA_URL", "http://localhost:11434"))
    p.add_argument("--ollama-model", default=os.getenv("OLLAMA_MODEL", "llama3.1:8b"))
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    files = _expand(args.reports)
    if not files:
        print("scan-triage: no report files matched", file=sys.stderr)
        return EXIT_USAGE

    raw, dropped, loaded = [], 0, []
    for path in files:
        try:
            findings, fp = load_report(path)
        except ParseError as exc:
            print(f"scan-triage: skipping {exc}", file=sys.stderr)
            continue
        raw += findings
        dropped += fp
        loaded.append(os.path.basename(path))
    if not loaded:
        print("scan-triage: no readable reports", file=sys.stderr)
        return EXIT_USAGE

    raw_count = len(raw)
    findings = rank(deduplicate(raw))

    suppressed: list[Finding] = []
    expired: list[suppress.Suppression] = []
    unused: list[suppress.Suppression] = []
    if args.suppressions:
        try:
            rules = suppress.load(args.suppressions)
        except suppress.SuppressionError as exc:
            print(f"scan-triage: {exc}", file=sys.stderr)
            return EXIT_USAGE
        findings, suppressed, expired, unused = suppress.apply(findings, rules)

    explainer = explain.build(args.explain, args.ollama_url, args.ollama_model)
    explain.explain_top(findings, explainer, args.explain_top)

    triage = Triage(findings, suppressed, expired, unused, raw_count, dropped, loaded)
    report = to_markdown(triage, args.top) if args.format == "markdown" else to_json(triage)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report)
    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as fh:
            fh.write(to_json(triage))

    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return EXIT_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
