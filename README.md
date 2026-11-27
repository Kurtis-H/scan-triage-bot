# scan-triage-bot

![CI](https://github.com/Kurtis-H/scan-triage-bot/actions/workflows/ci.yml/badge.svg)

**Security scanners are noisy. This turns their output into one short, ranked list a developer will actually read.**

Feed it reports from OWASP ZAP, Trivy and any SARIF tool (Semgrep, Bandit, CodeQL and others). It merges duplicates, ranks what's left with transparent rules, applies reviewed suppressions that expire, and can add plain-English explanations from a free local AI model.

```
$ scan-triage examples/ --suppressions examples/triage-suppressions.toml

12 findings to review (from 17 raw results across 5 reports) · 2 suppressed · 1 false positive dropped
🟧 4 high · 🟨 4 medium · 🟦 4 low

| # | Score | Severity | Finding                                  | Where              | Tools           |
|---|-------|----------|------------------------------------------|--------------------|-----------------|
| 1 | 80    | high     | SQL query built with string formatting   | app/main.py:80     | bandit, semgrep |
| 2 | 80    | high     | CVE-2099-0001: examplelib: HTTP request… | requirements.txt   | trivy           |
| 3 | 70    | high     | Hardcoded JWT secret                     | app/config.py:17   | semgrep         |
...
```

The sample reports in `examples/` are modeled on scans of [vuln-shop](https://github.com/Kurtis-H/vuln-shop) and point at its real line numbers. The package CVEs are deliberately fake (`CVE-2099-*`) so they can't be mistaken for real advisories.

## What it does

1. **Parses** ZAP JSON, Trivy JSON and SARIF 2.1.0 into one common format. The format is auto-detected.
2. **Deduplicates:**
   - The same ZAP alert across several reports or environments becomes one finding. Hosts and parameter values are stripped from URLs, so `GET http://staging/s?q=abc` and `GET http://localhost/s?q=xyz` match.
   - Different tools reporting the same weakness (CWE) on the same line become one finding, credited to both. The SQL injection above was flagged by both Semgrep and Bandit.
3. **Scores** every finding from 0 to 100 with fixed rules, and lists the reasons for each score.
4. **Suppresses** findings that a person has reviewed and accepted, but only until an expiry date.
5. **Reports** as Markdown (PR comment or job summary) and JSON, and can fail the build at a severity threshold.

## How scoring works

Every score shows its working (`Why score 45: high severity: base 70; only in test/dev/example files: x0.5; fixed version available: +10`).

| Rule | Effect |
|---|---|
| Base by severity | critical 90 · high 70 · medium 40 · low 15 · info 2 |
| Scanner confidence (ZAP) | multiplied by confidence (low 0.6, medium 0.85) |
| Only in tests, examples, docs or dev requirements | x0.5 |
| A fixed version exists | +10 (easy win, do it first) |
| Reported by 2+ tools | +10 |
| Many locations | +1 per extra location, up to +5 |

ZAP findings that ZAP itself marks as false positives are dropped and counted. SARIF results already suppressed in source code are dropped too.

## Where AI fits, and where it doesn't

`--explain ollama` asks a local model (free, runs on your own GPU via [Ollama](https://ollama.com)) to write a short plain-English explanation for the top findings. The rules around it:

- **AI never decides severity or ranking.** Scores come only from the rules above. The model sees the finding but never the score, and its text can't change anything. This is tested.
- **Scanner output is untrusted input.** It can contain text from the scanned app, such as page content an attacker controls. It's passed to the model inside a clearly marked `<finding>` block, with instructions to treat it as data, not commands.
- **The model's reply is also untrusted.** HTML and markdown are stripped, the length is capped, and it's labeled "AI explanation (does not affect score)".
- **Failure is non-fatal.** If Ollama isn't running, the report still ships without explanations.

```bash
ollama pull llama3.1:8b
scan-triage reports/ --explain ollama --explain-top 5
```

## Suppressions

`triage-suppressions.toml`. Every entry **must** have a reason and an expiry date. There's no such thing as "ignore forever".

```toml
[[suppress]]
rule = "zap:10055"            # tool:rule, a CWE like "CWE-693", or...
# fingerprint = "3f9a1c2b7d4e"  ...one exact finding (shown in each report)
path = "app/legacy/*"         # optional glob on location
reason = "Inline styles needed until the CSS refactor (TICKET-123)"
expires = 2027-06-30
```

- **Expired** suppressions stop working, and the report lists them at the top so the team sees them come back.
- **Unused** suppressions (matching nothing anymore) are listed as safe to delete, so the file doesn't fill up with dead entries.

## Install and use

```bash
pip install git+https://github.com/Kurtis-H/scan-triage-bot
scan-triage zap.json trivy.json semgrep.sarif
scan-triage reports/ --suppressions triage-suppressions.toml --fail-on high
scan-triage reports/ --format json -o triage.json
```

## GitHub Action

```yaml
- name: Triage security scans
  uses: Kurtis-H/scan-triage-bot@c91c263c9c944587db1b254873b7b11fe8e695a3 # main
  with:
    reports: reports/zap.json reports/trivy.json reports/semgrep.sarif
    suppressions: triage-suppressions.toml
    fail-on: high        # leave empty for report-only
```

There's no release tag yet, so pin a commit from `main`, as above. The ranked report appears in the job summary. To post it on PRs, add [sticky-pull-request-comment](https://github.com/marocchino/sticky-pull-request-comment) with `path: scan-triage.md`.

## Security of the tool itself

A triage tool reads attacker-influenced data and writes into PR comments, so it's held to the same standard it enforces:

- **Secrets are never echoed.** Trivy's matched secret value is dropped at parse time. Only the file and line are reported.
- **All scanner text is escaped** before it reaches Markdown, so a malicious finding title can't inject HTML, links or table breaks.
- **Input sizes are capped,** and malformed reports are skipped with a warning instead of crashing the run.

Each of these behaviors has a test (`tests/test_scan_triage.py`).

## Roadmap

- [ ] Reachability: lower the score for vulnerable packages the code never imports
- [ ] Map CVEs to CISA's Known Exploited Vulnerabilities list for a priority bump
- [ ] Track findings over time: new, fixed and reopened since the last run
- [ ] Sticky PR comment built in

## License

MIT
