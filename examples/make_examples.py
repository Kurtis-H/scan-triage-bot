"""Writes the illustrative sample reports in examples/. Modeled on scans of vuln-shop.

Package CVEs use obviously fake IDs (CVE-2099-*) and fake packages, so nobody mistakes
sample data for a real advisory.
"""

import json
from pathlib import Path

HERE = Path(__file__).parent


def zap_alert(pid, name, risk, conf, cwe, uris, desc, solution):
    return {
        "pluginid": str(pid),
        "alertRef": str(pid),
        "alert": name,
        "name": name,
        "riskcode": str(risk),
        "confidence": str(conf),
        "cweid": str(cwe),
        "wascid": "15",
        "desc": f"<p>{desc}</p>",
        "solution": f"<p>{solution}</p>",
        "count": str(len(uris)),
        "instances": [
            {"uri": u, "method": "GET", "param": "", "attack": "", "evidence": ""} for u in uris
        ],
    }


def zap_report(port, alerts):
    return {
        "@programName": "ZAP",
        "@version": "2.16.0",
        "site": [
            {
                "@name": f"http://localhost:{port}",
                "@host": "localhost",
                "@port": str(port),
                "@ssl": "false",
                "alerts": alerts,
            }
        ],
    }


CLICKJACK = dict(
    pid=10020,
    name="Missing Anti-clickjacking Header",
    risk=2,
    conf=2,
    cwe=1021,
    desc="The response does not protect against 'ClickJacking' attacks. It should include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options.",
    solution="Add a frame-ancestors directive to the Content-Security-Policy header, or set X-Frame-Options to DENY.",
)
MODERN = dict(
    pid=10109,
    name="Modern Web Application",
    risk=0,
    conf=2,
    cwe=-1,
    desc="The application appears to be a modern web application.",
    solution="This is an informational alert and so no changes are required.",
)

vuln = zap_report(
    8000,
    [
        zap_alert(
            10038,
            "Content Security Policy (CSP) Header Not Set",
            2,
            3,
            693,
            [
                "http://localhost:8000/",
                "http://localhost:8000/products/1",
                "http://localhost:8000/products/2",
                "http://localhost:8000/products/3",
            ],
            "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks.",
            "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.",
        ),
        zap_alert(
            10021,
            "X-Content-Type-Options Header Missing",
            1,
            2,
            693,
            ["http://localhost:8000/", "http://localhost:8000/static/app.js"],
            "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
            "Ensure that the application/web server sets the X-Content-Type-Options header to 'nosniff' for all web pages.",
        ),
        zap_alert(uris=["http://localhost:8000/", "http://localhost:8000/products/1"], **CLICKJACK),
        zap_alert(uris=["http://localhost:8000/"], **MODERN),
        zap_alert(
            10096,
            "Timestamp Disclosure - Unix",
            0,
            0,
            497,
            ["http://localhost:8000/static/app.js"],
            "A timestamp was disclosed by the application/web server.",
            "Manually confirm that the timestamp data is not sensitive.",
        ),
    ],
)
secure = zap_report(
    8001,
    [
        zap_alert(
            10055,
            "CSP: style-src unsafe-inline",
            2,
            3,
            693,
            ["http://localhost:8001/", "http://localhost:8001/products/1"],
            "The Content Security Policy allows 'unsafe-inline' in style-src, which weakens protection against injected styles.",
            "Move inline styles into a static stylesheet and remove 'unsafe-inline' from style-src.",
        ),
        zap_alert(uris=["http://localhost:8001/", "http://localhost:8001/products/2"], **CLICKJACK),
        zap_alert(uris=["http://localhost:8001/"], **MODERN),
    ],
)

trivy = {
    "SchemaVersion": 2,
    "ArtifactName": ".",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-0001",
                    "PkgName": "examplelib",
                    "InstalledVersion": "1.0.0",
                    "FixedVersion": "1.0.5",
                    "Severity": "HIGH",
                    "CweIDs": ["CWE-444"],
                    "Title": "examplelib: HTTP request smuggling (illustrative sample)",
                    "Description": "Sample advisory for demo purposes. A request smuggling flaw lets an attacker bypass front-end access controls.",
                },
                {
                    "VulnerabilityID": "CVE-2099-0003",
                    "PkgName": "otherlib",
                    "InstalledVersion": "3.2.0",
                    "FixedVersion": "",
                    "Severity": "MEDIUM",
                    "CweIDs": ["CWE-400"],
                    "Title": "otherlib: denial of service via crafted input (illustrative sample)",
                    "Description": "Sample advisory for demo purposes. No fixed version has been released yet.",
                },
            ],
        },
        {
            "Target": "requirements-dev.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-0002",
                    "PkgName": "exampletestlib",
                    "InstalledVersion": "2.1.0",
                    "FixedVersion": "2.2.0",
                    "Severity": "HIGH",
                    "CweIDs": ["CWE-22"],
                    "Title": "exampletestlib: path traversal in report writer (illustrative sample)",
                    "Description": "Sample advisory for demo purposes. Only affects the test toolchain.",
                }
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS026",
                    "AVDID": "AVD-DS-0026",
                    "Title": "No HEALTHCHECK defined",
                    "Severity": "LOW",
                    "Status": "FAIL",
                    "Message": "Add HEALTHCHECK instruction in your Dockerfile",
                    "Resolution": "Add HEALTHCHECK instruction in Dockerfile",
                }
            ],
        },
    ],
}


def sarif(tool, rules, results):
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "rules": rules}}, "results": results}],
    }


def result(rule_id, uri, line, msg, level="warning"):
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": msg},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
        ],
    }


semgrep = sarif(
    "Semgrep",
    [
        {
            "id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "shortDescription": {"text": "SQL query built with string formatting"},
            "help": {
                "text": "Use parameterized queries: pass user input as parameters, never format it into the SQL string."
            },
            "properties": {
                "security-severity": "8.1",
                "tags": [
                    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    "OWASP-A03:2021",
                ],
            },
        },
        {
            "id": "rules.raw-html-rendering",
            "shortDescription": {"text": "User content rendered into HTML without escaping"},
            "help": {
                "text": "Escape user content with html.escape() or use an auto-escaping template engine."
            },
            "properties": {
                "tags": [
                    "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
                ]
            },
        },
        {
            "id": "python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret",
            "shortDescription": {"text": "Hardcoded JWT secret"},
            "help": {
                "text": "Load the signing secret from an environment variable or secret manager."
            },
            "properties": {
                "security-severity": "7.5",
                "tags": ["CWE-798: Use of Hard-coded Credentials"],
            },
        },
    ],
    [
        result(
            "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "app/main.py",
            80,
            "Detected SQL statement built with an f-string. This could lead to SQL injection.",
            "error",
        ),
        result(
            "rules.raw-html-rendering",
            "app/main.py",
            140,
            "Review text is returned without HTML escaping.",
        ),
        result(
            "python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret",
            "app/config.py",
            17,
            "Hardcoded JWT secret detected.",
            "error",
        ),
    ],
)

bandit = sarif(
    "Bandit",
    [
        {
            "id": "B608",
            "shortDescription": {
                "text": "Possible SQL injection via string-based query construction"
            },
            "help": {"text": "Use parameterized queries."},
            "properties": {"tags": ["security", "CWE-89"]},
        },
        {
            "id": "B101",
            "shortDescription": {"text": "Use of assert detected"},
            "help": {
                "text": "Asserts are removed when Python runs with -O; don't use them for runtime checks."
            },
            "properties": {"tags": ["security", "CWE-703"]},
        },
    ],
    [
        result(
            "B608",
            "app/main.py",
            80,
            "Possible SQL injection vector through string-based query construction.",
        ),
        result("B101", "tests/test_vulns.py", 25, "Use of assert detected.", "note"),
        result("B101", "tests/test_baseline.py", 14, "Use of assert detected.", "note"),
    ],
)

for name, data in [
    ("zap-vulnerable.json", vuln),
    ("zap-secure.json", secure),
    ("trivy.json", trivy),
    ("semgrep.sarif", semgrep),
    ("bandit.sarif", bandit),
]:
    (HERE / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print("wrote sample reports to", HERE)
