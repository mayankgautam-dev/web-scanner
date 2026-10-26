# Automated Web Security Scanner

A Python command-line tool that audits websites for **missing or weak security headers**, **insecure cookie flags**, **information disclosure** and **CORS misconfigurations**, then produces a score, a letter grade and fix recommendations.

> **Legal notice:** Only scan systems you own or have written permission to test. The tool refuses to run unless you pass `--i-have-permission`.

## Features
- Checks 6 key headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- Detects weak HSTS max-age and unsafe CSP directives (`unsafe-inline`, `unsafe-eval`, wildcards)
- Cookie audit: `Secure`, `HttpOnly`, `SameSite`
- Version disclosure via `Server`, `X-Powered-By`, `X-AspNet-Version`
- CORS probes: arbitrary origin reflection, `null` origin, suffix/prefix bypass, wildcard + credentials, risky preflight methods
- Severity-weighted score (0-100) and grade (A-F)
- Batch scanning from a file and JSON report export
- Exit code `1` if any HIGH/CRITICAL finding exists (usable in CI)

## Installation
```bash
git clone https://github.com/<your-username>/web-security-scanner.git
cd web-security-scanner
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
```bash
# Single site
python scanner.py https://example.com --i-have-permission

# Multiple sites from a file with JSON output
python scanner.py -f targets.txt -o report.json --i-have-permission
```

| Option | Description |
|---|---|
| `urls` | One or more target URLs |
| `-f, --file` | File with one URL per line (`#` for comments) |
| `-o, --output` | Save results as JSON |
| `-t, --timeout` | Request timeout in seconds (default 10) |
| `--i-have-permission` | Required authorization confirmation |

## Scoring
Start at 100; subtract CRITICAL 25, HIGH 15, MEDIUM 8, LOW 3. Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F < 50.

## Testing
```bash
python -m pytest -q tests
```
Tests spin up local vulnerable and hardened HTTP servers, so no internet access is needed.

## Project structure
```
scanner.py          # main scanner
tests/test_scanner.py
requirements.txt
README.md
```

## Limitations
Performs passive, non-intrusive checks on one URL per target; it does not crawl, fuzz or exploit. Results should be validated manually.

## License
MIT
