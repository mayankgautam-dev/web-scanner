#!/usr/bin/env python3
"""
Automated Web Security Scanner
Audits websites for missing/weak security headers, cookie flags,
information disclosure and CORS misconfigurations.

Only scan sites you own or have explicit written permission to test.
"""
import argparse
import json
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import requests

requests.packages.urllib3.disable_warnings()  # allow scanning self-signed lab hosts

USER_AGENT = "WebSecScanner/1.0 (authorized-security-audit)"
SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    detail: str
    recommendation: str


@dataclass
class ScanResult:
    url: str
    status_code: Optional[int] = None
    scanned_at: str = ""
    score: int = 100
    grade: str = "A"
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None


# header -> (severity, recommendation)
REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("HIGH", "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    "Content-Security-Policy": ("HIGH", "Define a Content-Security-Policy restricting script/style/frame sources."),
    "X-Content-Type-Options": ("MEDIUM", "Add 'X-Content-Type-Options: nosniff'."),
    "X-Frame-Options": ("MEDIUM", "Add 'X-Frame-Options: DENY' or use CSP frame-ancestors."),
    "Referrer-Policy": ("LOW", "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter."),
    "Permissions-Policy": ("LOW", "Add a Permissions-Policy disabling unused browser features."),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def check_headers(resp: requests.Response, is_https: bool) -> List[Finding]:
    out = []
    h = resp.headers
    for name, (sev, rec) in REQUIRED_HEADERS.items():
        if name == "Strict-Transport-Security" and not is_https:
            continue  # HSTS only meaningful over HTTPS
        if name == "X-Frame-Options" and "frame-ancestors" in h.get("Content-Security-Policy", "").lower():
            continue
        if name not in h:
            out.append(Finding("headers", sev, f"Missing header: {name}", f"{name} was not returned.", rec))

    hsts = h.get("Strict-Transport-Security", "")
    if hsts:
        try:
            age = int(next((p.split("=")[1] for p in hsts.replace(" ", "").split(";")
                            if p.lower().startswith("max-age=")), "0"))
        except ValueError:
            age = 0
        if age < 15552000:
            out.append(Finding("headers", "MEDIUM", "Weak HSTS max-age",
                               f"max-age={age} is under 180 days.", "Use max-age of at least 31536000."))

    csp = h.get("Content-Security-Policy", "")
    if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp or " * " in f" {csp} "):
        out.append(Finding("headers", "MEDIUM", "Weak Content-Security-Policy",
                           "CSP contains 'unsafe-inline', 'unsafe-eval' or a wildcard source.",
                           "Remove unsafe directives; use nonces or hashes."))

    if h.get("X-Content-Type-Options", "").lower() not in ("", "nosniff"):
        out.append(Finding("headers", "LOW", "Invalid X-Content-Type-Options",
                           f"Value was '{h['X-Content-Type-Options']}'.", "Set to 'nosniff'."))

    for name in LEAKY_HEADERS:
        if name in h and any(ch.isdigit() for ch in h[name]):
            out.append(Finding("disclosure", "LOW", f"Version disclosure via {name}",
                               f"{name}: {h[name]}", f"Remove or genericize the {name} header."))
    return out


def check_cookies(resp: requests.Response, is_https: bool) -> List[Finding]:
    out = []
    raw = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
    for c in raw:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        if is_https and "secure" not in low:
            out.append(Finding("cookies", "MEDIUM", f"Cookie '{name}' missing Secure flag",
                               c[:80], "Add the Secure attribute."))
        if "httponly" not in low:
            out.append(Finding("cookies", "MEDIUM", f"Cookie '{name}' missing HttpOnly flag",
                               c[:80], "Add the HttpOnly attribute."))
        if "samesite" not in low:
            out.append(Finding("cookies", "LOW", f"Cookie '{name}' missing SameSite",
                               c[:80], "Add SameSite=Lax or Strict."))
    return out


def check_cors(url: str, session: requests.Session, timeout: int) -> List[Finding]:
    """Send crafted Origin headers and inspect how the server reflects them."""
    out = []
    host = urlparse(url).hostname or "target"
    probes = {
        "arbitrary origin": "https://evil.example",
        "null origin": "null",
        "suffix-match bypass": f"https://{host}.evil.example",
        "prefix-match bypass": f"https://evil{host}",
    }
    for label, origin in probes.items():
        try:
            r = session.get(url, headers={"Origin": origin}, timeout=timeout,
                            verify=False, allow_redirects=False)
        except requests.RequestException:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if not acao:
            continue
        reflected = acao == origin
        if (reflected or acao == "null") and acac:
            out.append(Finding("cors", "CRITICAL", f"CORS: {label} trusted WITH credentials",
                               f"Origin '{origin}' -> ACAO '{acao}', ACAC true.",
                               "Validate Origin against a strict allow-list; never reflect it with credentials."))
        elif reflected:
            out.append(Finding("cors", "HIGH", f"CORS: {label} reflected",
                               f"Origin '{origin}' echoed in Access-Control-Allow-Origin.",
                               "Use an explicit allow-list of trusted origins."))
        elif acao == "*" and acac:
            out.append(Finding("cors", "HIGH", "CORS: wildcard with credentials flag",
                               "ACAO '*' combined with ACAC true (invalid and risky).",
                               "Remove wildcard or disable credentials."))
        elif acao == "*" and label == "arbitrary origin":
            out.append(Finding("cors", "LOW", "CORS: wildcard origin allowed",
                               "Access-Control-Allow-Origin: * on this endpoint.",
                               "Acceptable only for fully public resources."))
    # preflight check
    try:
        p = session.options(url, headers={"Origin": "https://evil.example",
                                          "Access-Control-Request-Method": "DELETE"},
                            timeout=timeout, verify=False, allow_redirects=False)
        methods = p.headers.get("Access-Control-Allow-Methods", "")
        if p.headers.get("Access-Control-Allow-Origin") in ("*", "https://evil.example") and \
                any(m in methods.upper() for m in ("DELETE", "PUT", "PATCH")):
            out.append(Finding("cors", "MEDIUM", "CORS preflight allows state-changing methods",
                               f"Allow-Methods: {methods}", "Restrict allowed methods and origins."))
    except requests.RequestException:
        pass
    return out


def check_transport(url: str) -> List[Finding]:
    if urlparse(url).scheme == "http":
        return [Finding("transport", "HIGH", "Site served over plain HTTP",
                        "Traffic is unencrypted.", "Serve over HTTPS and redirect HTTP to HTTPS.")]
    return []


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"


def scan(url: str, timeout: int = 10) -> ScanResult:
    if not urlparse(url).scheme:
        url = "https://" + url
    result = ScanResult(url=url, scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    try:
        resp = s.get(url, timeout=timeout, verify=False, allow_redirects=True, stream=True)
        resp.close()
    except requests.RequestException as e:
        result.error = str(e)
        result.score, result.grade = 0, "N/A"
        return result
    result.status_code = resp.status_code
    https = urlparse(resp.url).scheme == "https"
    result.findings += check_transport(resp.url)
    result.findings += check_headers(resp, https)
    result.findings += check_cookies(resp, https)
    result.findings += check_cors(resp.url, s, timeout)
    result.score = max(0, 100 - sum(SEVERITY_WEIGHT[f.severity] for f in result.findings))
    result.grade = grade(result.score)
    return result


COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m", "INFO": "\033[0m"}


def print_report(r: ScanResult):
    print(f"\n=== {r.url} ===")
    if r.error:
        print(f"  ERROR: {r.error}")
        return
    print(f"  HTTP {r.status_code} | Score {r.score}/100 | Grade {r.grade}")
    order = list(SEVERITY_WEIGHT)
    for f in sorted(r.findings, key=lambda x: order.index(x.severity)):
        print(f"  {COLORS[f.severity]}[{f.severity}]\033[0m {f.title}\n      -> {f.recommendation}")
    if not r.findings:
        print("  No issues found.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Audit sites for secure headers, cookie flags and CORS flaws.")
    ap.add_argument("urls", nargs="*", help="Target URL(s)")
    ap.add_argument("-f", "--file", help="File with one URL per line")
    ap.add_argument("-o", "--output", help="Write JSON report to this path")
    ap.add_argument("-t", "--timeout", type=int, default=10)
    ap.add_argument("--i-have-permission", action="store_true",
                    help="Confirm you are authorized to scan the targets")
    a = ap.parse_args(argv)

    targets = list(a.urls)
    if a.file:
        with open(a.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        ap.error("provide at least one URL or --file")
    if not a.i_have_permission:
        print("Refusing to scan: pass --i-have-permission to confirm you are authorized.", file=sys.stderr)
        return 2

    results = [scan(t, a.timeout) for t in targets]
    for r in results:
        print_report(r)
    if a.output:
        with open(a.output, "w") as fh:
            json.dump([asdict(r) for r in results], fh, indent=2)
        print(f"\nJSON report saved to {a.output}")
    return 1 if any(f.severity in ("CRITICAL", "HIGH") for r in results for f in r.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
