"""Web module: passive HTTP checks (security headers, cookies, disclosure).

Sends ONE GET request. No payloads, no fuzzing, no exploitation.
"""

import json
from datetime import datetime, timezone

import requests

from reconx.findings import make_finding
from reconx.safety import parse_target

SECURITY_HEADERS = {
    "Content-Security-Policy": ("medium", "Helps restrict sources of browser-loaded content and limits XSS impact."),
    "X-Content-Type-Options": ("low", "Helps prevent MIME-type sniffing."),
    "X-Frame-Options": ("low", "Can help protect against clickjacking (or use CSP frame-ancestors)."),
    "Referrer-Policy": ("low", "Controls referrer information sent by the browser."),
    "Permissions-Policy": ("low", "Controls access to selected browser features."),
}
HSTS = ("Strict-Transport-Security", "Forces browsers to use HTTPS for future visits.")
DISCLOSURE_HEADERS = ("Server", "X-Powered-By")


def _set_cookie_headers(response):
    raw = getattr(response.raw, "headers", None)
    if raw is not None and hasattr(raw, "getlist"):
        return raw.getlist("Set-Cookie")
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def scan_web(url):
    target = parse_target(url)
    url = target["url"]
    response = requests.get(
        url, timeout=10, allow_redirects=False,
        headers={"User-Agent": "ReconX/1.0 (authorized security assessment)"},
    )
    headers = response.headers
    findings = []

    def add(*args, **kwargs):
        findings.append(make_finding(*args, module="web", **kwargs))

    for name, (severity, impact) in SECURITY_HEADERS.items():
        if name not in headers:
            add(f"Missing {name}", url, f"Response does not contain {name}.", impact,
                f"Review and add {name} if appropriate for this application.",
                severity=severity, confidence="medium")

    if target["scheme"] == "https" and HSTS[0] not in headers:
        add(f"Missing {HSTS[0]}", url, "HTTPS response lacks HSTS.", HSTS[1],
            "Add Strict-Transport-Security with a suitable max-age.", severity="low")

    for name in DISCLOSURE_HEADERS:
        if name in headers:
            add(f"{name} header discloses technology", url, f"{name}: {headers[name]}",
                "Version details can help attackers choose known exploits.",
                f"Remove or genericize the {name} header.", severity="info")

    if headers.get("Access-Control-Allow-Origin") == "*":
        add("Permissive CORS policy", url, "Access-Control-Allow-Origin: *",
            "Any website can read responses from this endpoint in a browser.",
            "Restrict CORS to trusted origins, especially for authenticated APIs.",
            severity="low", confidence="medium")

    for cookie in _set_cookie_headers(response):
        name = cookie.split("=", 1)[0].strip()
        lowered = cookie.lower()
        missing = []
        if target["scheme"] == "https" and "secure" not in lowered:
            missing.append("Secure")
        if "httponly" not in lowered:
            missing.append("HttpOnly")
        if "samesite" not in lowered:
            missing.append("SameSite")
        if missing:
            add(f"Cookie '{name}' missing {', '.join(missing)}", url,
                f"Set-Cookie for '{name}' lacks: {', '.join(missing)}.",
                "Weak cookie attributes raise the risk of theft or cross-site misuse.",
                "Set Secure, HttpOnly and an appropriate SameSite value.",
                severity="low", confidence="medium")

    if 300 <= response.status_code < 400:
        findings.append(make_finding(
            "Redirect not followed", url,
            f"HTTP {response.status_code} to {headers.get('Location', 'unknown')}",
            "Headers shown are those of the redirect, not the final page.",
            "Re-run against the final URL.", severity="info", module="web"))

    return {
        "module": "web",
        "target": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "http_status": response.status_code,
        "findings": findings,
        "limitations": [
            "Checks only the supplied URL with a single GET request.",
            "Missing headers are not automatically exploitable vulnerabilities.",
            "Redirects are not followed.",
            "This is not a complete penetration test.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(scan_web(input("Enter an authorized website URL: ")), indent=2))
