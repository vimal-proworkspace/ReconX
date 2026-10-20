"""TLS module: checks certificate validity, expiry, protocol and cipher."""

import json
import socket
import ssl
from datetime import datetime, timezone

from reconx.findings import make_finding

WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")


def _connect(host, port, verify):
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(), tls.version(), tls.cipher()


def scan_tls(host, port=443):
    location = f"{host}:{port}"
    result = {
        "module": "tls",
        "target": location,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "certificate": None,
        "protocol": None,
        "cipher": None,
        "findings": [],
    }
    findings = result["findings"]

    try:
        cert, version, cipher = _connect(host, port, verify=True)
        verified = True
    except ssl.SSLCertVerificationError as error:
        verified = False
        findings.append(make_finding(
            "Certificate failed validation", location, str(error.verify_message),
            "Browsers will warn users; connections may be open to interception.",
            "Install a certificate from a trusted CA that matches the hostname.",
            severity="medium", module="tls"))
        try:
            _, version, cipher = _connect(host, port, verify=False)
            cert = None
        except (OSError, ssl.SSLError) as error2:
            result["error"] = f"TLS handshake failed: {error2}"
            return result
    except (OSError, ssl.SSLError) as error:
        result["error"] = f"TLS connection failed: {error}"
        return result

    result["protocol"] = version
    result["cipher"] = cipher[0] if cipher else None

    if cert:
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        result["certificate"] = {
            "subject": subject.get("commonName"),
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_after": expires.isoformat(),
            "days_until_expiry": days_left,
            "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
        }
        if days_left < 0:
            findings.append(make_finding(
                "Certificate has expired", location, f"Expired {abs(days_left)} days ago.",
                "Clients will reject or warn about the connection.",
                "Renew and deploy a new certificate.", severity="high", module="tls"))
        elif days_left <= 30:
            findings.append(make_finding(
                "Certificate expires soon", location, f"{days_left} days remaining.",
                "An expired certificate causes outages and browser warnings.",
                "Renew the certificate; consider automated renewal.",
                severity="low", module="tls"))

    if version in WEAK_PROTOCOLS:
        findings.append(make_finding(
            f"Weak protocol negotiated ({version})", location,
            f"Server negotiated {version}.",
            "Older protocol versions have known weaknesses.",
            "Disable protocols older than TLS 1.2.", severity="medium", module="tls"))

    return result


if __name__ == "__main__":
    target = input("Enter host (or host:port) to inspect: ").strip()
    host, _, port = target.partition(":")
    print(json.dumps(scan_tls(host, int(port or 443)), indent=2))
