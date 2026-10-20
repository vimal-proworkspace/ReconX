"""Network module: threaded TCP connect scan, restricted to lab hosts."""

import json
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from reconx.findings import make_finding
from reconx.safety import require_lab_scope, resolve_ips

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
                 3000, 3306, 5432, 8000, 8080, 8443]

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3000: "HTTP (dev)", 3306: "MySQL", 5432: "PostgreSQL", 8000: "HTTP (alt)",
    8080: "HTTP (alt)", 8443: "HTTPS (alt)",
}
RISKY = {
    21: ("medium", "FTP transfers credentials and data in clear text."),
    23: ("high", "Telnet transmits everything, including passwords, in clear text."),
    445: ("medium", "SMB exposure has a long history of serious vulnerabilities."),
    3306: ("medium", "Databases should not be reachable beyond the hosts that need them."),
    5432: ("medium", "Databases should not be reachable beyond the hosts that need them."),
}


def parse_ports(spec):
    """Accept '80,443,8000-8010'. Returns a sorted list of valid ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, high = (int(x) for x in part.split("-", 1))
            ports.update(range(low, high + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    if len(ports) > 1024:
        raise ValueError("Limit of 1024 ports per scan.")
    return sorted(ports)


def _check(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.6):
            return port
    except OSError:
        return None


def scan_network(host, ports=None):
    require_lab_scope(host)
    ports = ports or DEFAULT_PORTS
    ip = resolve_ips(host)[0]

    with ThreadPoolExecutor(max_workers=50) as pool:
        open_ports = sorted(p for p in pool.map(lambda p: _check(ip, p), ports) if p)

    findings = []
    for port in open_ports:
        if port in RISKY:
            severity, impact = RISKY[port]
            findings.append(make_finding(
                f"Risky service exposed: {SERVICES.get(port, port)} ({port}/tcp)",
                f"{ip}:{port}", f"TCP port {port} accepted a connection.", impact,
                "Disable the service or restrict it with a firewall if not required.",
                severity=severity, confidence="medium", module="network"))

    return {
        "module": "network",
        "target": host,
        "resolved_ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ports_checked": len(ports),
        "open_ports": [{"port": p, "service": SERVICES.get(p, "unknown")} for p in open_ports],
        "findings": findings,
        "limitations": [
            "TCP connect scan only; no UDP, no version detection.",
            "An open port is not by itself a vulnerability.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(scan_network(input("Enter a lab host (e.g. 127.0.0.1): ")), indent=2))
