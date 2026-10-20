"""Scope and input validation. Every module goes through these checks first."""

import ipaddress
import socket
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a target is invalid or outside the allowed scope."""


def resolve_ips(host):
    """Return every IP address a hostname resolves to."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as error:
        raise ScopeError(f"Could not resolve '{host}': {error}") from error
    return sorted({info[4][0] for info in infos})


def is_lab_host(host):
    """True only if ALL addresses are loopback or private (RFC 1918 / ULA)."""
    ips = resolve_ips(host)
    for ip in ips:
        addr = ipaddress.ip_address(ip.split("%")[0])
        if not (addr.is_loopback or addr.is_private):
            return False
    return bool(ips)


def parse_target(raw):
    """Turn user input (URL, host or IP) into a normalized dict."""
    raw = (raw or "").strip()
    if not raw:
        raise ScopeError("Enter a target such as 127.0.0.1:3000 or https://example.com")

    to_parse = raw if "://" in raw else f"//{raw}"
    parsed = urlparse(to_parse, scheme="http")

    if parsed.scheme not in ("http", "https"):
        raise ScopeError("Only http:// and https:// targets are supported.")
    if parsed.username or parsed.password:
        raise ScopeError("URLs containing credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError as error:
        raise ScopeError("Invalid port number.") from error
    host = parsed.hostname
    if not host:
        raise ScopeError("Could not find a hostname in the target.")
    if port is not None and not (1 <= port <= 65535):
        raise ScopeError("Invalid port number.")

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    default_port = 443 if parsed.scheme == "https" else 80
    return {
        "host": host,
        "port": port or default_port,
        "scheme": parsed.scheme,
        "is_ip": is_ip,
        "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}",
    }


def require_authorization(confirmed):
    if not confirmed:
        raise ScopeError(
            "Authorization not confirmed. Only assess systems you own or have "
            "written permission to test."
        )


def require_lab_scope(host):
    """Active checks (port scanning) are limited to loopback/private lab hosts."""
    if not is_lab_host(host):
        raise ScopeError(
            f"'{host}' is not a loopback/private address. Port scanning is "
            "restricted to local lab targets in ReconX."
        )
