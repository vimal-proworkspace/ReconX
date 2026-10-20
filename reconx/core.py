"""Orchestrates modules so the CLI and Flask dashboard share one code path."""

from datetime import datetime, timezone

from reconx.modules import dns as dns_mod, network, tls, web
from reconx.safety import parse_target, require_authorization

ALL_MODULES = ("dns", "tls", "web", "network")


def run_assessment(raw_target, modules=ALL_MODULES, authorized=False, ports=None):
    require_authorization(authorized)
    target = parse_target(raw_target)
    results, errors = [], {}

    def attempt(name, func, *args):
        try:
            results.append(func(*args))
        except Exception as error:  # one failing module must not stop the rest
            errors[name] = f"{error.__class__.__name__}: {error}"

    for name in modules:
        if name == "dns":
            if target["is_ip"]:
                errors["dns"] = "Skipped: target is an IP address."
            else:
                attempt("dns", dns_mod.scan_dns, target["host"])
        elif name == "tls":
            if target["scheme"] == "https" or target["port"] == 443:
                attempt("tls", tls.scan_tls, target["host"], target["port"])
            else:
                errors["tls"] = "Skipped: target is not HTTPS."
        elif name == "web":
            attempt("web", web.scan_web, target["url"])
        elif name == "network":
            attempt("network", network.scan_network, target["host"], ports)

    return {
        "tool": "ReconX",
        "target": target["url"],
        "host": target["host"],
        "started": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "errors": errors,
    }
