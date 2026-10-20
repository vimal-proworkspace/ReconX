"""DNS module: collects records and checks basic email-security records."""

import json
import socket
from datetime import datetime, timezone

from reconx.findings import make_finding

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
PARENT_TYPES = ("NS", "TXT", "SOA")


def _import_dns():
    try:
        import dns.exception
        import dns.resolver
    except ImportError as error:
        raise RuntimeError("dnspython is required: pip install dnspython") from error
    return dns


def _query(resolver, name, rtype):
    dns = _import_dns()
    try:
        answers = resolver.resolve(name, rtype, raise_on_no_answer=False)
        return [a.to_text() for a in answers] if answers.rrset else []
    except dns.resolver.NXDOMAIN:
        raise
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []


def scan_dns(domain):
    dns = _import_dns()
    domain = domain.strip().rstrip(".").lower()
    if not domain or "/" in domain or ":" in domain or " " in domain:
        raise ValueError("Enter a valid domain name, not a URL or IP address.")

    results = {
        "module": "dns",
        "target": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "records": {},
        "errors": {},
        "findings": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            results["records"][rtype] = _query(resolver, domain, rtype)
        except dns.resolver.NXDOMAIN:
            results["errors"][rtype] = "Domain does not exist"
            break
        except (dns.exception.DNSException, OSError) as error:
            results["errors"][rtype] = str(error) or error.__class__.__name__

    # NS/TXT/SOA usually live at the zone apex, so look there if the host has none.
    try:
        zone = dns.resolver.zone_for_name(domain, resolver=resolver).to_text().rstrip(".")
    except Exception:
        zone = domain
    results["zone"] = zone
    if zone != domain:
        for rtype in PARENT_TYPES:
            if not results["records"].get(rtype):
                try:
                    found = _query(resolver, zone, rtype)
                    if found:
                        results["records"][rtype] = found
                        results.setdefault("from_parent_zone", []).append(rtype)
                except (dns.exception.DNSException, OSError):
                    pass

    try:
        results["resolved_ip"] = socket.gethostbyname(domain)
    except (socket.gaierror, OSError):
        results["resolved_ip"] = None

    _email_findings(resolver, zone, results)
    return results


def _email_findings(resolver, zone, results):
    txt = results["records"].get("TXT", [])
    has_mx = bool(results["records"].get("MX"))
    if not has_mx:
        return

    if not any("v=spf1" in t.lower() for t in txt):
        results["findings"].append(make_finding(
            "No SPF record found", zone,
            "Domain has MX records but no TXT record beginning with v=spf1.",
            "Receivers cannot verify which servers may send mail for this domain.",
            "Publish an SPF record listing your authorized mail senders.",
            severity="low", confidence="medium", module="dns"))

    try:
        dmarc = _query(resolver, f"_dmarc.{zone}", "TXT")
    except Exception:
        dmarc = []
    if not any("v=dmarc1" in d.lower() for d in dmarc):
        results["findings"].append(make_finding(
            "No DMARC record found", f"_dmarc.{zone}",
            "No TXT record beginning with v=DMARC1 at _dmarc.<domain>.",
            "Spoofed email using this domain is less likely to be rejected.",
            "Publish a DMARC policy (start with p=none and monitor reports).",
            severity="low", confidence="medium", module="dns"))


if __name__ == "__main__":
    target = input("Enter a domain you own or are authorized to assess: ")
    print(json.dumps(scan_dns(target), indent=2))
