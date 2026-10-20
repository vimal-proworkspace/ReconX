#!/usr/bin/env python3
"""ReconX command-line entry point (same style as autorecon.py)."""

import argparse
import sys

from reconx.core import ALL_MODULES, run_assessment
from reconx.modules.network import parse_ports
from reconx.report import save_reports, summarize
from reconx.safety import ScopeError


def main():
    parser = argparse.ArgumentParser(description="ReconX - scope-aware assessment toolkit")
    parser.add_argument("target", nargs="?", help="URL, hostname or IP")
    parser.add_argument("-m", "--modules", default=",".join(ALL_MODULES),
                        help="comma-separated: dns,tls,web,network")
    parser.add_argument("-p", "--ports", help="e.g. 80,443,3000-3010 (network module)")
    parser.add_argument("--yes", action="store_true",
                        help="confirm you are authorized to assess the target")
    parser.add_argument("-o", "--out", default="reports", help="report directory")
    args = parser.parse_args()

    print("=== ReconX Security Assessment ===")
    target = args.target or input("Enter your authorized target (URL/host/IP): ")
    authorized = args.yes or input(
        "Do you own this target or have written permission? (y/n): ").lower() == "y"

    try:
        modules = [m.strip() for m in args.modules.split(",") if m.strip() in ALL_MODULES]
        ports = parse_ports(args.ports) if args.ports else None
        assessment = run_assessment(target, modules, authorized, ports)
    except (ScopeError, ValueError) as error:
        print(f"[!] {error}")
        return 1

    findings, counts = summarize(assessment)
    for finding in findings:
        print(f"[{finding['severity'].upper():6}] {finding['module']}: {finding['title']}")
    for module, message in assessment["errors"].items():
        print(f"[skip] {module}: {message}")
    print("Summary:", ", ".join(f"{k}={v}" for k, v in counts.items()))
    json_path, html_path = save_reports(assessment, args.out)
    print(f"Reports saved:\n  {json_path}\n  {html_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
