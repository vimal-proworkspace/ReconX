"""Builds JSON and HTML reports from assessment results."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reconx.findings import SEVERITIES

TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))


def summarize(assessment):
    findings = [f for r in assessment["results"] for f in r.get("findings", [])]
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    findings.sort(key=lambda f: order[f["severity"]])
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in reversed(SEVERITIES)}
    return findings, counts


def render_html(assessment):
    findings, counts = summarize(assessment)
    return _env.get_template("report.html").render(
        a=assessment, findings=findings, counts=counts,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))


def save_reports(assessment, out_dir="reports"):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", assessment["host"])[:60]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = f"reconx_{safe}_{stamp}"
    json_path = out / f"{name}.json"
    html_path = out / f"{name}.html"
    json_path.write_text(json.dumps(assessment, indent=2))
    html_path.write_text(render_html(assessment))
    return json_path, html_path
