"""Flask dashboard. Binds to 127.0.0.1 only."""

import os
import secrets
from pathlib import Path

from flask import Flask, abort, render_template, request, send_from_directory, session

from reconx.core import ALL_MODULES, run_assessment
from reconx.report import render_html, save_reports
from reconx.safety import ScopeError

REPORTS = Path(__file__).parent / "reports"
app = Flask(__name__, template_folder="reconx/templates")
app.secret_key = os.urandom(32)


def _csrf():
    session.setdefault("csrf", secrets.token_hex(16))
    return session["csrf"]


@app.get("/")
def index():
    return render_template("dashboard.html", csrf=_csrf(), error=None)


@app.post("/scan")
def scan():
    if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
        abort(400, "Invalid form token.")
    modules = [m for m in request.form.getlist("modules") if m in ALL_MODULES]
    try:
        if not modules:
            raise ScopeError("Select at least one module.")
        assessment = run_assessment(
            request.form.get("target", ""), modules,
            authorized=request.form.get("authorized") == "yes")
    except ScopeError as error:
        return render_template("dashboard.html", csrf=_csrf(), error=str(error)), 400
    save_reports(assessment, REPORTS)
    return render_html(assessment)


@app.get("/reports/<path:name>")
def report_file(name):
    return send_from_directory(REPORTS, name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
