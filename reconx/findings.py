"""Shared finding structure so every module reports the same fields."""

SEVERITIES = ("info", "low", "medium", "high")


def make_finding(title, location, evidence, impact, recommendation,
                 severity="low", confidence="high", module=""):
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    return {
        "module": module,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "location": location,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
    }
