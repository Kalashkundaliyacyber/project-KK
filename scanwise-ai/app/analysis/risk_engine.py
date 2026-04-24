"""
Risk Prioritization Engine
Weighted score → Low / Medium / High / Critical.
"""

CRITICALITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2}
VERSION_RISK_WEIGHT = {"high": 8, "medium": 5, "low": 1}
EXPOSURE_WEIGHT     = {"high": 8, "medium": 5, "low": 2, "none": 0}


def calculate_risk(context_data: dict) -> dict:
    result = dict(context_data)
    for host in result.get("hosts", []):
        host_exposure = host.get("context", {}).get("exposure", "medium")
        port_levels   = []
        for port in host.get("ports", []):
            port["risk"] = _calculate_port_risk(port, host_exposure)
            port_levels.append(port["risk"]["level"])
        host["risk_summary"] = _host_risk_summary(port_levels)
    return result


def _calculate_port_risk(port: dict, host_exposure: str) -> dict:
    cves       = port.get("cves", [])
    context    = port.get("context", {})
    va         = port.get("version_analysis", {})

    max_cvss   = max((c["cvss_score"] for c in cves), default=0.0)
    crit_score = CRITICALITY_WEIGHT.get(context.get("criticality", "low"), 2)
    ver_score  = VERSION_RISK_WEIGHT.get(context.get("version_risk", "medium"), 5)
    exp_score  = EXPOSURE_WEIGHT.get(host_exposure, 5)

    raw = (max_cvss * 0.4) + (crit_score * 0.25) + (ver_score * 0.2) + (exp_score * 0.15)

    # CVSS 10.0 always critical
    if max_cvss >= 10.0:
        raw = max(raw, 8.5)

    score = round(min(raw, 10.0), 1)
    level = _score_to_level(score)

    return {
        "score":    score,
        "level":    level,
        "max_cvss": max_cvss,
        "cve_count": len(cves),
        "reasons":  _build_reasons(max_cvss, context.get("criticality", "low"), va, host_exposure, len(cves)),
        "color":    _level_color(level),
    }


def _score_to_level(score: float) -> str:
    if score >= 8.5: return "critical"
    if score >= 6.5: return "high"
    if score >= 4.0: return "medium"
    return "low"


def _level_color(level: str) -> str:
    return {"critical": "#E24B4A", "high": "#EF9F27",
            "medium": "#378ADD", "low": "#1D9E75"}.get(level, "#888780")


def _build_reasons(cvss, criticality, va, exposure, cve_count) -> list:
    reasons = []
    if cvss >= 9.0:
        reasons.append(f"Critical CVSS score of {cvss} — severe vulnerability present")
    elif cvss >= 7.0:
        reasons.append(f"High CVSS score of {cvss}")
    elif cvss > 0:
        reasons.append(f"CVSS score of {cvss}")
    if criticality in ("critical", "high"):
        reasons.append(f"Service criticality is {criticality}")
    status = va.get("status", "unknown")
    if status == "unsupported":
        reasons.append("Running an end-of-life version with no security patches")
    elif status == "outdated":
        age = va.get("age_years")
        reasons.append(f"Version is outdated" + (f" ({age} years old)" if age else ""))
    if exposure in ("high", "medium"):
        reasons.append(f"Host has {exposure} overall exposure")
    if cve_count >= 3:
        reasons.append(f"{cve_count} known CVEs mapped to this service")
    elif cve_count > 0:
        reasons.append(f"{cve_count} known CVE(s) mapped")
    if not reasons:
        reasons.append("No significant risk factors identified")
    return reasons


def _host_risk_summary(port_levels: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for lvl in port_levels:
        if lvl in counts:
            counts[lvl] += 1
    if counts["critical"] > 0:   overall = "critical"
    elif counts["high"] > 0:     overall = "high"
    elif counts["medium"] > 0:   overall = "medium"
    else:                        overall = "low"
    return {
        "overall":     overall,
        "counts":      counts,
        "total_ports": len(port_levels),
        "color":       _level_color(overall),
    }
