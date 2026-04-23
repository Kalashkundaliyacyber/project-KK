"""
Scan Recommendation Engine
Suggests the next safe, appropriate scan based on current findings.
Only recommends from the approved scan template list.
"""

RECOMMENDATIONS = {
    "no_version_info": {
        "scan_type": "service_detect",
        "title": "Service & Version Detection",
        "reason": "Open ports found but no service versions detected. Run service detection to identify what is running.",
        "priority": 1
    },
    "outdated_versions": {
        "scan_type": "version_deep",
        "title": "Deep Version Detection",
        "reason": "Outdated versions detected. Deep version scan will precisely fingerprint service versions for accurate CVE mapping.",
        "priority": 2
    },
    "udp_not_scanned": {
        "scan_type": "udp_scan",
        "title": "UDP Top-100 Scan",
        "reason": "UDP ports not yet scanned. Services like DNS (53), SNMP (161), NTP (123) are UDP-based and often overlooked.",
        "priority": 3
    },
    "scripts_not_run": {
        "scan_type": "enum_scripts",
        "title": "Script-Based Enumeration",
        "reason": "Default NSE scripts can detect additional vulnerabilities, misconfigurations, and service banners.",
        "priority": 4
    },
    "os_not_detected": {
        "scan_type": "os_detect",
        "title": "OS Detection",
        "reason": "Operating system not yet identified. OS information helps assess patch status and attack surface.",
        "priority": 5
    },
    "critical_cve_found": {
        "scan_type": "enum_scripts",
        "title": "Script Enumeration (Critical CVE Follow-up)",
        "reason": "Critical CVEs detected. NSE scripts can confirm exploitability and gather additional service intelligence.",
        "priority": 1
    },
    "all_complete": {
        "scan_type": None,
        "title": "Generate Report",
        "reason": "Scanning appears comprehensive. Export a report summarising all findings, risks, and recommended patches.",
        "priority": 10
    }
}

def get_recommendation(risk_data: dict, current_scan_type: str) -> dict:
    """Determine the best next scan to run."""
    hosts = risk_data.get("hosts", [])
    if not hosts:
        return _format(RECOMMENDATIONS["all_complete"])

    checks = []

    has_version_info = False
    has_outdated = False
    has_critical_cve = False
    has_os = False

    for host in hosts:
        if host.get("os"):
            has_os = True
        for port in host.get("ports", []):
            v = port.get("version_analysis", {})
            if v.get("status") not in (None, "unknown"):
                has_version_info = True
            if v.get("status") in ("outdated", "unsupported"):
                has_outdated = True
            for cve in port.get("cves", []):
                if cve.get("severity") in ("critical", "high"):
                    has_critical_cve = True

    if has_critical_cve and current_scan_type not in ("enum_scripts",):
        checks.append("critical_cve_found")

    if not has_version_info:
        checks.append("no_version_info")
    elif has_outdated and current_scan_type not in ("version_deep",):
        checks.append("outdated_versions")

    if current_scan_type not in ("udp_scan",):
        checks.append("udp_not_scanned")

    if current_scan_type not in ("enum_scripts",) and "critical_cve_found" not in checks:
        checks.append("scripts_not_run")

    if not has_os and current_scan_type not in ("os_detect",):
        checks.append("os_not_detected")

    if not checks:
        return _format(RECOMMENDATIONS["all_complete"])

    # Pick highest priority
    best_key = min(checks, key=lambda k: RECOMMENDATIONS[k]["priority"])
    rec = RECOMMENDATIONS[best_key]

    # Add secondary options
    secondary = [
        _format(RECOMMENDATIONS[k])
        for k in checks if k != best_key
    ][:2]

    result = _format(rec)
    result["alternatives"] = secondary
    return result


def _format(rec: dict) -> dict:
    from app.scanner.orchestrator import SCAN_TEMPLATES
    out = {
        "title": rec["title"],
        "reason": rec["reason"],
        "scan_type": rec["scan_type"],
        "priority": rec["priority"]
    }
    if rec["scan_type"] and rec["scan_type"] in SCAN_TEMPLATES:
        t = SCAN_TEMPLATES[rec["scan_type"]]
        out["command_description"] = t["description"]
    return out
