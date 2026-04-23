"""Context-Aware Analysis Engine"""

CRITICAL_SERVICES = {
    "ssh": {"criticality": "high", "reason": "Remote administration access"},
    "rdp": {"criticality": "critical", "reason": "Remote Desktop — full GUI access"},
    "ftp": {"criticality": "high", "reason": "File transfer — often transmits credentials in plaintext"},
    "telnet": {"criticality": "critical", "reason": "Plaintext remote access — should never be exposed"},
    "smb": {"criticality": "critical", "reason": "File sharing — common ransomware attack vector"},
    "mysql": {"criticality": "high", "reason": "Database access — may contain sensitive data"},
    "postgresql": {"criticality": "high", "reason": "Database access — may contain sensitive data"},
    "mssql": {"criticality": "critical", "reason": "Microsoft SQL Server — common attack target"},
    "mongodb": {"criticality": "high", "reason": "NoSQL database — often misconfigured"},
    "redis": {"criticality": "high", "reason": "In-memory database — commonly exposed without auth"},
    "snmp": {"criticality": "high", "reason": "Network management — v1/v2c uses community strings"},
    "domain": {"criticality": "high", "reason": "DNS — can be abused for amplification attacks"},
    "http": {"criticality": "medium", "reason": "Web service — attack surface depends on application"},
    "https": {"criticality": "medium", "reason": "Encrypted web service — check TLS version"},
    "http-proxy": {"criticality": "high", "reason": "Open proxy — can be abused for traffic routing"},
    "vnc": {"criticality": "critical", "reason": "Remote desktop without strong auth by default"},
    "smtp": {"criticality": "medium", "reason": "Mail relay — check for open relay configuration"},
    "ldap": {"criticality": "critical", "reason": "Directory service — often stores credentials"},
}

def analyze_context(cve_data: dict) -> dict:
    result = dict(cve_data)
    for host in result.get("hosts", []):
        open_ports = host.get("ports", [])
        port_count = len(open_ports)
        host["context"] = _host_context(port_count)
        for port in open_ports:
            port["context"] = _port_context(port, port_count)
    return result


def _host_context(port_count: int) -> dict:
    if port_count == 0:
        exposure, note = "none", "No open ports found."
    elif port_count < 3:
        exposure, note = "low", f"Only {port_count} open port(s). Minimal attack surface."
    elif port_count <= 8:
        exposure, note = "medium", f"{port_count} open ports. Moderate attack surface."
    else:
        exposure, note = "high", f"{port_count} open ports. Large attack surface."
    return {"open_port_count": port_count, "exposure": exposure, "exposure_note": note}


def _port_context(port: dict, total_ports: int) -> dict:
    service = port.get("service", "").lower()
    port_num = port.get("port", 0)
    version_status = port.get("version_analysis", {}).get("status", "unknown")

    service_info = CRITICAL_SERVICES.get(service, {
        "criticality": "low", "reason": "Non-standard service. Review if necessary."
    })

    if port_num in (21, 22, 23, 25, 80, 443, 3306, 5432, 3389, 445, 139, 161, 53):
        exposure_type = "commonly_exposed"
    elif port_num < 1024:
        exposure_type = "well_known_port"
    else:
        exposure_type = "high_port"

    version_risk = {"latest": "low", "outdated": "medium", "unsupported": "high"}.get(version_status, "medium")

    return {
        "criticality": service_info["criticality"],
        "criticality_reason": service_info["reason"],
        "exposure_type": exposure_type,
        "version_risk": version_risk,
        "total_open_ports": total_ports
    }
