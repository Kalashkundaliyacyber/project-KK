"""
Explanation Layer
Generates human-readable, plain-English explanations of scan findings.
Safe: No exploit instructions. Focused on defensive guidance.
"""

def generate_explanation(risk_data: dict, recommendation: dict) -> dict:
    hosts = risk_data.get("hosts", [])
    if not hosts:
        return {
            "summary": "No live hosts found in scan results.",
            "findings": [],
            "defensive_guidance": ["Verify the target is online and reachable."],
            "next_step": recommendation.get("reason", "")
        }

    all_findings = []
    all_guidance = set()
    critical_count = 0
    high_count = 0

    for host in hosts:
        ip = host.get("ip", "unknown")
        for port in host.get("ports", []):
            finding = _explain_port(ip, port)
            all_findings.append(finding)
            all_guidance.update(finding.get("guidance", []))
            risk_level = port.get("risk", {}).get("level", "low")
            if risk_level == "critical":
                critical_count += 1
            elif risk_level == "high":
                high_count += 1

    summary = _build_summary(hosts, critical_count, high_count)

    return {
        "summary": summary,
        "findings": all_findings,
        "defensive_guidance": sorted(all_guidance),
        "next_step": recommendation.get("reason", ""),
        "next_scan": recommendation.get("title", ""),
    }


def _explain_port(ip: str, port: dict) -> dict:
    port_num = port.get("port")
    service = port.get("service", "unknown")
    product = port.get("product", "")
    version = port.get("version", "")
    cves = port.get("cves", [])
    risk = port.get("risk", {})
    version_analysis = port.get("version_analysis", {})
    context = port.get("context", {})

    full_version = f"{product} {version}".strip() or "unknown version"
    risk_level = risk.get("level", "low")
    v_status = version_analysis.get("status", "unknown")

    # What was found
    what = f"Port {port_num}/{port.get('protocol','tcp')} is open running {service.upper()}"
    if full_version and full_version != "unknown version":
        what += f" ({full_version})"

    # Why it matters
    why = context.get("criticality_reason", f"{service} service is running and accessible.")

    # Version status narrative
    if v_status == "latest":
        version_note = f"{full_version} is up to date."
    elif v_status == "outdated":
        age = version_analysis.get("age_years")
        version_note = (f"{full_version} is outdated"
                        + (f" and approximately {age} years old" if age else "")
                        + ". Consider upgrading.")
    elif v_status == "unsupported":
        version_note = (f"{full_version} has reached end-of-life and no longer receives "
                        f"security patches. This is a significant risk.")
    else:
        version_note = "Version information was not detected. A version scan is recommended."

    # CVE summary
    cve_notes = []
    top_cves = cves[:3]
    for cve in top_cves:
        cve_notes.append(
            f"{cve['cve_id']} (CVSS {cve['cvss_score']}, {cve['severity'].upper()}): "
            f"{cve['description']}"
        )

    # Defensive guidance
    guidance = _get_guidance(service, v_status, cves, port_num)

    # Risk explanation
    risk_reasons = risk.get("reasons", ["No specific risk factors identified"])
    risk_explanation = f"Risk is {risk_level.upper()} (score {risk.get('score', 0)}). " + "; ".join(risk_reasons) + "."

    return {
        "port": port_num,
        "service": service,
        "version": full_version,
        "risk_level": risk_level,
        "what_was_found": what,
        "why_it_matters": why,
        "version_status": version_note,
        "cve_count": len(cves),
        "top_cves": cve_notes,
        "risk_explanation": risk_explanation,
        "guidance": guidance,
    }


def _get_guidance(service: str, v_status: str, cves: list, port_num: int) -> list:
    guidance = []

    # Patch guidance
    if v_status in ("outdated", "unsupported"):
        guidance.append(f"Upgrade {service.upper()} to the latest stable version immediately.")

    # Service-specific hardening
    service_guidance = {
        "ssh": [
            "Disable root SSH login (PermitRootLogin no in sshd_config).",
            "Use SSH key-based authentication instead of passwords.",
            "Restrict SSH access by IP using AllowUsers or firewall rules.",
        ],
        "ftp": [
            "Replace FTP with SFTP or SCP — FTP sends credentials in plaintext.",
            "If FTP must be used, restrict access to known IP ranges.",
        ],
        "http": [
            "Ensure all web traffic is redirected to HTTPS.",
            "Review web application for common vulnerabilities (OWASP Top 10).",
        ],
        "https": [
            "Verify TLS 1.2 or 1.3 is enforced. Disable SSLv3, TLS 1.0, TLS 1.1.",
            "Check SSL certificate validity and renewal schedule.",
        ],
        "mysql": [
            "Ensure MySQL is not listening on 0.0.0.0 — bind to localhost or internal IP only.",
            "Disable remote root login. Use application-specific accounts.",
        ],
        "smb": [
            "Disable SMBv1 immediately — used in WannaCry and other ransomware.",
            "Block port 445 from external access at the firewall.",
        ],
        "rdp": [
            "Place RDP behind a VPN — never expose directly to the internet.",
            "Enable Network Level Authentication (NLA).",
        ],
        "snmp": [
            "Replace SNMP v1/v2c community strings with SNMPv3 with authentication.",
            "Restrict SNMP access to monitoring systems only.",
        ],
        "telnet": [
            "Replace Telnet with SSH immediately — Telnet is plaintext.",
        ],
    }

    for tip in service_guidance.get(service, []):
        guidance.append(tip)

    # CVE-specific patches
    for cve in cves[:2]:
        if cve.get("patch"):
            guidance.append(f"CVE fix: {cve['patch']}")

    # Port restriction
    if port_num in (3306, 5432, 27017, 6379):
        guidance.append(f"Port {port_num} should not be accessible publicly. Restrict via firewall.")

    return list(dict.fromkeys(guidance))  # deduplicate


def _build_summary(hosts: list, critical: int, high: int) -> str:
    host_count = len(hosts)
    total_ports = sum(len(h.get("ports", [])) for h in hosts)

    parts = [f"Scan complete. Found {host_count} live host(s) with {total_ports} open port(s)."]

    if critical > 0:
        parts.append(f"{critical} finding(s) classified as CRITICAL — immediate action required.")
    if high > 0:
        parts.append(f"{high} finding(s) classified as HIGH — remediation strongly recommended.")
    if critical == 0 and high == 0:
        parts.append("No critical or high-severity findings detected in this scan.")

    return " ".join(parts)
