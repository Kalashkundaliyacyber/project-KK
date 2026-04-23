"""
CVE Mapping Engine - maps service/version to known CVEs.
SAFETY: Returns CVE descriptions only. No exploit steps.
"""

LOCAL_CVE_DB = {
    "openssh": [
        {"cve_id": "CVE-2023-38408", "affected_versions": ["7.", "8.", "9.0", "9.1", "9.2"],
         "cvss_score": 9.8, "severity": "critical",
         "description": "Remote code execution via ssh-agent in OpenSSH. A malicious SSH server can execute arbitrary commands on a client running ssh-agent.",
         "patch": "Upgrade to OpenSSH 9.3p2 or later."},
        {"cve_id": "CVE-2023-28531", "affected_versions": ["8.", "9.0", "9.1", "9.2"],
         "cvss_score": 9.8, "severity": "critical",
         "description": "Memory corruption in OpenSSH ssh-agent when a PKCS#11 provider is used. Allows remote code execution.",
         "patch": "Upgrade to OpenSSH 9.3 or later."},
        {"cve_id": "CVE-2018-15473", "affected_versions": ["7.", "6.", "5."],
         "cvss_score": 5.3, "severity": "medium",
         "description": "Username enumeration vulnerability in OpenSSH. Remote attackers can determine valid usernames via a crafted packet.",
         "patch": "Upgrade to OpenSSH 7.8 or later."},
        {"cve_id": "CVE-2016-6515", "affected_versions": ["7.2", "7.1", "7.0", "6.", "5."],
         "cvss_score": 7.5, "severity": "high",
         "description": "Denial of service in OpenSSH via a very long password string causing CPU exhaustion.",
         "patch": "Upgrade to OpenSSH 7.4 or later."},
        {"cve_id": "CVE-2016-0777", "affected_versions": ["7.0", "6.", "5."],
         "cvss_score": 6.5, "severity": "medium",
         "description": "Information disclosure in OpenSSH client roaming. Private keys may be leaked to a rogue SSH server.",
         "patch": "Upgrade to OpenSSH 7.1p2 or disable UseRoaming."},
    ],
    "apache httpd": [
        {"cve_id": "CVE-2021-41773", "affected_versions": ["2.4.49"],
         "cvss_score": 9.8, "severity": "critical",
         "description": "Path traversal and remote code execution in Apache HTTP Server 2.4.49.",
         "patch": "Upgrade to Apache 2.4.51 or later immediately."},
        {"cve_id": "CVE-2021-42013", "affected_versions": ["2.4.49", "2.4.50"],
         "cvss_score": 9.8, "severity": "critical",
         "description": "Incomplete fix for CVE-2021-41773 in Apache 2.4.50. Path traversal and RCE still possible.",
         "patch": "Upgrade to Apache 2.4.51 or later."},
        {"cve_id": "CVE-2017-7679", "affected_versions": ["2.2.", "2.0.", "2.4.25", "2.4.26"],
         "cvss_score": 9.8, "severity": "critical",
         "description": "Buffer overflow in mod_mime in Apache HTTP Server. Remote code execution possible.",
         "patch": "Upgrade to Apache 2.4.26 or later. Apache 2.2.x is EOL."},
        {"cve_id": "CVE-2022-31813", "affected_versions": ["2.4.53", "2.4.52", "2.4.51", "2.4.50", "2.4.49", "2.4.48"],
         "cvss_score": 9.8, "severity": "critical",
         "description": "HTTP Request Smuggling in Apache mod_proxy allowing bypass of IP-based access controls.",
         "patch": "Upgrade to Apache 2.4.54 or later."},
    ],
    "vsftpd": [
        {"cve_id": "CVE-2011-2523", "affected_versions": ["2.3.4"],
         "cvss_score": 10.0, "severity": "critical",
         "description": "Backdoor in vsftpd 2.3.4. A shell is spawned on port 6200 when a username ending in ':)' is used. This was a supply-chain compromise.",
         "patch": "Remove vsftpd 2.3.4 immediately. Use 3.0.5 or later."},
        {"cve_id": "CVE-2021-3618", "affected_versions": ["3.0.3", "3.0.2", "3.0.1", "2.3."],
         "cvss_score": 7.4, "severity": "high",
         "description": "ALPACA cross-protocol attack allows redirecting TLS traffic intended for one service to another.",
         "patch": "Enable strict TLS SNI checking. Upgrade vsftpd to 3.0.5."},
    ],
    "mysql": [
        {"cve_id": "CVE-2016-6662", "affected_versions": ["5.5.", "5.6.", "5.7."],
         "cvss_score": 9.8, "severity": "critical",
         "description": "Remote code execution in MySQL. Attackers with any MySQL account can write to configuration files and escalate to root.",
         "patch": "Upgrade to MySQL 5.7.15 or 8.0 or later."},
        {"cve_id": "CVE-2012-2122", "affected_versions": ["5.5.", "5.1.", "5.0."],
         "cvss_score": 7.5, "severity": "high",
         "description": "Authentication bypass in MySQL via timing attack. Remote attackers can gain access without a valid password.",
         "patch": "Upgrade to MySQL 5.5.24 or later."},
        {"cve_id": "CVE-2023-21980", "affected_versions": ["8.0."],
         "cvss_score": 7.1, "severity": "high",
         "description": "MySQL Server optimizer vulnerability allowing denial of service by a low-privileged attacker.",
         "patch": "Upgrade to MySQL 8.0.33 or later."},
    ],
    "isc bind": [
        {"cve_id": "CVE-2021-25220", "affected_versions": ["9.9.", "9.11.", "9.16.", "9.18."],
         "cvss_score": 6.8, "severity": "medium",
         "description": "DNS cache poisoning in BIND 9 due to incorrect cache behavior allowing forged DNS responses.",
         "patch": "Upgrade to BIND 9.18.3 or 9.16.27."},
        {"cve_id": "CVE-2022-2795", "affected_versions": ["9.9.", "9.11.", "9.16.", "9.18."],
         "cvss_score": 5.3, "severity": "medium",
         "description": "Denial of service in BIND 9 resolver via excessive queries for a specific QNAME.",
         "patch": "Upgrade to BIND 9.18.7 or 9.16.33."},
    ],
    "net-snmp": [
        {"cve_id": "CVE-2022-44792", "affected_versions": ["5.7.", "5.8.", "5.9."],
         "cvss_score": 6.5, "severity": "medium",
         "description": "NULL pointer dereference in net-snmp. A malicious SNMP packet can crash the snmpd daemon.",
         "patch": "Upgrade to net-snmp 5.9.3 or apply vendor patches."},
        {"cve_id": "CVE-2020-15861", "affected_versions": ["5.7.", "5.6.", "5.4."],
         "cvss_score": 7.8, "severity": "high",
         "description": "Privilege escalation in net-snmp. The EXTEND MIB feature can be abused to run commands as root.",
         "patch": "Disable extend MIB or upgrade to net-snmp 5.7.3."},
    ],
}


def map_cves(versioned: dict) -> dict:
    result = dict(versioned)
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            port["cves"] = _find_cves(port)
    return result


def _find_cves(port: dict) -> list:
    service = port.get("service", "").lower()
    product = port.get("product", "").lower()
    version = port.get("version", "").lower()

    matches = []
    for db_key, cve_list in LOCAL_CVE_DB.items():
        if db_key in product or db_key in service:
            for cve in cve_list:
                if _version_affected(version, cve["affected_versions"]):
                    matches.append({
                        "cve_id": cve["cve_id"],
                        "cvss_score": cve["cvss_score"],
                        "severity": cve["severity"],
                        "description": cve["description"],
                        "patch": cve["patch"],
                    })

    matches.sort(key=lambda x: x["cvss_score"], reverse=True)
    return matches


def _version_affected(detected_version: str, affected_list: list) -> bool:
    if not detected_version:
        return False
    for pattern in affected_list:
        if detected_version.startswith(pattern) or pattern.startswith(detected_version[:3]):
            return True
    return False
