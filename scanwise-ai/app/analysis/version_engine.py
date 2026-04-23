"""
Version Detection Engine
Classifies service versions as latest, outdated, or unsupported.
"""

VERSION_DB = {
    "ssh": [
        ("OpenSSH 9.8", "latest", 2024, None),
        ("OpenSSH 9.7", "latest", 2024, None),
        ("OpenSSH 9.6", "outdated", 2023, None),
        ("OpenSSH 9.0", "outdated", 2022, None),
        ("OpenSSH 8.9", "outdated", 2022, None),
        ("OpenSSH 8.0", "outdated", 2019, None),
        ("OpenSSH 7.9", "outdated", 2018, None),
        ("OpenSSH 7.4", "outdated", 2016, None),
        ("OpenSSH 7.2", "outdated", 2016, None),
        ("OpenSSH 6", "unsupported", 2013, 2015),
        ("OpenSSH 5", "unsupported", 2008, 2012),
    ],
    "http": [
        ("Apache httpd 2.4.62", "latest", 2024, None),
        ("Apache httpd 2.4.60", "outdated", 2024, None),
        ("Apache httpd 2.4.58", "outdated", 2023, None),
        ("Apache httpd 2.4.51", "outdated", 2021, None),
        ("Apache httpd 2.4.49", "outdated", 2021, None),
        ("Apache httpd 2.4.29", "outdated", 2017, None),
        ("Apache httpd 2.2.34", "unsupported", 2017, 2018),
        ("Apache httpd 2.2", "unsupported", 2005, 2018),
        ("Apache httpd 2.0", "unsupported", 2002, 2013),
        ("nginx 1.26", "latest", 2024, None),
        ("nginx 1.24", "outdated", 2023, None),
        ("nginx 1.18", "outdated", 2020, None),
        ("nginx 1.14", "unsupported", 2018, 2020),
    ],
    "https": [
        ("Apache httpd 2.4.62", "latest", 2024, None),
        ("Apache httpd 2.2.34", "unsupported", 2017, 2018),
        ("nginx 1.26", "latest", 2024, None),
        ("nginx 1.18", "outdated", 2020, None),
    ],
    "ftp": [
        ("vsftpd 3.0.5", "latest", 2021, None),
        ("vsftpd 3.0.3", "outdated", 2015, None),
        ("vsftpd 2.3.5", "outdated", 2011, None),
        ("vsftpd 2.3.4", "unsupported", 2011, 2011),
        ("ProFTPD 1.3.8", "latest", 2023, None),
        ("ProFTPD 1.3.5", "outdated", 2014, None),
    ],
    "mysql": [
        ("MySQL 8.4", "latest", 2024, None),
        ("MySQL 8.0", "outdated", 2018, None),
        ("MySQL 5.7", "outdated", 2015, 2023),
        ("MySQL 5.6", "unsupported", 2013, 2021),
        ("MySQL 5.5", "unsupported", 2010, 2018),
    ],
    "domain": [
        ("ISC BIND 9.18", "latest", 2022, None),
        ("ISC BIND 9.16", "outdated", 2020, None),
        ("ISC BIND 9.11", "unsupported", 2016, 2022),
        ("ISC BIND 9.9.5", "unsupported", 2013, 2018),
    ],
    "snmp": [
        ("net-snmp 5.9", "latest", 2020, None),
        ("net-snmp 5.7", "outdated", 2013, None),
        ("net-snmp 5.6", "outdated", 2011, None),
        ("net-snmp 5.4", "unsupported", 2007, 2013),
    ],
}

def analyze_versions(parsed: dict) -> dict:
    result = dict(parsed)
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            port["version_analysis"] = _analyze_port_version(port)
    return result


def _analyze_port_version(port: dict) -> dict:
    service = port.get("service", "").lower()
    product = port.get("product", "")
    version = port.get("version", "")
    full_version = f"{product} {version}".strip()

    if not full_version or full_version == " ":
        return {
            "status": "unknown",
            "version_string": "Not detected",
            "confidence": "low",
            "message": "No version information available. Consider running a version detection scan."
        }

    candidates = VERSION_DB.get(service, [])

    for db_version, status, rel_year, eol_year in candidates:
        if _version_matches(full_version, db_version):
            age_years = 2025 - rel_year
            return {
                "status": status,
                "version_string": full_version,
                "db_entry": db_version,
                "release_year": rel_year,
                "eol_year": eol_year,
                "age_years": age_years,
                "confidence": "high",
                "message": _status_message(status, full_version, age_years, eol_year)
            }

    if candidates:
        return {
            "status": "outdated",
            "version_string": full_version,
            "confidence": "medium",
            "message": f"{full_version} is not in the version database. Treat as potentially outdated.",
            "age_years": None
        }

    return {
        "status": "unknown",
        "version_string": full_version,
        "confidence": "low",
        "message": f"Service '{service}' is not in the version knowledge base.",
        "age_years": None
    }


def _version_matches(detected: str, db_entry: str) -> bool:
    d = detected.lower().strip()
    db = db_entry.lower().strip()
    return d.startswith(db) or db.startswith(d) or db in d


def _status_message(status: str, version: str, age: int, eol_year) -> str:
    if status == "latest":
        return f"{version} is up to date."
    if status == "outdated":
        return f"{version} is outdated ({age} years old). Upgrade recommended."
    if status == "unsupported":
        eol = f" (EOL: {eol_year})" if eol_year else ""
        return f"{version} is end-of-life{eol}. No longer receives security patches. Replace immediately."
    return f"{version}: status unknown."
