"""
Command Orchestrator
Maps scan_type string to a fixed, safe nmap argument list.
No shell injection possible. No arbitrary commands allowed.
"""

SCAN_TEMPLATES = {
    "tcp_basic": {
        "name": "TCP Connect Scan",
        "description": "Scans the top 1000 TCP ports using a full connect scan.",
        "args": ["-sT", "-T3", "--open", "-oX", "-"],
        "requires_root": False,
    },
    "tcp_syn": {
        "name": "TCP SYN Scan",
        "description": "Fast stealth SYN scan. Requires root/sudo.",
        "args": ["-sS", "-T3", "--open", "-oX", "-"],
        "requires_root": True,
    },
    "udp_scan": {
        "name": "UDP Top-100 Scan",
        "description": "Scans the top 100 UDP ports for common services.",
        "args": ["-sU", "--top-ports", "100", "-T3", "-oX", "-"],
        "requires_root": True,
    },
    "service_detect": {
        "name": "Service Detection",
        "description": "Identifies services running on open TCP ports.",
        "args": ["-sT", "-sV", "-T3", "--open", "-oX", "-"],
        "requires_root": False,
    },
    "version_deep": {
        "name": "Deep Version Detection",
        "description": "Aggressively fingerprints exact service versions.",
        "args": ["-sT", "-sV", "--version-intensity", "9", "-T3", "-oX", "-"],
        "requires_root": False,
    },
    "os_detect": {
        "name": "OS Detection",
        "description": "Attempts to identify the target operating system.",
        "args": ["-sT", "-O", "-T3", "--open", "-oX", "-"],
        "requires_root": True,
    },
    "port_range": {
        "name": "Port Range 1-1024",
        "description": "Scans well-known ports 1 through 1024.",
        "args": ["-sT", "-p", "1-1024", "-T3", "--open", "-oX", "-"],
        "requires_root": False,
    },
    "enum_scripts": {
        "name": "Script Enumeration",
        "description": "Runs default NSE scripts for deeper service enumeration.",
        "args": ["-sT", "-sC", "-sV", "-T3", "--open", "-oX", "-"],
        "requires_root": False,
    },
}


def get_scan_command(scan_type: str, target: str) -> list:
    """Return full nmap command as a safe list. Target is always last."""
    if scan_type not in SCAN_TEMPLATES:
        raise ValueError(f"Unknown scan type: {scan_type}")
    return ["nmap"] + SCAN_TEMPLATES[scan_type]["args"] + [target]
