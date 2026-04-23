"""
Command Orchestrator — maps scan type to a safe, fixed nmap argument list.
No shell injection possible. No arbitrary command construction.
"""

SCAN_TEMPLATES = {
    "tcp_basic":      {"name": "TCP Connect Scan",        "description": "Scans top 1000 TCP ports using a full connect scan.",                "args": ["-sT", "-T3", "--open", "-oX", "-"],                        "requires_root": False},
    "tcp_syn":        {"name": "TCP SYN Scan",             "description": "Faster stealth SYN scan (requires root/sudo).",                      "args": ["-sS", "-T3", "--open", "-oX", "-"],                        "requires_root": True},
    "udp_scan":       {"name": "UDP Top-100 Scan",         "description": "Scans top 100 UDP ports for commonly used services.",                "args": ["-sU", "--top-ports", "100", "-T3", "-oX", "-"],            "requires_root": True},
    "service_detect": {"name": "Service Detection",        "description": "Identifies services running on open ports.",                         "args": ["-sT", "-sV", "-T3", "--open", "-oX", "-"],                 "requires_root": False},
    "version_deep":   {"name": "Deep Version Detection",   "description": "Aggressively fingerprints service versions.",                        "args": ["-sT", "-sV", "--version-intensity", "9", "-T3", "-oX", "-"],"requires_root": False},
    "os_detect":      {"name": "OS Detection",             "description": "Attempts to identify the operating system.",                         "args": ["-sT", "-O", "-T3", "--open", "-oX", "-"],                  "requires_root": True},
    "port_range":     {"name": "Port Range Scan 1-1024",   "description": "Scans ports 1–1024 (well-known ports).",                            "args": ["-sT", "-p", "1-1024", "-T3", "--open", "-oX", "-"],        "requires_root": False},
    "enum_scripts":   {"name": "Script Enumeration",       "description": "Runs default NSE scripts for deeper service enumeration.",           "args": ["-sT", "-sC", "-sV", "-T3", "--open", "-oX", "-"],          "requires_root": False},
}

def get_scan_command(scan_type: str, target: str) -> list:
    """Return the full nmap command as a safe argument list. Target is always last."""
    if scan_type not in SCAN_TEMPLATES:
        raise ValueError(f"Unknown scan type: {scan_type}")
    return ["nmap"] + SCAN_TEMPLATES[scan_type]["args"] + [target]
