"""Input validation — target and scan type sanitization."""
import re

ALLOWED_SCAN_TYPES = [
    "tcp_basic", "tcp_syn", "udp_scan", "service_detect",
    "version_deep", "os_detect", "port_range", "enum_scripts"
]

TARGET_PATTERN = re.compile(
    r'^((\d{1,3}\.){3}\d{1,3}'
    r'|localhost'
    r'|([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}'
    r'|(\d{1,3}\.){3}\d{1,3}/\d{1,2})$'
)


def validate_target(target: str) -> str:
    try:
        from fastapi import HTTPException
        Exc = HTTPException
    except ImportError:
        class Exc(Exception):
            def __init__(self, status_code=400, detail=""):
                super().__init__(detail)

    target = target.strip()
    if not target:
        raise Exc(status_code=400, detail="Target cannot be empty")
    if len(target) > 100:
        raise Exc(status_code=400, detail="Target too long")
    if not TARGET_PATTERN.match(target):
        raise Exc(status_code=400,
                  detail="Invalid target. Use IP, hostname, or CIDR e.g. 192.168.1.0/24")
    return target


def validate_scan_type(scan_type: str) -> str:
    try:
        from fastapi import HTTPException
        Exc = HTTPException
    except ImportError:
        class Exc(Exception):
            def __init__(self, status_code=400, detail=""):
                super().__init__(detail)

    scan_type = scan_type.strip().lower()
    if scan_type not in ALLOWED_SCAN_TYPES:
        raise Exc(status_code=400,
                  detail=f"Unknown scan type. Allowed: {', '.join(ALLOWED_SCAN_TYPES)}")
    return scan_type
