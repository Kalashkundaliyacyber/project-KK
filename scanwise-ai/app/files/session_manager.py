"""
Session & File Management Layer
Stores all scan data in organised per-session folders.
Maintains SQLite index for search.
"""
import os, json, time, sqlite3
from pathlib import Path

BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(__file__)))), "data", "sessions")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(__file__)))), "data", "scanwise.db")

def _init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            target TEXT,
            scan_type TEXT,
            timestamp TEXT,
            overall_risk TEXT,
            open_ports INTEGER,
            cve_count INTEGER
        )
    """)
    conn.commit()
    conn.close()

_init_db()


def create_session(target: str, scan_type: str) -> str:
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(".", "-")
    session_id = f"{ts}_{safe_target}_{scan_type}"

    session_path = os.path.join(BASE_DIR, session_id)
    for sub in ("raw", "parsed", "analysis", "logs", "report"):
        os.makedirs(os.path.join(session_path, sub), exist_ok=True)

    # Log creation
    log_path = os.path.join(session_path, "logs", "session.log")
    with open(log_path, "w") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Session created\n")
        f.write(f"Target: {target}\nScan type: {scan_type}\nSession ID: {session_id}\n")

    return session_id


def save_raw(session_id: str, raw_output: str, xml_output: str):
    base = os.path.join(BASE_DIR, session_id, "raw")
    with open(os.path.join(base, "output.txt"), "w") as f:
        f.write(raw_output)
    with open(os.path.join(base, "output.xml"), "w") as f:
        f.write(xml_output)


def save_parsed(session_id: str, parsed: dict):
    path = os.path.join(BASE_DIR, session_id, "parsed", "parsed.json")
    with open(path, "w") as f:
        json.dump(parsed, f, indent=2)


def save_analysis(session_id: str, analysis: dict):
    path = os.path.join(BASE_DIR, session_id, "analysis", "analysis.json")
    with open(path, "w") as f:
        json.dump(analysis, f, indent=2)

    # Update SQLite index
    hosts = analysis.get("risk", {}).get("hosts", [])
    overall_risk = "low"
    total_cves = 0
    total_ports = 0

    for host in hosts:
        rs = host.get("risk_summary", {})
        if rs.get("overall") in ("critical", "high", "medium"):
            if rs["overall"] == "critical":
                overall_risk = "critical"
            elif rs["overall"] == "high" and overall_risk != "critical":
                overall_risk = "high"
            elif rs["overall"] == "medium" and overall_risk not in ("critical", "high"):
                overall_risk = "medium"
        total_ports += rs.get("total_ports", 0)
        for port in host.get("ports", []):
            total_cves += len(port.get("cves", []))

    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT OR REPLACE INTO sessions
        (session_id, target, scan_type, timestamp, overall_risk, open_ports, cve_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        session_id,
        analysis.get("target", ""),
        analysis.get("scan_type", ""),
        analysis.get("timestamp", ""),
        overall_risk,
        total_ports,
        total_cves
    ))
    conn.commit()
    conn.close()


def list_sessions(target: str = None, severity: str = None) -> list:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM sessions"
    params = []
    conditions = []

    if target:
        conditions.append("target LIKE ?")
        params.append(f"%{target}%")
    if severity:
        conditions.append("overall_risk = ?")
        params.append(severity)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp DESC LIMIT 100"

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_session(session_id: str) -> dict:
    path = os.path.join(BASE_DIR, session_id, "analysis", "analysis.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)
