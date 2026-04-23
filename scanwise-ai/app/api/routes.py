from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import os, json, time

from app.api.validators import validate_target, validate_scan_type
from app.scanner.orchestrator import get_scan_command, SCAN_TEMPLATES
from app.scanner.executor import execute_scan
from app.parser.nmap_parser import parse_nmap_output
from app.analysis.version_engine import analyze_versions
from app.cve.mapper import map_cves
from app.analysis.context_engine import analyze_context
from app.analysis.risk_engine import calculate_risk
from app.recommendation.recommender import get_recommendation
from app.explanation.explainer import generate_explanation
from app.files.session_manager import (
    create_session, save_raw, save_parsed, save_analysis, list_sessions, get_session
)
from app.report.template_builder import build_report

router = APIRouter()

class ScanRequest(BaseModel):
    target: str
    scan_type: str
    message: Optional[str] = ""

class ChatRequest(BaseModel):
    message: str
    target: Optional[str] = ""

class ReportRequest(BaseModel):
    session_id: str

@router.get("/templates")
async def get_templates():
    return {"templates": list(SCAN_TEMPLATES.keys())}

@router.post("/chat")
async def chat(req: ChatRequest):
    msg = req.message.lower()
    suggestions = []
    reply = ""

    keywords = {
        "tcp": "tcp_basic", "port": "tcp_basic", "open": "tcp_basic",
        "udp": "udp_scan", "service": "service_detect",
        "version": "version_deep", "os": "os_detect",
        "script": "enum_scripts", "enum": "enum_scripts",
        "syn": "tcp_syn", "range": "port_range"
    }

    matched = None
    for kw, template in keywords.items():
        if kw in msg:
            matched = template
            break

    if matched:
        cmd_info = SCAN_TEMPLATES[matched]
        reply = (f"I suggest running a **{cmd_info['name']}** scan. "
                 f"{cmd_info['description']} "
                 f"Select '{matched}' from the scan menu and hit Scan.")
        suggestions = [matched]
    elif any(w in msg for w in ["hello", "hi", "help", "what"]):
        reply = ("Welcome to **ScanWise AI**! I can help you scan a target for open ports, "
                 "detect services and versions, map CVEs, and prioritize risks. "
                 "Enter a target IP/hostname, choose a scan type, and click Scan.")
    elif any(w in msg for w in ["cve", "vulnerab"]):
        reply = ("CVE mapping is done automatically after each scan. "
                 "I look up known vulnerabilities for every service and version discovered.")
    elif any(w in msg for w in ["risk", "danger", "critical"]):
        reply = ("Risk is scored using CVSS severity, service exposure, version age, "
                 "and service criticality → Low / Medium / High / Critical.")
    else:
        reply = ("I can help you run TCP, UDP, service detection, version detection, "
                 "OS detection, or script-based enumeration scans. "
                 "Enter a target and choose a scan type to get started.")

    return {"reply": reply, "suggestions": suggestions}

@router.post("/scan")
async def run_scan(req: ScanRequest):
    target = validate_target(req.target)
    scan_type = validate_scan_type(req.scan_type)

    session_id = create_session(target, scan_type)
    cmd = get_scan_command(scan_type, target)

    try:
        raw_output, xml_output, duration = execute_scan(cmd, target, scan_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    save_raw(session_id, raw_output, xml_output)

    parsed = parse_nmap_output(xml_output, raw_output)
    save_parsed(session_id, parsed)

    versioned  = analyze_versions(parsed)
    cve_data   = map_cves(versioned)
    context    = analyze_context(cve_data)
    risk       = calculate_risk(context)
    recommendation = get_recommendation(risk, scan_type)
    explanation    = generate_explanation(risk, recommendation)

    analysis = {
        "session_id": session_id,
        "target": target,
        "scan_type": scan_type,
        "duration": duration,
        "parsed": parsed,
        "versioned": versioned,
        "cve_data": cve_data,
        "context": context,
        "risk": risk,
        "recommendation": recommendation,
        "explanation": explanation,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    save_analysis(session_id, analysis)
    return analysis

@router.get("/history")
async def get_history(target: Optional[str] = None, severity: Optional[str] = None):
    sessions = list_sessions(target=target, severity=severity)
    return {"sessions": sessions}

@router.get("/session/{session_id}")
async def get_session_detail(session_id: str):
    data = get_session(session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    return data

@router.post("/report")
async def generate_report(req: ReportRequest):
    data = get_session(req.session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    report_path = build_report(req.session_id, data)
    return {"report_path": report_path, "session_id": req.session_id}

@router.get("/report/download/{session_id}")
async def download_report(session_id: str):
    base = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data", "sessions", session_id, "report"
    )
    json_path = os.path.join(base, "report.json")
    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="Report not yet generated")
    return FileResponse(json_path, media_type="application/json",
                        filename=f"scanwise_report_{session_id}.json")
