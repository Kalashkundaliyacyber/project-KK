"""ScanWise AI — API Routes (full feature set)"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import os, time

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
from app.ai_analysis import analyze_scan
from app.visualization.charts import generate_chart_data, generate_history_trends
from app.report.template_builder import build_report
from app.report.html_report import build_html_report
from app.ai_comparison.compare import compare_analyses
from app.files.session_manager import (
    create_session, save_raw, save_parsed, save_analysis,
    list_sessions, get_session
)

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

class CompareRequest(BaseModel):
    session_id: str


# ── Chat ──────────────────────────────────────────────────────────────────────

@router.get("/templates")
async def get_templates():
    return {"templates": list(SCAN_TEMPLATES.keys())}


@router.post("/chat")
async def chat(req: ChatRequest):
    msg = req.message.lower()
    suggestions = []

    keywords = {
        "tcp": "tcp_basic", "port": "tcp_basic", "open": "tcp_basic",
        "udp": "udp_scan", "service": "service_detect",
        "version": "version_deep", "os": "os_detect",
        "script": "enum_scripts", "enum": "enum_scripts",
        "syn": "tcp_syn", "range": "port_range",
    }
    matched = next((t for kw, t in keywords.items() if kw in msg), None)

    if matched:
        info   = SCAN_TEMPLATES[matched]
        reply  = (f"I suggest a **{info['name']}** scan. {info['description']} "
                  f"Select '{matched}' and click Scan.")
        suggestions = [matched]
    elif any(w in msg for w in ["chart","graph","visual","dashboard"]):
        reply = ("Charts are shown automatically after each scan — "
                 "check the **Dashboard** tab for risk distribution, service charts, "
                 "and CVE breakdown. The History tab shows trends over time.")
    elif any(w in msg for w in ["report","export","pdf","html"]):
        reply = ("After scanning, click **Export Report** to download a full HTML report "
                 "with charts, findings, CVEs, and guidance. "
                 "Open in browser and use Ctrl+P → Save as PDF.")
    elif any(w in msg for w in ["compare","ai","analysis"]):
        reply = ("After a scan, use the **Compare AI vs Rules** button to see how "
                 "Claude AI compares to rule-based analysis on 5 metrics: "
                 "correctness, explainability, usefulness, conciseness, and recommendation quality.")
    elif any(w in msg for w in ["history","previous","past"]):
        reply = ("Click the **History** tab to view all past scans, "
                 "filter by target, risk level, or date, "
                 "and see trend charts over time.")
    elif any(w in msg for w in ["hello","hi","help","what","start"]):
        reply = ("Welcome to **ScanWise AI**! "
                 "Enter a target IP, choose a scan type, and click Scan. "
                 "I'll map CVEs, score risk, generate charts, and explain everything. "
                 "Use the Dashboard for visuals, History for trends, and Export for reports.")
    elif any(w in msg for w in ["cve","vuln"]):
        reply = ("CVE mapping runs after every scan automatically. "
                 "I match each service/version to known CVEs and show severity, "
                 "CVSS score, and patch advice in the CVE tab and the HTML report.")
    elif any(w in msg for w in ["risk","score","critical"]):
        reply = ("Risk is scored 0–10 using CVSS, exposure, version age, and criticality → "
                 "Low / Medium / High / Critical. "
                 "The Dashboard shows a risk gauge and distribution chart.")
    else:
        reply = ("I can run TCP, UDP, service detection, version detection, "
                 "OS detection, or script enumeration scans. "
                 "Type a target above and choose a scan type to begin.")

    return {"reply": reply, "suggestions": suggestions}


# ── Scan ──────────────────────────────────────────────────────────────────────

@router.post("/scan")
async def run_scan(req: ScanRequest):
    target    = validate_target(req.target)
    scan_type = validate_scan_type(req.scan_type)
    session_id = create_session(target, scan_type)
    cmd = get_scan_command(scan_type, target)

    try:
        raw_output, xml_output, duration = execute_scan(cmd, target, scan_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    save_raw(session_id, raw_output, xml_output)
    parsed         = parse_nmap_output(xml_output, raw_output)
    save_parsed(session_id, parsed)

    versioned      = analyze_versions(parsed)
    cve_data       = map_cves(versioned)
    context        = analyze_context(cve_data)
    risk           = calculate_risk(context)
    recommendation = get_recommendation(risk, scan_type)
    explanation    = generate_explanation(risk, recommendation)
    ai_analysis    = analyze_scan(risk)
    charts         = generate_chart_data({"risk": risk})

    analysis = {
        "session_id":     session_id,
        "target":         target,
        "scan_type":      scan_type,
        "duration":       duration,
        "parsed":         parsed,
        "versioned":      versioned,
        "cve_data":       cve_data,
        "context":        context,
        "risk":           risk,
        "recommendation": recommendation,
        "explanation":    explanation,
        "ai_analysis":    ai_analysis,
        "charts":         charts,
        "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_analysis(session_id, analysis)
    return analysis


# ── History ───────────────────────────────────────────────────────────────────

@router.get("/history")
async def get_history(target: Optional[str] = None, severity: Optional[str] = None):
    sessions = list_sessions(target=target, severity=severity)
    return {"sessions": sessions}


@router.get("/history/trends")
async def get_history_trends():
    sessions = list_sessions()
    trends   = generate_history_trends(sessions)
    return trends


@router.get("/session/{session_id}")
async def get_session_detail(session_id: str):
    data = get_session(session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    return data


# ── Reports ───────────────────────────────────────────────────────────────────

@router.post("/report")
async def generate_report(req: ReportRequest):
    data = get_session(req.session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    json_path = build_report(req.session_id, data)
    html_path = build_html_report(req.session_id, data)
    return {
        "session_id": req.session_id,
        "json_path":  json_path,
        "html_path":  html_path,
    }


@router.get("/report/download/json/{session_id}")
async def download_json_report(session_id: str):
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data", "sessions", session_id, "report", "report.json"
    )
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not generated yet")
    return FileResponse(path, media_type="application/json",
                        filename=f"scanwise_{session_id}.json")


@router.get("/report/download/html/{session_id}")
async def download_html_report(session_id: str):
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "data", "sessions", session_id, "report", "report.html"
    )
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="HTML report not generated yet")
    return FileResponse(path, media_type="text/html",
                        filename=f"scanwise_report_{session_id}.html")


# ── AI Comparison ─────────────────────────────────────────────────────────────

@router.post("/compare")
async def compare_ai_vs_rules(req: CompareRequest):
    data = get_session(req.session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")

    ai_result = data.get("ai_analysis", {})
    if not ai_result:
        raise HTTPException(status_code=400, detail="No AI analysis in this session")

    # Run rule-based again for comparison
    from app.ai_analysis import _rule_based_analyze
    rule_result = _rule_based_analyze(data.get("risk", {}))

    comparison = compare_analyses(rule_result, ai_result)
    return comparison


# ── Charts endpoint (for re-fetching chart data) ──────────────────────────────

@router.get("/charts/{session_id}")
async def get_charts(session_id: str):
    data = get_session(session_id)
    if not data:
        raise HTTPException(status_code=404, detail="Session not found")
    charts = data.get("charts") or generate_chart_data({"risk": data.get("risk", {})})
    return charts
