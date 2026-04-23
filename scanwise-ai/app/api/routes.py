"""ScanWise AI — API Routes"""
from datetime import datetime
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from typing import Optional

from app.api.validators import validate_target, validate_scan_type
from app.scanner.orchestrator import CommandOrchestrator
from app.scanner.executor import ScanExecutor
from app.parser.nmap_parser import NmapParser
from app.analysis.version_engine import VersionEngine
from app.cve.mapper import CVEMapper
from app.analysis.context_engine import ContextEngine
from app.analysis.risk_engine import RiskEngine
from app.recommendation.recommender import Recommender
from app.explanation.explainer import Explainer
from app.files.session_manager import SessionManager
from app.report.template_builder import ReportBuilder

router = APIRouter()

class ScanRequest(BaseModel):
    target: str
    scan_type: str
    message: Optional[str] = None

    @field_validator("target")
    @classmethod
    def check_target(cls, v):
        if not validate_target(v):
            raise ValueError(f"Invalid target: {v}")
        return v.strip()

    @field_validator("scan_type")
    @classmethod
    def check_scan_type(cls, v):
        if not validate_scan_type(v):
            raise ValueError(f"Unknown scan type: {v}")
        return v

class ChatRequest(BaseModel):
    message: str
    target: Optional[str] = None


@router.get("/health")
async def health():
    return {"status": "ok", "service": "ScanWise AI", "version": "1.0.0"}


@router.post("/chat")
async def chat(req: ChatRequest):
    orchestrator = CommandOrchestrator()
    intent = orchestrator.parse_intent(req.message)
    return {"intent": intent, "suggested_scan": intent.get("scan_type", "tcp_basic"),
            "message": intent.get("explanation", "Ready to scan.")}


@router.post("/scan")
async def run_scan(req: ScanRequest):
    orchestrator = CommandOrchestrator()
    executor = ScanExecutor()
    command = orchestrator.build_command(req.scan_type, req.target)
    if not command:
        raise HTTPException(400, "Could not build safe command")

    session_id = SessionManager.create_session(req.target, req.scan_type)
    raw_output, error, rc = executor.execute(command, session_id)
    SessionManager.save_raw(session_id, raw_output, error)

    parser = NmapParser()
    parsed = parser.parse(raw_output, req.target)
    SessionManager.save_parsed(session_id, parsed)

    version_engine = VersionEngine()
    for port in parsed.get("ports", []):
        port["version_analysis"] = version_engine.analyze(
            port.get("service", ""), port.get("version", ""))

    cve_mapper = CVEMapper()
    for port in parsed.get("ports", []):
        port["cves"] = cve_mapper.lookup(
            port.get("service", ""), port.get("version", ""))

    context_engine = ContextEngine()
    context = context_engine.analyze(parsed, req.target)

    risk_engine = RiskEngine()
    risk_results = risk_engine.prioritize(parsed.get("ports", []), context)

    recommender = Recommender()
    recommendations = recommender.suggest(parsed, req.scan_type, risk_results)

    explainer = Explainer()
    explanations = explainer.explain(parsed, risk_results, recommendations)

    analysis = {
        "session_id": session_id,
        "target": req.target,
        "scan_type": req.scan_type,
        "timestamp": datetime.now().isoformat(),
        "parsed": parsed,
        "context": context,
        "risk_results": risk_results,
        "recommendations": recommendations,
        "explanations": explanations,
        "command_used": " ".join(command),
        "raw_output": raw_output,
        "error_output": error,
        "return_code": rc,
    }
    SessionManager.save_analysis(session_id, analysis)
    return analysis


@router.get("/history")
async def get_history(target: Optional[str] = None, severity: Optional[str] = None):
    sessions = SessionManager.list_sessions(target=target, severity=severity)
    return {"sessions": sessions}


@router.get("/history/{session_id}")
async def get_session(session_id: str):
    session = SessionManager.load_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    return session


@router.post("/export/{session_id}")
async def export_report(session_id: str):
    session = SessionManager.load_session(session_id)
    if not session:
        raise HTTPException(404, "Session not found")
    builder = ReportBuilder()
    report = builder.build(session)
    report_path = SessionManager.save_report(session_id, report)
    return {"report": report, "saved_to": str(report_path)}


@router.get("/scan-types")
async def get_scan_types():
    orchestrator = CommandOrchestrator()
    return {"scan_types": orchestrator.get_scan_types()}
