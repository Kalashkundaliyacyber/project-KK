"""ScanWise AI — Main FastAPI Application"""
import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.api.routes import router
from app.files.session_manager import SessionManager

app = FastAPI(title="ScanWise AI", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

static_path = Path(__file__).parent.parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

app.include_router(router, prefix="/api")

@app.get("/")
async def root():
    index_path = Path(__file__).parent.parent / "static" / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "ScanWise AI API running", "docs": "/docs"}

@app.on_event("startup")
async def startup_event():
    SessionManager.initialize_directories()
    print("ScanWise AI started — http://localhost:8000")
