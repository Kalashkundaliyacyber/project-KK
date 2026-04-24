"""ScanWise AI — FastAPI Application Entry Point"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import os

from app.api.routes import router

app = FastAPI(
    title="ScanWise AI",
    description="Context-Aware Explainable Vulnerability Intelligence System",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

# Serve static files (the web UI)
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def serve_ui():
    index = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    return FileResponse(index)

@app.on_event("startup")
async def startup_event():
    # Ensure data directories exist at startup
    base = os.path.dirname(os.path.dirname(__file__))
    for d in ["data/sessions", "data/cve_db", "data/version_db", "data/logs", "reports", "exports"]:
        os.makedirs(os.path.join(base, d), exist_ok=True)

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
