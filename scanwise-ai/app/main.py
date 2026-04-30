"""ScanWise AI — FastAPI Application Entry Point"""
import os
import socket
import time
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn

from app.api.routes import router

# ── Config (override via .env or environment) ──────────────────────────────
HOST       = os.environ.get("HOST", "0.0.0.0")
PORT       = int(os.environ.get("PORT", "3332"))
API_TOKEN  = os.environ.get("API_TOKEN", "")          # optional: set to require token
DEBUG      = os.environ.get("DEBUG", "false").lower() == "true"


def get_lan_ip() -> str:
    """Detect the LAN IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LAN_IP = get_lan_ip()

# ── Rate limiter ────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── FastAPI app ─────────────────────────────────────────────────────────────
app = FastAPI(
    title="ScanWise AI",
    description="Context-Aware Explainable Vulnerability Intelligence System",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS — allow localhost + LAN IP ────────────────────────────────────────
CORS_ORIGINS = [
    "http://localhost:3332",
    f"http://127.0.0.1:3332",
    f"http://{LAN_IP}:3332",
    "http://localhost:8000",
    f"http://{LAN_IP}:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Optional API token middleware ──────────────────────────────────────────
@app.middleware("http")
async def token_middleware(request: Request, call_next):
    # Only enforce token on write/scan endpoints if API_TOKEN is set
    if API_TOKEN:
        protected = ["/api/scan", "/api/report", "/api/compare"]
        if any(request.url.path.startswith(p) for p in protected):
            token = request.headers.get("X-API-Token", "")
            if token != API_TOKEN:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing API token. Set X-API-Token header."}
                )
    return await call_next(request)

# ── Routes ─────────────────────────────────────────────────────────────────
app.include_router(router, prefix="/api")

# ── Health endpoint ─────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":    "ok",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version":   "1.0.0",
    }

# ── Config endpoint ─────────────────────────────────────────────────────────
@app.get("/config")
async def config():
    return {
        "host":         LAN_IP,
        "port":         PORT,
        "local_url":    f"http://localhost:{PORT}",
        "lan_url":      f"http://{LAN_IP}:{PORT}",
        "token_enabled": bool(API_TOKEN),
        "debug":        DEBUG,
    }

# ── Static files ────────────────────────────────────────────────────────────
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def serve_ui():
    index = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "index.html")
    return FileResponse(index)


# ── Startup ─────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    base = os.path.dirname(os.path.dirname(__file__))
    for d in ["data/sessions","data/cve_db","data/version_db","data/logs","reports","exports"]:
        os.makedirs(os.path.join(base, d), exist_ok=True)

    print("\n" + "━"*54)
    print("  🛡  ScanWise AI — Security Intelligence Platform")
    print("━"*54)
    print(f"  Local  →  http://localhost:{PORT}")
    print(f"  LAN    →  http://{LAN_IP}:{PORT}")
    print(f"  Docs   →  http://localhost:{PORT}/docs")
    if API_TOKEN:
        print(f"  Token  →  Required (X-API-Token header)")
    else:
        print(f"  Token  →  Not set (open access on LAN)")
    print("━"*54 + "\n")


if __name__ == "__main__":
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
