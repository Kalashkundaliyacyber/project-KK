#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Run Script
#  Kali Linux | Python 3.13 | LAN accessible on port 3332
#
#  First time:  bash setup_env.sh
#  Every time:  bash run.sh
#  Options:     --test | --benchmark
# ─────────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"
PY="$VENV/bin/python3"
PORT="${PORT:-3332}"

# Load .env if it exists
if [ -f "$PROJECT_DIR/.env" ]; then
    export $(grep -v '^#' "$PROJECT_DIR/.env" | xargs)
    echo -e "${GREEN}  ✓ .env loaded${NC}"
fi

echo -e "${CYAN}"
echo "  ███████╗ ██████╗ █████╗ ███╗   ██╗██╗    ██╗██╗███████╗███████╗"
echo "  ██╔════╝██╔════╝██╔══██╗████╗  ██║██║    ██║██║██╔════╝██╔════╝"
echo "  ███████╗██║     ███████║██╔██╗ ██║██║ █╗ ██║██║███████╗█████╗  "
echo "  ╚════██║██║     ██╔══██║██║╚██╗██║██║███╗██║██║╚════██║██╔══╝  "
echo "  ███████║╚██████╗██║  ██║██║ ╚████║╚███╔███╔╝██║███████║███████╗"
echo "  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝"
echo -e "${NC}               AI Security Intelligence Platform v1.0"
echo ""

# ── [1/3] Check venv ─────────────────────────────────────────────
echo -e "${YELLOW}[1/3] Checking environment...${NC}"
if [ ! -f "$PY" ]; then
    echo -e "${RED}  ✗ .venv not found. Run: bash setup_env.sh${NC}"; exit 1
fi

"$PY" -c "
import fastapi, uvicorn, pydantic, jinja2
assert pydantic.VERSION.startswith('1.'), f'pydantic {pydantic.VERSION} is v2'
print(f'  fastapi {fastapi.__version__}  uvicorn {uvicorn.__version__}  pydantic {pydantic.VERSION}')
" 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Import check failed. Run: bash setup_env.sh${NC}"; exit 1
fi

# Check slowapi is installed (install via setup_env.sh if missing)
if ! "$PY" -c "import slowapi" 2>/dev/null; then
    echo -e "${RED}  ✗ slowapi not found. Run: bash setup_env.sh${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ Environment OK${NC}"

# ── [2/3] Check nmap ─────────────────────────────────────────────
echo -e "${YELLOW}[2/3] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}  ✓ $(nmap --version | head -1)${NC}"
else
    echo -e "${YELLOW}  ⚠  nmap not found — simulation mode active${NC}"
fi

mkdir -p data/sessions data/cve_db data/logs reports exports

# ── Optional modes ────────────────────────────────────────────────
if [ "$1" = "--test" ]; then
    echo -e "${YELLOW}\n[TESTS] Running unit tests...${NC}"
    "$PY" tests/run_tests.py; exit $?
fi
if [ "$1" = "--benchmark" ]; then
    echo -e "${YELLOW}\n[BENCHMARK] Running CVE benchmark...${NC}"
    "$PY" tests/benchmark.py; exit $?
fi

# ── [3/3] Detect LAN IP and start server ─────────────────────────
echo -e "${YELLOW}[3/3] Starting ScanWise AI...${NC}"

LAN_IP=$("$PY" -c "
import socket
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(('8.8.8.8',80))
    print(s.getsockname()[0]); s.close()
except: print('127.0.0.1')
")

echo ""
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Local  →  http://localhost:${PORT}${NC}"
echo -e "${GREEN}  LAN    →  http://${LAN_IP}:${PORT}${NC}"
echo -e "${CYAN}  Mobile →  Connect to same Wi-Fi, open LAN URL${NC}"
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}  Press Ctrl+C to stop${NC}"
echo ""

export PORT="$PORT"
"$PY" -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --reload
