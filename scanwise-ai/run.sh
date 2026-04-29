#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Run Script
#  FIRST TIME: run   bash setup_env.sh
#  THEN:       run   bash run.sh
# ─────────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"
PY="$VENV/bin/python3"

# Load .env if it exists
if [ -f "$PROJECT_DIR/.env" ]; then
    export $(grep -v '^\#' "$PROJECT_DIR/.env" | xargs)
    echo -e "${GREEN}  ✓ API key loaded from .env${NC}"
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

# ── Check venv exists ─────────────────────────────────────────────
if [ ! -f "$PY" ]; then
    echo -e "${RED}  ✗ Virtual environment not found.${NC}"
    echo -e "${YELLOW}  → Run first:  bash setup_env.sh${NC}"
    exit 1
fi

# ── Verify imports are working ────────────────────────────────────
echo -e "${YELLOW}[1/3] Checking environment...${NC}"
"$PY" -c "
import sys
try:
    import fastapi, uvicorn, pydantic, jinja2
    assert pydantic.VERSION.startswith('1.'), f'pydantic {pydantic.VERSION} is v2 — run setup_env.sh'
    print(f'  fastapi {fastapi.__version__}  uvicorn {uvicorn.__version__}  pydantic {pydantic.VERSION}')
except Exception as e:
    print(f'  ✗ {e}')
    sys.exit(1)
" 2>&1
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Environment check failed. Run: bash setup_env.sh${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ Environment OK${NC}"

# ── Check nmap ────────────────────────────────────────────────────
echo -e "${YELLOW}[2/3] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}  ✓ $(nmap --version | head -1)${NC}"
else
    echo -e "${YELLOW}  ⚠  nmap not found — simulation mode active${NC}"
fi

# ── Data directories ──────────────────────────────────────────────
mkdir -p data/sessions data/cve_db data/logs reports exports

# ── Optional modes ────────────────────────────────────────────────
if [ "$1" = "--test" ]; then
    echo -e "${YELLOW}\n[TESTS] Running 209 unit tests...${NC}"
    "$PY" tests/run_tests.py
    exit $?
fi

if [ "$1" = "--benchmark" ]; then
    echo -e "${YELLOW}\n[BENCHMARK] Running CVE benchmark...${NC}"
    "$PY" tests/benchmark.py
    exit $?
fi

# ── Start server ──────────────────────────────────────────────────
echo -e "${YELLOW}[3/3] Starting ScanWise AI...${NC}"
echo ""
echo -e "${GREEN}  ✓ Running at → http://localhost:8000${NC}"
echo -e "${GREEN}  ✓ Open browser → http://localhost:8000${NC}"
echo -e "${CYAN}  Ctrl+C to stop${NC}"
echo ""

"$PY" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload