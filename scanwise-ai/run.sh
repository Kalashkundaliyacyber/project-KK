#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Startup Script
#  Supports: Kali Linux, Ubuntu, Debian, any venv-based Python env
#  Usage:  bash run.sh              → start server
#          bash run.sh --test       → run unit tests
#          bash run.sh --benchmark  → run CVE benchmark
# ─────────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

VENV_DIR="$PROJECT_DIR/.venv"

echo ""
echo -e "${CYAN}  ███████╗ ██████╗ █████╗ ███╗   ██╗██╗    ██╗██╗███████╗███████╗${NC}"
echo -e "${CYAN}  ██╔════╝██╔════╝██╔══██╗████╗  ██║██║    ██║██║██╔════╝██╔════╝${NC}"
echo -e "${CYAN}  ███████╗██║     ███████║██╔██╗ ██║██║ █╗ ██║██║███████╗█████╗  ${NC}"
echo -e "${CYAN}  ╚════██║██║     ██╔══██║██║╚██╗██║██║███╗██║██║╚════██║██╔══╝  ${NC}"
echo -e "${CYAN}  ███████║╚██████╗██║  ██║██║ ╚████║╚███╔███╔╝██║███████║███████╗${NC}"
echo -e "${CYAN}  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝${NC}"
echo -e "${CYAN}               AI Security Intelligence Platform v1.0${NC}"
echo ""

# ── [1/5] Check Python ────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking Python...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ Python 3 not found.${NC}"
    echo -e "${RED}    Install: sudo apt install python3 python3-venv${NC}"
    exit 1
fi
PYVER=$(python3 --version)
echo -e "${GREEN}  ✓ $PYVER${NC}"

# ── [2/5] Check nmap ─────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
    NMAPVER=$(nmap --version | head -1)
    echo -e "${GREEN}  ✓ $NMAPVER${NC}"
else
    echo -e "${YELLOW}  ⚠  nmap not found — simulation mode will be used for demos.${NC}"
    echo -e "${YELLOW}     Install real scanning: sudo apt install nmap${NC}"
fi

# ── [3/5] Create data directories ────────────────────────────────
echo -e "${YELLOW}[3/5] Creating data directories...${NC}"
mkdir -p data/sessions data/cve_db data/version_db data/logs reports exports
echo -e "${GREEN}  ✓ Directories ready${NC}"

# ── [4/5] Set up Python virtual environment ───────────────────────
echo -e "${YELLOW}[4/5] Setting up Python virtual environment...${NC}"

# Check python3-venv is available
if ! python3 -c "import venv" &>/dev/null; then
    echo -e "${RED}  ✗ python3-venv module not found.${NC}"
    echo -e "${RED}    Install it: sudo apt install python3-venv${NC}"
    exit 1
fi

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${CYAN}  → Creating virtual environment at .venv/ ...${NC}"
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}  ✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}  ✓ Virtual environment already exists${NC}"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# Upgrade pip silently
pip install --upgrade pip -q

# Install project dependencies
echo -e "${CYAN}  → Installing dependencies into .venv/ ...${NC}"
pip install -r requirements.txt -q
echo -e "${GREEN}  ✓ All dependencies installed in .venv/${NC}"

# ── [5/5] Run or start ────────────────────────────────────────────
if [[ "$1" == "--benchmark" ]]; then
    echo -e "${YELLOW}\n[BENCHMARK] Running 5-fixture CVE evaluation suite...${NC}"
    python3 tests/benchmark.py
    deactivate
    exit 0
fi

if [[ "$1" == "--test" ]]; then
    echo -e "${YELLOW}\n[TESTS] Running full unit test suite (209 tests)...${NC}"
    python3 tests/run_tests.py
    deactivate
    exit 0
fi

echo -e "${YELLOW}[5/5] Starting ScanWise AI server...${NC}"
echo ""
echo -e "${GREEN}  ✓ Server starting at http://localhost:8000${NC}"
echo -e "${GREEN}  ✓ Open your browser → http://localhost:8000${NC}"
echo -e "${CYAN}  Press Ctrl+C to stop${NC}"
echo ""

python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
