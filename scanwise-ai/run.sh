#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Startup Script
#  Usage: bash run.sh
# ─────────────────────────────────────────────────────────────────

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}  ███████╗ ██████╗ █████╗ ███╗   ██╗██╗    ██╗██╗███████╗███████╗${NC}"
echo -e "${CYAN}  ██╔════╝██╔════╝██╔══██╗████╗  ██║██║    ██║██║██╔════╝██╔════╝${NC}"
echo -e "${CYAN}  ███████╗██║     ███████║██╔██╗ ██║██║ █╗ ██║██║███████╗█████╗  ${NC}"
echo -e "${CYAN}  ╚════██║██║     ██╔══██║██║╚██╗██║██║███╗██║██║╚════██║██╔══╝  ${NC}"
echo -e "${CYAN}  ███████║╚██████╗██║  ██║██║ ╚████║╚███╔███╔╝██║███████║███████╗${NC}"
echo -e "${CYAN}  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚══╝╚══╝ ╚═╝╚══════╝╚══════╝${NC}"
echo -e "${CYAN}                        A I  Security Intelligence Platform v1.0${NC}"
echo ""

# ── Check Python ──────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking Python...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ Python 3 not found. Install with: sudo apt install python3${NC}"
    exit 1
fi
PYVER=$(python3 --version)
echo -e "${GREEN}  ✓ $PYVER${NC}"

# ── Check nmap ────────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
    NMAPVER=$(nmap --version | head -1)
    echo -e "${GREEN}  ✓ $NMAPVER${NC}"
else
    echo -e "${YELLOW}  ⚠ nmap not found — simulation mode will be used.${NC}"
    echo -e "${YELLOW}    Install with: sudo apt install nmap${NC}"
fi

# ── Create data directories ───────────────────────────────────────
echo -e "${YELLOW}[3/5] Creating data directories...${NC}"
mkdir -p data/sessions data/cve_db data/version_db data/logs reports exports
echo -e "${GREEN}  ✓ Directories ready${NC}"

# ── Install dependencies ──────────────────────────────────────────
echo -e "${YELLOW}[4/5] Installing Python dependencies...${NC}"
if pip3 install -r requirements.txt -q 2>&1; then
    echo -e "${GREEN}  ✓ Dependencies installed${NC}"
else
    echo -e "${YELLOW}  Trying with --break-system-packages...${NC}"
    pip3 install -r requirements.txt --break-system-packages -q
    echo -e "${GREEN}  ✓ Dependencies installed${NC}"
fi

# ── Run benchmark (optional) ──────────────────────────────────────
if [[ "$1" == "--benchmark" ]]; then
    echo -e "${YELLOW}\n[BENCHMARK] Running evaluation suite...${NC}"
    python3 tests/benchmark.py
    exit 0
fi

# ── Run tests (optional) ──────────────────────────────────────────
if [[ "$1" == "--test" ]]; then
    echo -e "${YELLOW}\n[TESTS] Running pytest suite...${NC}"
    python3 -m pytest tests/ -v
    exit 0
fi

# ── Start server ──────────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Starting ScanWise AI server...${NC}"
echo ""
echo -e "${GREEN}  ✓ ScanWise AI is starting on http://localhost:8000${NC}"
echo -e "${GREEN}  ✓ Open your browser and go to: http://localhost:8000${NC}"
echo -e "${CYAN}  Press Ctrl+C to stop${NC}"
echo ""

python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
