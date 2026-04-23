#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Startup Script
#  Kali Linux / Ubuntu / Debian — Python 3.10 → 3.13 compatible
#  Usage:
#    bash run.sh              → start server
#    bash run.sh --test       → run unit tests
#    bash run.sh --benchmark  → run CVE benchmark
# ─────────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

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
    echo -e "${RED}  ✗ Python 3 not found. Run: sudo apt install python3 python3-venv${NC}"
    exit 1
fi
PYVER=$(python3 --version)
echo -e "${GREEN}  ✓ $PYVER${NC}"

# ── [2/5] Check nmap ─────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}  ✓ $(nmap --version | head -1)${NC}"
else
    echo -e "${YELLOW}  ⚠  nmap not installed — simulation mode active${NC}"
    echo -e "${YELLOW}     Real scans: sudo apt install nmap${NC}"
fi

# ── [3/5] Data directories ────────────────────────────────────────
echo -e "${YELLOW}[3/5] Creating data directories...${NC}"
mkdir -p data/sessions data/cve_db data/version_db data/logs reports exports
echo -e "${GREEN}  ✓ Directories ready${NC}"

# ── [4/5] Virtual environment + install ──────────────────────────
echo -e "${YELLOW}[4/5] Setting up Python virtual environment...${NC}"

if ! python3 -c "import venv" &>/dev/null; then
    echo -e "${RED}  ✗ python3-venv missing. Run: sudo apt install python3-venv${NC}"
    exit 1
fi

# Always recreate venv if pydantic v2 is somehow present (corrupted state)
if [ -d "$VENV_DIR" ]; then
    BAD_PYDANTIC=$("$VENV_DIR/bin/python3" -c "import pydantic; print(pydantic.VERSION)" 2>/dev/null | cut -d. -f1)
    if [ "$BAD_PYDANTIC" = "2" ]; then
        echo -e "${YELLOW}  ⚠  Detected pydantic v2 in existing venv — recreating clean venv...${NC}"
        rm -rf "$VENV_DIR"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${CYAN}  → Creating fresh .venv/ ...${NC}"
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}  ✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}  ✓ Virtual environment exists${NC}"
fi

source "$VENV_DIR/bin/activate"

# Upgrade pip to latest
pip install --upgrade pip --quiet

# ── KEY FIX: Explicitly uninstall pydantic v2 if somehow present ──
pip uninstall pydantic pydantic-core -y --quiet 2>/dev/null || true

# Install pydantic v1 first, pinned — no Rust, pure Python
echo -e "${CYAN}  → Installing pydantic v1 (pure Python, no Rust)...${NC}"
pip install "pydantic==1.10.21" --no-deps --quiet
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Failed to install pydantic. Check internet connection.${NC}"
    deactivate; exit 1
fi

# Verify we got v1
PYDANTIC_VER=$("$VENV_DIR/bin/python3" -c "import pydantic; print(pydantic.VERSION)")
PYDANTIC_MAJOR=$(echo "$PYDANTIC_VER" | cut -d. -f1)
if [ "$PYDANTIC_MAJOR" != "1" ]; then
    echo -e "${RED}  ✗ Wrong pydantic version: $PYDANTIC_VER (need 1.x)${NC}"
    deactivate; exit 1
fi
echo -e "${GREEN}  ✓ pydantic $PYDANTIC_VER installed (pure Python)${NC}"

# Install remaining packages — exclude pydantic (already installed)
echo -e "${CYAN}  → Installing remaining dependencies...${NC}"
pip install \
    "fastapi==0.104.1" \
    "uvicorn==0.24.0" \
    "starlette==0.27.0" \
    "anyio==3.7.1" \
    "sniffio==1.3.1" \
    "h11==0.14.0" \
    "click==8.1.7" \
    "python-multipart==0.0.9" \
    "jinja2==3.1.4" \
    "MarkupSafe==2.1.5" \
    "typing_extensions==4.12.2" \
    "idna==3.7" \
    --quiet

if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Dependency install failed.${NC}"
    deactivate; exit 1
fi

# ── Final verification ────────────────────────────────────────────
echo -e "${CYAN}  → Verifying all imports...${NC}"
"$VENV_DIR/bin/python3" - << 'PYCHECK'
import sys
failed = []
mods = ["fastapi","uvicorn","pydantic","jinja2","starlette","anyio"]
for m in mods:
    try:
        mod = __import__(m)
        ver = getattr(mod, "__version__", getattr(mod, "VERSION", "?"))
        print(f"    ✓  {m} {ver}")
    except ImportError as e:
        print(f"    ✗  {m}: {e}")
        failed.append(m)

import pydantic
major = int(pydantic.VERSION.split(".")[0])
if major != 1:
    print(f"  ERROR: pydantic v{pydantic.VERSION} installed — need v1.x")
    sys.exit(1)

if failed:
    print(f"  Missing: {failed}")
    sys.exit(1)
print("    All dependencies OK")
PYCHECK

if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Import check failed. See errors above.${NC}"
    deactivate; exit 1
fi

echo -e "${GREEN}  ✓ All dependencies verified${NC}"

# ── Optional modes ────────────────────────────────────────────────
if [[ "$1" == "--benchmark" ]]; then
    echo -e "${YELLOW}\n[BENCHMARK] Running 5-fixture CVE evaluation...${NC}"
    python3 tests/benchmark.py
    deactivate; exit 0
fi

if [[ "$1" == "--test" ]]; then
    echo -e "${YELLOW}\n[TESTS] Running 209 unit tests...${NC}"
    python3 tests/run_tests.py
    deactivate; exit 0
fi

# ── [5/5] Start server ────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Starting ScanWise AI server...${NC}"
echo ""
echo -e "${GREEN}  ✓ Running at → http://localhost:8000${NC}"
echo -e "${GREEN}  ✓ Open browser → http://localhost:8000${NC}"
echo -e "${CYAN}  Ctrl+C to stop${NC}"
echo ""

python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
