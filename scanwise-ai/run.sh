#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Startup Script
#  Compatible: Kali Linux, Ubuntu, Debian — Python 3.10 → 3.13
#
#  Usage:
#    bash run.sh              → start server
#    bash run.sh --test       → run 209 unit tests
#    bash run.sh --benchmark  → run 5-fixture CVE benchmark
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

# ── [1/5] Python ──────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking Python...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ Python 3 not found. Run: sudo apt install python3 python3-venv${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ $(python3 --version)${NC}"

# ── [2/5] nmap ────────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Checking nmap...${NC}"
if command -v nmap &>/dev/null; then
    echo -e "${GREEN}  ✓ $(nmap --version | head -1)${NC}"
else
    echo -e "${YELLOW}  ⚠  nmap not found — demo/simulation mode will be used${NC}"
    echo -e "${YELLOW}     Install for real scanning: sudo apt install nmap${NC}"
fi

# ── [3/5] Data directories ────────────────────────────────────────
echo -e "${YELLOW}[3/5] Creating data directories...${NC}"
mkdir -p data/sessions data/cve_db data/version_db data/logs reports exports
echo -e "${GREEN}  ✓ Directories ready${NC}"

# ── [4/5] Virtual environment + dependencies ──────────────────────
echo -e "${YELLOW}[4/5] Setting up Python virtual environment...${NC}"

if ! python3 -c "import venv" &>/dev/null; then
    echo -e "${RED}  ✗ python3-venv missing. Run: sudo apt install python3-venv${NC}"
    exit 1
fi

# Delete venv if it contains pydantic v2 (broken state from previous attempts)
if [ -d "$VENV_DIR" ]; then
    PYDANTIC_MAJOR=$("$VENV_DIR/bin/python3" -c \
        "import pydantic; print(pydantic.VERSION.split('.')[0])" 2>/dev/null || echo "0")
    if [ "$PYDANTIC_MAJOR" = "2" ]; then
        echo -e "${YELLOW}  ⚠  Found pydantic v2 in .venv — deleting and rebuilding...${NC}"
        rm -rf "$VENV_DIR"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${CYAN}  → Creating fresh virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
echo -e "${GREEN}  ✓ Virtual environment active${NC}"

# Upgrade pip silently
pip install --upgrade pip --quiet 2>/dev/null

# Remove any stale pydantic v2 artefacts before installing
pip uninstall pydantic pydantic-core -y --quiet 2>/dev/null || true

# ── Install pydantic v1 FIRST, alone, pinned ──────────────────────
echo -e "${CYAN}  → Installing pydantic v1 (pure Python, no Rust)...${NC}"
pip install "pydantic==1.10.21" --no-deps --quiet
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Could not install pydantic. Check internet connection.${NC}"
    deactivate; exit 1
fi

# Verify pydantic v1 is installed
PYDANTIC_VER=$("$VENV_DIR/bin/python3" -c "import pydantic; print(pydantic.VERSION)" 2>/dev/null)
PYDANTIC_MAJOR=$(echo "$PYDANTIC_VER" | cut -d. -f1)
if [ "$PYDANTIC_MAJOR" != "1" ]; then
    echo -e "${RED}  ✗ pydantic $PYDANTIC_VER installed — need v1.x. Try deleting .venv and rerunning.${NC}"
    deactivate; exit 1
fi
echo -e "${GREEN}  ✓ pydantic $PYDANTIC_VER (pure Python)${NC}"

# ── Install remaining packages ─────────────────────────────────────
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
    echo -e "${RED}  ✗ Dependency install failed. Check internet connection.${NC}"
    deactivate; exit 1
fi

# ── Verify all imports work before starting ───────────────────────
echo -e "${CYAN}  → Verifying imports...${NC}"
"$VENV_DIR/bin/python3" - << 'PYCHECK'
import sys
failed = []
checks = [
    ("fastapi",         "__version__"),
    ("uvicorn",         "__version__"),
    ("pydantic",        "VERSION"),
    ("jinja2",          "__version__"),
    ("starlette",       "__version__"),
]
for mod_name, ver_attr in checks:
    try:
        mod = __import__(mod_name)
        ver = getattr(mod, ver_attr, "?")
        print(f"    ✓  {mod_name} {ver}")
    except ImportError as e:
        print(f"    ✗  {mod_name}: {e}")
        failed.append(mod_name)

import pydantic
if int(pydantic.VERSION.split(".")[0]) != 1:
    print(f"  ERROR: pydantic {pydantic.VERSION} — need v1.x")
    sys.exit(1)
if failed:
    print(f"  Missing modules: {failed}")
    sys.exit(1)
print("    All imports OK")
PYCHECK

if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Import verification failed. See errors above.${NC}"
    deactivate; exit 1
fi
echo -e "${GREEN}  ✓ All dependencies verified${NC}"

# ── Optional modes ────────────────────────────────────────────────
if [[ "$1" == "--test" ]]; then
    echo -e "${YELLOW}\n[TESTS] Running 209 unit tests...${NC}"
    python3 tests/run_tests.py
    deactivate; exit $?
fi

if [[ "$1" == "--benchmark" ]]; then
    echo -e "${YELLOW}\n[BENCHMARK] Running 5-fixture CVE evaluation...${NC}"
    python3 tests/benchmark.py
    deactivate; exit $?
fi

# ── [5/5] Start server ────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Starting ScanWise AI server...${NC}"
echo ""
echo -e "${GREEN}  ✓ Server → http://localhost:8000${NC}"
echo -e "${GREEN}  ✓ Open your browser → http://localhost:8000${NC}"
echo -e "${CYAN}  Press Ctrl+C to stop the server${NC}"
echo ""

python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
