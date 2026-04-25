#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Environment Setup Script
#  Run this FIRST before run.sh
#  Usage (as root):  bash setup_env.sh
# ─────────────────────────────────────────────────────────────────
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"

echo -e "${CYAN}\n  ScanWise AI — Environment Setup${NC}\n"

# Python check
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ python3 not found. Run: apt install python3 python3-venv${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ $(python3 --version)${NC}"

# Ensure python3-venv
if ! python3 -c "import venv" &>/dev/null; then
    echo -e "${YELLOW}  Installing python3-venv...${NC}"
    apt-get install -y python3-venv
fi

# Nuke old venv completely
if [ -d "$VENV" ]; then
    echo -e "${YELLOW}  → Removing old .venv ...${NC}"
    rm -rf "$VENV"
fi

# Create fresh venv
echo -e "${CYAN}  → Creating fresh .venv ...${NC}"
python3 -m venv "$VENV"
echo -e "${GREEN}  ✓ venv created${NC}"

# Use venv pip directly
VPIP="$VENV/bin/pip"
VPY="$VENV/bin/python3"

# Upgrade pip
"$VPIP" install --upgrade pip --quiet
echo -e "${GREEN}  ✓ pip upgraded${NC}"

# ── KEY: Install pydantic v1 using constraint file to BLOCK v2 ────
echo -e "${CYAN}  → Installing pydantic==1.10.21 (blocking v2)...${NC}"

# Write a constraints file that hard-blocks pydantic v2
cat > /tmp/sw_constraints.txt << 'CONSTRAINTS'
pydantic==1.10.21
pydantic-core==0.0.0
CONSTRAINTS

"$VPIP" install \
    "pydantic==1.10.21" \
    --constraint /tmp/sw_constraints.txt \
    --no-deps \
    --quiet

# Verify
PVER=$("$VPY" -c "import pydantic; print(pydantic.VERSION)" 2>/dev/null)
PMAJ=$(echo "$PVER" | cut -d. -f1)
if [ "$PMAJ" != "1" ]; then
    echo -e "${RED}  ✗ Got pydantic $PVER — expected 1.x${NC}"
    echo -e "${RED}    This may be a pip cache issue. Try: pip cache purge${NC}"
    "$VPIP" cache purge 2>/dev/null || true
    "$VPIP" install "pydantic==1.10.21" --constraint /tmp/sw_constraints.txt --no-deps --quiet --no-cache-dir
    PVER=$("$VPY" -c "import pydantic; print(pydantic.VERSION)" 2>/dev/null)
    PMAJ=$(echo "$PVER" | cut -d. -f1)
    if [ "$PMAJ" != "1" ]; then
        echo -e "${RED}  ✗ Still getting pydantic $PVER. Check pip version.${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}  ✓ pydantic $PVER installed${NC}"

# ── Install all other packages ────────────────────────────────────
echo -e "${CYAN}  → Installing remaining packages...${NC}"
"$VPIP" install \
    "fastapi==0.104.1" \
    "uvicorn==0.24.0" \
    "starlette==0.27.0" \
    "anyio==3.7.1" \
    "sniffio==1.3.1" \
    "h11==0.14.0" \
    "click==8.1.8" \
    "python-multipart==0.0.9" \
    "jinja2==3.1.6" \
    "MarkupSafe==3.0.2" \
    "typing_extensions==4.12.2" \
    "idna==3.10" \
    --constraint /tmp/sw_constraints.txt \
    --quiet

echo -e "${GREEN}  ✓ All packages installed${NC}"

# ── Final check: make sure pydantic is STILL v1 ───────────────────
PVER2=$("$VPY" -c "import pydantic; print(pydantic.VERSION)")
PMAJ2=$(echo "$PVER2" | cut -d. -f1)
if [ "$PMAJ2" != "1" ]; then
    echo -e "${RED}  ✗ pydantic got overwritten to $PVER2 during install!${NC}"
    echo -e "${YELLOW}  → Reinstalling pydantic v1 explicitly...${NC}"
    "$VPIP" install "pydantic==1.10.21" --no-deps --quiet --no-cache-dir --force-reinstall
fi

# ── Verify all imports ────────────────────────────────────────────
echo -e "${CYAN}  → Verifying imports...${NC}"
"$VPY" << 'PYCHECK'
import sys
mods = {"fastapi":"__version__","uvicorn":"__version__","pydantic":"VERSION",
        "jinja2":"__version__","starlette":"__version__","anyio":"__version__"}
ok = True
for m, attr in mods.items():
    try:
        mod = __import__(m)
        ver = getattr(mod, attr, "?")
        print(f"    ✓  {m} {ver}")
    except ImportError as e:
        print(f"    ✗  {m}: {e}")
        ok = False
import pydantic
if not pydantic.VERSION.startswith("1."):
    print(f"  ✗ pydantic {pydantic.VERSION} — NEED v1.x")
    sys.exit(1)
if not ok:
    sys.exit(1)
PYCHECK

if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Import check failed${NC}"; exit 1
fi

# Data directories
mkdir -p "$PROJECT_DIR/data/sessions" "$PROJECT_DIR/data/logs" \
         "$PROJECT_DIR/reports" "$PROJECT_DIR/exports"

echo ""
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓ Setup complete! Now run: bash run.sh${NC}"
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
