#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Environment Setup Script
#  Run ONCE before starting the server:  bash setup_env.sh
# ─────────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"
VPIP="$VENV/bin/pip"
VPY="$VENV/bin/python3"

echo -e "${CYAN}\n  ScanWise AI — Environment Setup${NC}\n"

# Python check
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ python3 not found. Run: apt install python3 python3-venv${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ $(python3 --version)${NC}"

# python3-venv check
if ! python3 -c "import venv" &>/dev/null; then
    echo -e "${YELLOW}  → Installing python3-venv...${NC}"
    apt-get install -y python3-venv
fi

# Remove old venv
if [ -d "$VENV" ]; then
    echo -e "${YELLOW}  → Removing old .venv ...${NC}"
    rm -rf "$VENV"
fi

# Create fresh venv
echo -e "${CYAN}  → Creating fresh .venv ...${NC}"
python3 -m venv "$VENV"
echo -e "${GREEN}  ✓ venv created${NC}"

# Upgrade pip
"$VPIP" install --upgrade pip --quiet
echo -e "${GREEN}  ✓ pip upgraded${NC}"

# Write constraint file to block pydantic v2
cat > /tmp/sw_constraints.txt << 'CONSTRAINTS'
pydantic==1.10.21
pydantic-core==0.0.0
CONSTRAINTS

# Step 1: install pydantic v1 alone
echo -e "${CYAN}  → Installing pydantic==1.10.21 ...${NC}"
"$VPIP" install "pydantic==1.10.21" --no-deps --no-cache-dir --quiet
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ pydantic install failed. Check internet connection.${NC}"; exit 1
fi

# Step 2: install all other packages (constraint keeps pydantic pinned)
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
    --no-cache-dir \
    --quiet
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Package install failed. Check internet connection.${NC}"; exit 1
fi

# Step 3: force reinstall pydantic v1 in case anything overwrote it
"$VPIP" install "pydantic==1.10.21" --no-deps --force-reinstall --no-cache-dir --quiet
echo -e "${GREEN}  ✓ All packages installed${NC}"

# Verify pydantic is v1
PVER=$("$VPY" -c "import pydantic; print(pydantic.VERSION)" 2>/dev/null)
PMAJ=$(echo "$PVER" | cut -d. -f1)
if [ "$PMAJ" != "1" ]; then
    echo -e "${RED}  ✗ pydantic $PVER installed — need v1.x${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ pydantic $PVER confirmed${NC}"

# Verify all imports
echo -e "${CYAN}  → Verifying imports...${NC}"
"$VPY" - << 'PYCHECK'
import sys
mods = {
    "fastapi":           "__version__",
    "uvicorn":           "__version__",
    "pydantic":          "VERSION",
    "jinja2":            "__version__",
    "starlette":         "__version__",
    "anyio":             "__version__",
}
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

# Create data directories
mkdir -p "$PROJECT_DIR/data/sessions" \
         "$PROJECT_DIR/data/cve_db" \
         "$PROJECT_DIR/data/logs" \
         "$PROJECT_DIR/reports" \
         "$PROJECT_DIR/exports"

echo ""
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓ Setup complete! Now run:  bash run.sh${NC}"
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

