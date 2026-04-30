#!/bin/bash
# ─────────────────────────────────────────────────────────────────
#  ScanWise AI — Environment Setup Script
#  Run ONCE before starting the server:  bash setup_env.sh
#
#  ALL pip dependencies are installed here.
#  If you add a new package to the project, add it to the
#  "Install all packages" section below and nowhere else.
# ─────────────────────────────────────────────────────────────────

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

VENV="$PROJECT_DIR/.venv"
VPIP="$VENV/bin/pip"
VPY="$VENV/bin/python3"

echo -e "${CYAN}\n  ScanWise AI — Environment Setup${NC}\n"

# ── Python check ──────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  ✗ python3 not found. Run: apt install python3 python3-venv${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ $(python3 --version)${NC}"

# ── python3-venv check ────────────────────────────────────────────
if ! python3 -c "import venv" &>/dev/null; then
    echo -e "${YELLOW}  → Installing python3-venv...${NC}"
    apt-get install -y python3-venv
fi

# ── Remove old venv (clean slate) ────────────────────────────────
if [ -d "$VENV" ]; then
    echo -e "${YELLOW}  → Removing old .venv ...${NC}"
    rm -rf "$VENV"
fi

# ── Create fresh venv ─────────────────────────────────────────────
echo -e "${CYAN}  → Creating fresh .venv ...${NC}"
python3 -m venv "$VENV"
echo -e "${GREEN}  ✓ venv created${NC}"

# ── Upgrade pip ───────────────────────────────────────────────────
"$VPIP" install --upgrade pip --quiet
echo -e "${GREEN}  ✓ pip upgraded${NC}"

# ── Constraint file: hard-block pydantic v2 ───────────────────────
# pydantic v2 requires Rust compilation and fails on Python 3.13.
# We pin v1 (pure Python) and block pydantic-core entirely.
cat > /tmp/sw_constraints.txt << 'CONSTRAINTS'
pydantic==1.10.21
pydantic-core==0.0.0
CONSTRAINTS

# ── Step 1: Install pydantic v1 FIRST, alone ─────────────────────
# Must be installed before fastapi, or fastapi's resolver pulls v2.
echo -e "${CYAN}  → Installing pydantic==1.10.21 (pure Python, no Rust)...${NC}"
"$VPIP" install "pydantic==1.10.21" \
    --no-deps \
    --no-cache-dir \
    --quiet
if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ pydantic install failed. Check internet connection.${NC}"; exit 1
fi

# ── Step 2: Install ALL project packages ─────────────────────────
# ╔══════════════════════════════════════════════════════════════╗
# ║  ADD NEW PACKAGES HERE — this is the single source of truth ║
# ║  for all pip dependencies in ScanWise AI.                   ║
# ║  Format:  "package==version" \                              ║
# ╚══════════════════════════════════════════════════════════════╝
echo -e "${CYAN}  → Installing all project packages...${NC}"
"$VPIP" install \
    \
    `# ── Web framework ──────────────────────────────────────────` \
    "fastapi==0.104.1" \
    "uvicorn==0.24.0" \
    "starlette==0.27.0" \
    \
    `# ── Rate limiting ──────────────────────────────────────────` \
    "slowapi==0.1.9" \
    \
    `# ── Async / HTTP internals ─────────────────────────────────` \
    "anyio==3.7.1" \
    "sniffio==1.3.1" \
    "h11==0.14.0" \
    "idna==3.10" \
    \
    `# ── Utilities ──────────────────────────────────────────────` \
    "click==8.1.8" \
    "python-multipart==0.0.9" \
    "typing_extensions==4.12.2" \
    \
    `# ── Templating ─────────────────────────────────────────────` \
    "jinja2==3.1.6" \
    "MarkupSafe==3.0.2" \
    \
    `# ── (Future packages go here) ───────────────────────────────` \
    \
    --constraint /tmp/sw_constraints.txt \
    --no-cache-dir \
    --quiet

if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Package install failed. Check internet connection.${NC}"; exit 1
fi

# ── Step 3: Force reinstall pydantic v1 ──────────────────────────
# Ensures fastapi's dependency resolver did not silently upgrade to v2.
"$VPIP" install "pydantic==1.10.21" \
    --no-deps \
    --force-reinstall \
    --no-cache-dir \
    --quiet
echo -e "${GREEN}  ✓ All packages installed${NC}"

# ── Verify pydantic is v1 ─────────────────────────────────────────
PVER=$("$VPY" -c "import pydantic; print(pydantic.VERSION)" 2>/dev/null)
PMAJ=$(echo "$PVER" | cut -d. -f1)
if [ "$PMAJ" != "1" ]; then
    echo -e "${RED}  ✗ pydantic $PVER installed — need v1.x${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ pydantic $PVER confirmed${NC}"

# ── Verify all imports ────────────────────────────────────────────
echo -e "${CYAN}  → Verifying all imports...${NC}"
"$VPY" - << 'PYCHECK'
import sys
# All packages that must be importable at runtime
REQUIRED = {
    "fastapi":           "__version__",
    "uvicorn":           "__version__",
    "pydantic":          "VERSION",
    "starlette":         "__version__",
    "jinja2":            "__version__",
    "anyio":             "__version__",
    "slowapi":           "__version__",
    "multipart":         "__version__",
}
ok = True
for mod_name, ver_attr in REQUIRED.items():
    try:
        mod = __import__(mod_name)
        ver = getattr(mod, ver_attr, "?")
        print(f"    ✓  {mod_name} {ver}")
    except ImportError as e:
        print(f"    ✗  {mod_name}: {e}")
        ok = False

import pydantic
if not pydantic.VERSION.startswith("1."):
    print(f"  ✗ pydantic {pydantic.VERSION} — NEED v1.x")
    sys.exit(1)

if not ok:
    sys.exit(1)

print("    All imports OK")
PYCHECK

if [ $? -ne 0 ]; then
    echo -e "${RED}  ✗ Import check failed. See errors above.${NC}"; exit 1
fi
echo -e "${GREEN}  ✓ All imports verified${NC}"

# ── Create data directories ───────────────────────────────────────
echo -e "${CYAN}  → Creating data directories...${NC}"
mkdir -p \
    "$PROJECT_DIR/data/sessions" \
    "$PROJECT_DIR/data/cve_db" \
    "$PROJECT_DIR/data/version_db" \
    "$PROJECT_DIR/data/logs" \
    "$PROJECT_DIR/reports" \
    "$PROJECT_DIR/exports"
echo -e "${GREEN}  ✓ Directories ready${NC}"

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✓ Setup complete!${NC}"
echo -e "${GREEN}  → Start server:  bash run.sh${NC}"
echo -e "${GREEN}  → Run tests:     bash run.sh --test${NC}"
echo -e "${GREEN}  → Benchmark:     bash run.sh --benchmark${NC}"
echo -e "${GREEN}  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
