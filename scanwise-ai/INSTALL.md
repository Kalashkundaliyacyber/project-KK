# ScanWise AI — Installation Guide

## Why the previous installs failed

**Problem 1 — pydantic-core Rust build failure on Python 3.13**
`pydantic v2` requires compiling a Rust extension (`pydantic-core`).
On Python 3.13, the bundled `pyo3 v0.21.1` only supports up to Python 3.12.

**Solution:** This project uses `pydantic==1.10.21` — pure Python, no Rust, works on all Python versions including 3.13.

**Problem 2 — Python 3.13 XML element truthiness change**
Python 3.13 deprecated using `if element:` on XML elements. An element with no child nodes now evaluates as `False`. All XML parsing code has been updated to use `if element is not None:`.

---

## Quick Start (Kali Linux)

```bash
# One-time system install
sudo apt update
sudo apt install python3 python3-venv nmap -y

# Extract and run
cd scanwise-ai
bash run.sh
```

Open browser → **http://localhost:8000**

`run.sh` handles everything automatically:
- Creates `.venv/` virtual environment
- Removes any stale pydantic v2 artefacts
- Installs pydantic v1 first (pure Python, pinned)
- Installs all remaining packages
- Verifies all imports before starting
- Starts the FastAPI server

---

## Manual Install (if run.sh fails)

```bash
cd scanwise-ai

# 1. Create clean venv
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate

# 2. Upgrade pip
pip install --upgrade pip

# 3. Remove any pydantic v2 (from previous attempts)
pip uninstall pydantic pydantic-core -y 2>/dev/null || true

# 4. Install pydantic v1 FIRST, pinned, alone
pip install "pydantic==1.10.21" --no-deps

# 5. Verify it's v1
python3 -c "import pydantic; print(pydantic.VERSION)"
# Must print: 1.10.21

# 6. Install everything else
pip install \
  "fastapi==0.104.1" "uvicorn==0.24.0" "starlette==0.27.0" \
  "anyio==3.7.1" "sniffio==1.3.1" "h11==0.14.0" "click==8.1.7" \
  "python-multipart==0.0.9" "jinja2==3.1.4" "MarkupSafe==2.1.5" \
  "typing_extensions==4.12.2" "idna==3.7"

# 7. Create data directories
mkdir -p data/sessions data/logs reports exports

# 8. Start server
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open browser → **http://localhost:8000**

---

## Packages — all pure Python, no compilation

| Package           | Version   | Pure Python |
|-------------------|-----------|-------------|
| pydantic          | 1.10.21   | ✓ Yes       |
| fastapi           | 0.104.1   | ✓ Yes       |
| uvicorn           | 0.24.0    | ✓ Yes       |
| starlette         | 0.27.0    | ✓ Yes       |
| anyio             | 3.7.1     | ✓ Yes       |
| sniffio           | 1.3.1     | ✓ Yes       |
| h11               | 0.14.0    | ✓ Yes       |
| click             | 8.1.7     | ✓ Yes       |
| python-multipart  | 0.0.9     | ✓ Yes       |
| jinja2            | 3.1.4     | ✓ Yes       |
| MarkupSafe        | 2.1.5     | ✓ Yes       |
| typing_extensions | 4.12.2    | ✓ Yes       |
| idna              | 3.7       | ✓ Yes       |

All standard library modules (xml, sqlite3, json, subprocess, re) require no install.

---

## Running Tests

```bash
source .venv/bin/activate

# 209 unit tests
python3 tests/run_tests.py

# 5-fixture CVE benchmark
python3 tests/benchmark.py

# Via run.sh shortcuts
bash run.sh --test
bash run.sh --benchmark
```

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `pydantic-core build failed` | `rm -rf .venv` then follow manual install |
| `No module named uvicorn` | `source .venv/bin/activate` first |
| `python3-venv not found` | `sudo apt install python3-venv` |
| `Port 8000 in use` | `kill $(lsof -t -i:8000)` then retry |
| Root-required scans fail | `sudo bash run.sh` for tcp_syn, udp_scan, os_detect |
| No nmap installed | Simulation mode activates automatically |
