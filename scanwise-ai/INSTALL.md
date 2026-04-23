# ScanWise AI — Kali Linux Install Guide (Python 3.13 Fix)

## Root Cause

`pydantic v2` compiles a Rust extension (`pydantic-core`).
On Python 3.13, the build fails because `pyo3 v0.21.1` only supports up to Python 3.12.

**This project uses `pydantic v1.10.21` — pure Python, zero Rust, works on all Python versions.**

---

## Method 1 — Automatic (recommended)

```bash
cd scanwise-ai
bash run.sh
```

`run.sh` will:
- Create a clean `.venv/`
- Force-uninstall any pydantic v2 if found
- Install pydantic v1.10.21 first (pinned, pure Python)
- Install remaining packages
- Verify all imports before starting

---

## Method 2 — Manual step by step

```bash
cd scanwise-ai

# Step 1: Create clean venv
python3 -m venv .venv

# Step 2: Activate
source .venv/bin/activate

# Step 3: Upgrade pip
pip install --upgrade pip

# Step 4: Remove any pydantic v2 (in case pip cached it)
pip uninstall pydantic pydantic-core -y 2>/dev/null || true

# Step 5: Install pydantic v1 FIRST, pinned
pip install "pydantic==1.10.21" --no-deps

# Step 6: Verify you have v1
python3 -c "import pydantic; print('pydantic', pydantic.VERSION)"
# Must print: pydantic 1.10.21

# Step 7: Install everything else
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
  "idna==3.7"

# Step 8: Verify all imports
python3 -c "import fastapi, uvicorn, pydantic, jinja2; print('All OK')"

# Step 9: Start the server
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Then open: **http://localhost:8000**

---

## Method 3 — Nuclear option (wipe everything and start fresh)

If `.venv` is corrupted or has wrong packages:

```bash
cd scanwise-ai

# Delete the entire venv
rm -rf .venv

# Recreate from scratch
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip uninstall pydantic pydantic-core -y 2>/dev/null || true
pip install "pydantic==1.10.21" --no-deps
pip install "fastapi==0.104.1" "uvicorn==0.24.0" "starlette==0.27.0" \
            "anyio==3.7.1" "sniffio==1.3.1" "h11==0.14.0" "click==8.1.7" \
            "python-multipart==0.0.9" "jinja2==3.1.4" "MarkupSafe==2.1.5" \
            "typing_extensions==4.12.2" "idna==3.7"
python3 -c "import fastapi, uvicorn, pydantic; print('OK — pydantic', pydantic.VERSION)"
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Package list (all pure Python, no Rust/C compilation)

| Package | Version | Pure Python? |
|---------|---------|-------------|
| pydantic | 1.10.21 | ✓ Yes |
| fastapi | 0.104.1 | ✓ Yes |
| uvicorn | 0.24.0 | ✓ Yes |
| starlette | 0.27.0 | ✓ Yes |
| anyio | 3.7.1 | ✓ Yes |
| sniffio | 1.3.1 | ✓ Yes |
| h11 | 0.14.0 | ✓ Yes |
| click | 8.1.7 | ✓ Yes |
| python-multipart | 0.0.9 | ✓ Yes |
| jinja2 | 3.1.4 | ✓ Yes |
| MarkupSafe | 2.1.5 | ✓ Yes |
| typing_extensions | 4.12.2 | ✓ Yes |
| idna | 3.7 | ✓ Yes |

**None of these require Rust, maturin, cargo, or any C compiler.**

---

## Troubleshooting

| Error | Fix |
|-------|-----|
| `pydantic-core` build fails | Run Method 3 (nuclear wipe) |
| `No module named uvicorn` | `source .venv/bin/activate` first |
| `python3-venv not found` | `sudo apt install python3-venv` |
| `Port 8000 in use` | `kill $(lsof -t -i:8000)` |
| nmap scans need root | `sudo bash run.sh` |

