# ScanWise AI 🛡️

**Context-Aware, Explainable Vulnerability Intelligence System**  
M.Tech Research Project — Cybersecurity

---

## Python Dependencies

The project uses **only 5 lightweight pip packages**. Everything else (XML parsing, SQLite, JSON, subprocess) uses Python's built-in standard library.

| Package | Version | Purpose |
|---|---|---|
| `fastapi` | 0.111.0 | REST API framework |
| `uvicorn[standard]` | 0.29.0 | ASGI web server (runs FastAPI) |
| `pydantic` | 2.7.1 | Request/response data validation |
| `python-multipart` | 0.0.9 | File upload support |
| `jinja2` | 3.1.4 | Report template rendering |

---

## Quick Start — Kali Linux / Debian / Ubuntu

### Step 1 — One-time system packages

```bash
sudo apt update
sudo apt install python3 python3-venv nmap -y
```

### Step 2 — Run

```bash
cd scanwise-ai
bash run.sh
```

This automatically:
1. Creates a `.venv/` Python virtual environment inside the project folder
2. Installs all 5 pip packages **inside `.venv/`** — no system Python touched
3. Starts the server at `http://localhost:8000`

> **Why venv?** Kali Linux (and modern Debian/Ubuntu) block system-wide pip installs
> under PEP 668 to protect the OS Python. Using a venv is the correct Kali way.
> `run.sh` handles all of this automatically.

### Step 3 — Open in browser

```
http://localhost:8000
```

---

## Manual Setup (if run.sh fails for any reason)

```bash
cd scanwise-ai

# 1. Create virtual environment
python3 -m venv .venv

# 2. Activate it
source .venv/bin/activate

# 3. Install the 5 dependencies
pip install fastapi==0.111.0 "uvicorn[standard]==0.29.0" \
            pydantic==2.7.1 python-multipart==0.0.9 jinja2==3.1.4

# 4. Create data directories
mkdir -p data/sessions data/cve_db data/logs reports exports

# 5. Start the server
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Simulation Mode (no nmap / no root needed)

If nmap is not installed, the system automatically returns **realistic simulated
scan output** covering OpenSSH, Apache, MySQL, vsftpd, BIND, and SNMP — so all
CVE mapping, risk scoring, recommendation, and explanation features work in full
for demos and development.

Install nmap for real scanning:
```bash
sudo apt install nmap       # basic scans (no root needed for -sT)
sudo nmap ...               # root needed for: tcp_syn, udp_scan, os_detect
```

---

## Running Tests

```bash
source .venv/bin/activate          # activate venv first

# Run all 209 unit tests
python3 tests/run_tests.py

# Run the 5-fixture CVE benchmark
python3 tests/benchmark.py

# Or use the run.sh shortcuts (activates venv automatically)
bash run.sh --test
bash run.sh --benchmark
```

---

## Project Structure

```
scanwise-ai/
├── app/
│   ├── main.py                  ← FastAPI entry point
│   ├── api/
│   │   ├── routes.py            ← /scan /chat /history /report endpoints
│   │   └── validators.py        ← Target + scan type sanitization
│   ├── scanner/
│   │   ├── orchestrator.py      ← 8 safe scan templates (whitelist only)
│   │   └── executor.py          ← subprocess runner + simulation fallback
│   ├── parser/
│   │   └── nmap_parser.py       ← Nmap XML → structured JSON
│   ├── analysis/
│   │   ├── version_engine.py    ← latest / outdated / unsupported
│   │   ├── context_engine.py    ← exposure + service criticality
│   │   └── risk_engine.py       ← weighted score → Low/Med/High/Critical
│   ├── cve/
│   │   └── mapper.py            ← 18+ real CVEs, local DB, no exploits
│   ├── recommendation/
│   │   └── recommender.py       ← next safe scan suggestion
│   ├── explanation/
│   │   └── explainer.py         ← plain-English findings + guidance
│   ├── files/
│   │   └── session_manager.py   ← SQLite index + per-session folders
│   └── report/
│       └── template_builder.py  ← JSON report generator
├── static/
│   └── index.html               ← Full dark-themed chatbot web UI
├── data/
│   ├── sessions/                ← Per-scan session folders (auto-created)
│   └── scanwise.db              ← SQLite history index (auto-created)
├── tests/
│   ├── run_tests.py             ← Standalone test runner (no pytest needed)
│   ├── benchmark.py             ← 5-fixture ground-truth evaluation
│   ├── test_parser.py           ← pytest-compatible parser tests
│   ├── test_cve_mapper.py       ← pytest-compatible CVE tests
│   ├── test_engines.py          ← pytest-compatible engine tests
│   └── test_recommendation.py  ← pytest-compatible rec + explain tests
├── config/
│   └── settings.yaml            ← App configuration
├── requirements.txt             ← 5 pip packages
└── run.sh                       ← Startup script (handles venv + server)
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/chat` | Chatbot — NLP scan guidance |
| `POST` | `/api/scan` | Run scan + full analysis pipeline |
| `GET`  | `/api/history` | List all past scan sessions |
| `GET`  | `/api/session/{id}` | Fetch a specific session's analysis |
| `GET`  | `/api/templates` | List available scan types |
| `POST` | `/api/report` | Generate report for a session |
| `GET`  | `/api/report/download/{id}` | Download report as JSON |

---

## Approved Scan Templates

| Name | Command (simplified) | Root? |
|---|---|---|
| `tcp_basic` | `nmap -sT -T3 --open` | No |
| `tcp_syn` | `nmap -sS -T3 --open` | Yes |
| `udp_scan` | `nmap -sU --top-ports 100` | Yes |
| `service_detect` | `nmap -sT -sV` | No |
| `version_deep` | `nmap -sV --version-intensity 9` | No |
| `os_detect` | `nmap -O` | Yes |
| `port_range` | `nmap -p 1-1024` | No |
| `enum_scripts` | `nmap -sC -sV` | No |

All commands use `shell=False` — no shell injection possible.

---

## CVEs in Local Database

| Service | CVEs |
|---|---|
| OpenSSH | CVE-2023-38408, CVE-2023-28531, CVE-2018-15473, CVE-2016-6515, CVE-2016-0777 |
| Apache httpd | CVE-2021-41773, CVE-2021-42013, CVE-2017-7679, CVE-2022-31813 |
| vsftpd | CVE-2011-2523 (backdoor), CVE-2021-3618 |
| MySQL | CVE-2016-6662, CVE-2012-2122, CVE-2023-21980 |
| ISC BIND | CVE-2021-25220, CVE-2022-2795 |
| net-snmp | CVE-2022-44792, CVE-2020-15861 |

---

## Safety Design

- `shell=False` everywhere — no shell injection possible
- Whitelist-only command templates — no arbitrary execution
- Input validation on all targets (regex: IPv4 / CIDR / hostname)
- CVE descriptions only — no exploit steps, no PoC links
- Explanation layer is purely defensive guidance

---

## Test Results

```
Unit tests  : 209 / 209 passed  (100%) ✦
Benchmark   :   5 /   5 passed  (100%) ✦
```

---

## Research Title

**ScanWise AI: A Context-Aware, Explainable Vulnerability Intelligence System
for Safe and Automated Network Security Assessment**

M.Tech Cybersecurity Project — v1.0
