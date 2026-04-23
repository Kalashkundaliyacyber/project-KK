# ScanWise AI 🛡️

**Context-Aware, Explainable Vulnerability Intelligence System**

An M.Tech research project that combines network scanning, CVE mapping, risk prioritization, and plain-English explanation into a safe, local, chatbot-driven web application.

---

## Quick Start

```bash
# Clone or extract the project
cd scanwise-ai

# Start everything (auto-installs dependencies)
bash run.sh

# Open browser
# http://localhost:8000
```

> **No nmap?** The system automatically uses realistic simulated scan output so you can demo and test all features without installing nmap or running as root.

---

## Features

| Feature | Description |
|---|---|
| 💬 Chatbot UI | Ask questions, get guided scan suggestions |
| 🔍 8 Scan Templates | TCP, UDP, SYN, Service, Version, OS, Scripts, Range |
| 📦 Output Parser | Nmap XML → structured JSON automatically |
| 🔬 Version Engine | Detects latest / outdated / unsupported status |
| 🗂️ CVE Mapping | 18+ real CVEs mapped to services and versions |
| ⚖️ Risk Scoring | Weighted formula: CVSS + exposure + criticality |
| 💡 Recommendations | Suggests next safe scan with reasoning |
| 📝 Explanation Layer | Plain-English findings, why it matters, what to do |
| 📁 Session History | SQLite-indexed scan history, searchable |
| 📄 Report Export | Downloadable JSON report with full analysis |

---

## Project Structure

```
scanwise-ai/
├── app/
│   ├── main.py                  ← FastAPI app entry point
│   ├── api/
│   │   ├── routes.py            ← All API endpoints
│   │   └── validators.py        ← Input sanitization
│   ├── scanner/
│   │   ├── orchestrator.py      ← 8 safe scan templates
│   │   └── executor.py          ← subprocess runner + simulation
│   ├── parser/
│   │   └── nmap_parser.py       ← XML → JSON parser
│   ├── analysis/
│   │   ├── version_engine.py    ← Version status classification
│   │   ├── context_engine.py    ← Exposure + criticality
│   │   └── risk_engine.py       ← Weighted risk scoring
│   ├── cve/
│   │   └── mapper.py            ← CVE database + mapping
│   ├── recommendation/
│   │   └── recommender.py       ← Next scan suggestions
│   ├── explanation/
│   │   └── explainer.py         ← Human-readable output
│   ├── files/
│   │   └── session_manager.py   ← SQLite + folder storage
│   └── report/
│       └── template_builder.py  ← Report JSON generator
├── static/
│   └── index.html               ← Full web UI
├── data/
│   ├── sessions/                ← Per-scan session folders
│   ├── cve_db/                  ← Local CVE database
│   └── scanwise.db              ← SQLite history index
├── tests/
│   ├── test_parser.py           ← Parser unit tests
│   ├── test_cve_mapper.py       ← CVE mapper unit tests
│   ├── test_engines.py          ← Version + risk engine tests
│   ├── test_recommendation.py   ← Recommender + explainer tests
│   └── benchmark.py             ← 5-fixture evaluation suite
├── config/
│   └── settings.yaml
├── requirements.txt
└── run.sh
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/chat` | Chatbot NLP response |
| POST | `/api/scan` | Run a scan and get full analysis |
| GET | `/api/history` | List all past sessions |
| GET | `/api/session/{id}` | Fetch a specific session |
| GET | `/api/templates` | List available scan types |
| POST | `/api/report` | Generate report for a session |
| GET | `/api/report/download/{id}` | Download report JSON |

---

## Scan Types

| Template | Command Used | Requires Root |
|---|---|---|
| `tcp_basic` | `nmap -sT -T3 --open` | No |
| `tcp_syn` | `nmap -sS -T3 --open` | Yes |
| `udp_scan` | `nmap -sU --top-ports 100` | Yes |
| `service_detect` | `nmap -sT -sV` | No |
| `version_deep` | `nmap -sV --version-intensity 9` | No |
| `os_detect` | `nmap -O` | Yes |
| `port_range` | `nmap -p 1-1024` | No |
| `enum_scripts` | `nmap -sC -sV` | No |

---

## Running Tests

```bash
# All unit tests
python -m pytest tests/ -v

# Specific test file
python -m pytest tests/test_parser.py -v

# Benchmark evaluation (5 ground-truth fixtures)
python tests/benchmark.py

# Or via run.sh
bash run.sh --test
bash run.sh --benchmark
```

---

## Architecture Layers

```
User (Browser)
    ↓ HTTP
FastAPI Backend (routes.py)
    ↓ validated input
Command Orchestrator (8 safe templates only)
    ↓ subprocess (shell=False)
Linux Scanner (nmap) / Simulation
    ↓ XML stdout
Output Parser → structured JSON
    ↓
Version Detection Engine
    ↓
CVE Mapping Engine (local DB, 18+ CVEs)
    ↓
Context Engine (exposure + criticality)
    ↓
Risk Prioritization (score 0–10 → low/medium/high/critical)
    ↓
Recommendation Engine (next safe scan)
    ↓
Explanation Layer (plain English)
    ↓
File Manager (SQLite + session folders)
    ↓ JSON API response
Web UI (Chat + Risk + CVE + Findings + Recommendations)
```

---

## Safety Design

- **No shell=True** anywhere in the codebase
- **Whitelist-only** command templates — no arbitrary execution
- **Input validation** on all targets (IP/CIDR/hostname regex)
- **CVE descriptions only** — no exploit steps, no PoC links
- **Explanation layer** is purely defensive guidance

---

## CVEs Covered (Local Database)

| Service | CVEs |
|---|---|
| OpenSSH | CVE-2023-38408, CVE-2023-28531, CVE-2018-15473, CVE-2016-6515, CVE-2016-0777 |
| Apache HTTP | CVE-2021-41773, CVE-2021-42013, CVE-2017-7679, CVE-2022-31813 |
| vsftpd | CVE-2011-2523 (backdoor), CVE-2021-3618 |
| MySQL | CVE-2016-6662, CVE-2012-2122, CVE-2023-21980 |
| ISC BIND | CVE-2021-25220, CVE-2022-2795 |
| net-snmp | CVE-2022-44792, CVE-2020-15861 |

---

## Future Enhancements

1. **NVD API integration** — live CVE lookups via `api.nvd.nist.gov`
2. **PDF report generation** — via WeasyPrint or ReportLab
3. **LLM-enhanced explanations** — Ollama + Mistral 7B for narrative
4. **MITRE ATT&CK mapping** — link findings to attacker techniques
5. **Multi-host scanning** — subnet CIDR support with host correlation
6. **Delta reports** — compare scan sessions over time
7. **CVSS v4.0** — updated severity framework

---

## Research Title

**ScanWise AI: A Context-Aware, Explainable Vulnerability Intelligence System for Safe and Automated Network Security Assessment**

---

## Author

M.Tech Research Project — Cybersecurity  
ScanWise AI v1.0
