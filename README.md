# 🔍 LogWise — Autonomous macOS Log Intelligence Platform

> **Diagnose business-critical macOS app failures from logs alone. No customer input required.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests: 40/40](https://img.shields.io/badge/tests-40%20passing-brightgreen.svg)](#testing)
[![Coverage: 88%](https://img.shields.io/badge/coverage-88%25-green.svg)](#test-coverage)

---

## The Problem

Your enterprise macOS app is broken. Users are reporting failures. You have log files — but no access to the customer's machine and no one to ask follow-up questions.

The challenge: macOS fails **silently at the OS layer**. An app log saying *"token refresh failed: -1009"* is nearly useless without knowing that `kernel` logged a sandbox network-outbound denial two seconds earlier, and `configd` logged that split DNS domains are unreachable. The root cause is invisible unless you correlate across all three log sources simultaneously.

**LogWise solves this by treating log diagnosis as a fully autonomous problem.**

---

## Demo

```bash
git clone https://github.com/YOUR_USERNAME/logwise.git
cd logwise
pip install flask
python3 app.py
# → open http://localhost:5050
```

The dashboard auto-loads the included sample logs and runs the full analysis pipeline.

---

## What It Does

```
Your log files  (3 formats)
      ↓
  [PARSER]    → Unifies app logs + macOS system log + crash reports into one timeline
      ↓
  [CLUSTERER] → Fingerprints & groups similar errors (50 SQLITE_BUSY = 1 cluster)
      ↓
  [MATCHER]   → Runs 8 macOS-specific failure signatures against the corpus
      ↓
  [AI ENGINE] → Claude synthesizes ranked root-cause hypotheses with causal chains
      ↓
  [DASHBOARD] → Visual war-room interface with blast radius, playbook, timeline
```

### Sample Incident Output

Given 3 log files from a broken enterprise Mac app, LogWise:

- Parses **55 log entries** across 3 formats into a unified timeline
- Clusters **23 errors** into **28 unique clusters**
- Matches **7 of 8** failure signatures
- Identifies **1 root cause** (VPN not running) behind 7 different symptoms
- Generates a **shell remediation playbook** an IT admin can run immediately

---

## Architecture

```
logwise/
├── src/
│   ├── log_parser.py      # Multi-format log ingestion (app, syslog, crash)
│   ├── analyzer.py        # Error clustering + 8 macOS signature patterns
│   └── ai_engine.py       # Claude API integration + rule-based fallback
├── tests/
│   └── test_logwise.py    # 40 tests across 5 test classes
├── static/
│   └── index.html         # Single-page war-room dashboard
├── sample_logs/           # Realistic sample incident logs
│   ├── app_errors.log
│   ├── system.log
│   └── Acme_2025-11-14-083015_crash.ips
├── docs/
│   ├── APPROACH.md        # Design decisions & engineering rationale
│   ├── ANALYSIS_REPORT.md # Full incident analysis of sample logs
│   └── ASSUMPTIONS.md     # Scope, assumptions, known risks
├── scripts/
│   └── run_tests.sh       # Test runner with coverage report
└── app.py                 # Flask server (REST API + static serving)
```

---

## Installation

See **[docs/INSTALLATION.md](docs/INSTALLATION.md)** for full instructions.

**Quick start:**
```bash
pip install flask httpx        # httpx only needed for live AI analysis
python3 app.py                 # opens at http://localhost:5050
```

**With AI-powered analysis:**
```bash
ANTHROPIC_API_KEY=sk-ant-... python3 app.py
```

**Run tests:**
```bash
pip install pytest pytest-cov
pytest tests/ -v
```

---

## Key Design Decisions

| Decision | Why |
|---|---|
| Rule-based signatures as primary detection | Fast, explainable, works offline/air-gapped |
| Claude for synthesis, not detection | LLMs reason well over structured context; regex is more reliable for pattern matching |
| Multi-source correlation (3 log types) | Root cause is almost always in `kernel`/`configd`, not the app's own logger |
| Error clustering before analysis | Without it, 50 identical errors obscure the true distribution |
| Graceful AI fallback | Enterprise environments restrict outbound network; tool must work everywhere |

---

## Detected Failure Signatures

| ID | Name | Severity | macOS Subsystem |
|---|---|---|---|
| `sandbox_violation` | Sandbox Policy Violation | HIGH | kernel / AMFI |
| `keychain_missing` | Keychain Item Not Found | HIGH | Security framework |
| `network_dns_failure` | VPN / Split Tunnel DNS Failure | HIGH | configd / mDNSResponder |
| `auth_cascade` | Auth Failure Cascade | CRITICAL | App + network |
| `db_lock_contention` | SQLite Multi-Process Lock | MEDIUM | SQLite |
| `memory_pressure` | Memory Pressure / Jetsam | MEDIUM | kernel / Jetsam |
| `http_403_perm` | HTTP 403 on File Uploads | MEDIUM | App + server |
| `dylib_load_fail` | AMFI Library Validation Failure | HIGH | AMFI / dyld |

---

## Testing

```
tests/test_logwise.py
├── TestLogParser         (13 tests) — parse, normalize, 3 formats, edge cases
├── TestFingerprinting    ( 8 tests) — identical messages, variable stripping
├── TestSignatureMatching (12 tests) — pattern match, structural, false-positive guard
├── TestAnalyzer          (13 tests) — counts, clustering, timeline, serialization
├── TestAIEngine          (14 tests) — fallback, prompt, severity, idempotency
└── TestIntegration       ( 6 tests) — full 3-file pipeline, idempotency, empty input

Total: 40 tests · 0 failures · avg coverage 88%
```

Run with coverage:
```bash
pytest tests/ -v --cov=src --cov-report=term-missing
```

---

## Roadmap

- **v1 (built):** Post-hoc log diagnosis — drop files, get diagnosis
- **v2:** Live streaming via SSH + `log stream`, real-time anomaly detection
- **v3:** MDM-push auto-remediation — self-healing for known failure classes

---

## License

MIT — see [LICENSE](LICENSE)
