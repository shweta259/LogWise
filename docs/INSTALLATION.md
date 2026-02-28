# Installation Guide

## Requirements

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.8+ | 3.9+ recommended |
| Flask | 3.0+ | Web server |
| httpx | 0.27+ | Only for live AI analysis |
| pytest | 7.0+ | Only for running tests |
| pytest-cov | 4.0+ | Only for coverage report |

---

## Option 1 — Basic (no AI, works fully offline)

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/logwise.git
cd logwise

# 2. Install the single required dependency
pip install flask

# 3. Run
python3 app.py
```

Open **http://localhost:5050** — the dashboard loads sample logs automatically.

---

## Option 2 — With AI-Powered Analysis

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/logwise.git
cd logwise

# 2. Install dependencies
pip install flask httpx

# 3. Set your Anthropic API key
export ANTHROPIC_API_KEY=sk-ant-...

# 4. Run
python3 app.py
```

You'll see:
```
🔍 LogWise running at http://localhost:5050
   AI analysis: ✓ enabled
```

Get an API key at: https://console.anthropic.com

---

## Option 3 — Virtual Environment (recommended for production)

```bash
git clone https://github.com/YOUR_USERNAME/logwise.git
cd logwise

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

ANTHROPIC_API_KEY=sk-ant-... python3 app.py
```

---

## Running the Tests

```bash
pip install pytest pytest-cov

# Run all 40 tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=src --cov-report=term-missing

# Run a specific test class
pytest tests/ -v -k "TestLogParser"
```

Expected output:
```
tests/test_logwise.py::TestLogParser::test_parse_app_log_single_error PASSED
tests/test_logwise.py::TestLogParser::test_parse_app_log_count PASSED
... (40 tests)

40 passed in 0.30s
```

---

## Analyzing Your Own Logs

### Via the web UI
1. Run the server: `python3 app.py`
2. Open http://localhost:5050
3. Drag and drop your log files onto the upload zone
4. Click **Analyze Logs**

### Via the API directly
```bash
curl -X POST http://localhost:5050/api/analyze \
  -F "app_log=@/path/to/your/app.log" \
  -F "system_log=@/path/to/system.log" \
  -F "crash=@/path/to/crash.ips"
```

### Accepted file formats
| Format | Description | How to export |
|---|---|---|
| `*.log` | App logs with timestamp/level/component | From your app's logger |
| `*.log` (syslog) | macOS unified system log | `log show --last 2h > system.log` |
| `*.ips` / `*.crash` | Apple crash reports | From ~/Library/Logs/DiagnosticReports/ |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | No | Enables Claude AI analysis. Falls back to rule-based if unset. |
| `PORT` | No | Server port (default: 5050) |

---

## Python Version Compatibility

The codebase uses `typing.List`, `typing.Dict`, and `typing.Optional` from the `typing` module for compatibility with **Python 3.8+**. No `list[...]` or `dict[...]` generics are used, so it runs on older Python without modification.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'flask'`**
```bash
pip install flask
```

**`Address already in use` on port 5050**
```bash
PORT=5051 python3 app.py
```

**No AI analysis, just rule-based**
Make sure `ANTHROPIC_API_KEY` is set:
```bash
echo $ANTHROPIC_API_KEY   # should print your key
```

**`python3: command not found`**
```bash
python app.py    # try without the 3
```
