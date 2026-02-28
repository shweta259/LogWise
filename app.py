"""
app.py - LogWise backend server
Provides REST API for log upload, analysis, and AI-powered diagnosis.
"""

import asyncio
import json
import os
import sys
import traceback
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from log_parser import parse_all
from analyzer import analyze
from ai_engine import run_ai_analysis, _fallback_analysis

app = Flask(__name__, static_folder="static")

@app.after_request
def add_cors(r):
    r.headers["Access-Control-Allow-Origin"] = "*"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return r

SAMPLE_LOGS_DIR = Path(__file__).parent / "sample_logs"


def load_sample_logs() -> dict[str, str]:
    """Load all sample log files from the sample_logs directory."""
    files = {}
    for p in SAMPLE_LOGS_DIR.iterdir():
        if p.is_file():
            files[p.name] = p.read_text(errors="replace")
    return files


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Analyze uploaded log files.
    Accepts multipart/form-data with one or more log files,
    or falls back to sample logs if no files are uploaded.
    """
    try:
        log_files = {}

        # Handle file uploads
        if request.files:
            for key, file in request.files.items():
                filename = file.filename or key
                content = file.read().decode("utf-8", errors="replace")
                log_files[filename] = content

        # Fall back to sample logs for demo
        if not log_files:
            log_files = load_sample_logs()

        # Parse
        parsed = parse_all(log_files)

        # Analyze
        analysis = analyze(parsed)
        analysis_dict = analysis.to_dict()

        # Raw log snippets for AI context (errors only, truncated)
        snippets = []
        for e in parsed["entries"]:
            if e["level"] in ("ERROR", "CRITICAL", "FAULT"):
                snippets.append(f"[{e['timestamp']}] [{e['level']}] {e['source']}: {e['message']}")

        # AI analysis (run synchronously via asyncio)
        use_ai = bool(os.environ.get("ANTHROPIC_API_KEY"))
        if use_ai:
            try:
                ai_result = asyncio.run(
                    run_ai_analysis(analysis_dict, parsed["crashes"], snippets)
                )
            except Exception as e:
                ai_result = _fallback_analysis(analysis_dict, parsed["crashes"], str(e))
        else:
            ai_result = _fallback_analysis(analysis_dict, parsed["crashes"], "ANTHROPIC_API_KEY not set — using rule-based analysis")

        return jsonify({
            "success": True,
            "analysis": analysis_dict,
            "crashes": parsed["crashes"],
            "ai": ai_result,
            "file_count": len(log_files),
            "file_names": list(log_files.keys()),
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/sample-info")
def sample_info():
    """Return info about available sample log files."""
    files = []
    for p in SAMPLE_LOGS_DIR.iterdir():
        if p.is_file():
            files.append({
                "name": p.name,
                "size_bytes": p.stat().st_size,
                "lines": len(p.read_text(errors="replace").splitlines()),
            })
    return jsonify({"files": files})


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "ai_enabled": bool(os.environ.get("ANTHROPIC_API_KEY"))})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"🔍 LogWise running at http://localhost:{port}")
    print(f"   AI analysis: {'✓ enabled' if os.environ.get('ANTHROPIC_API_KEY') else '✗ disabled (set ANTHROPIC_API_KEY)'}")
    app.run(debug=True, port=port, host="0.0.0.0")
