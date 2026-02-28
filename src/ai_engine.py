"""
ai_engine.py - Claude-powered root cause analysis
Constructs a rich but token-efficient prompt from structured analysis results,
then synthesizes an executive diagnosis with confidence-ranked hypotheses.
"""

import json
import os
import re
from typing import Optional, List


def _build_prompt(analysis: dict, crashes: list, raw_snippets: List[str]) -> str:
    """Build a context-rich prompt for Claude from structured analysis data."""

    sigs = analysis.get("matched_signatures", [])
    clusters = analysis.get("error_clusters", [])[:8]  # top 8 clusters

    sig_block = ""
    if sigs:
        sig_block = "DETECTED FAILURE SIGNATURES:\n"
        for s in sigs:
            sig_block += f"  [{s['severity']}] {s['name']} ({s['category']})\n"
            sig_block += f"    → {s['description'][:200]}\n"

    cluster_block = "TOP ERROR CLUSTERS:\n"
    for c in clusters:
        cluster_block += f"  ({c['count']}x) [{c['severity']}] {c['representative_message'][:120]}\n"

    crash_block = ""
    if crashes:
        cr = crashes[0]
        crash_block = f"""CRASH REPORT:
  Process: {cr.get('process')} v{cr.get('version')} on {cr.get('os_version')}
  Exception: {cr.get('exception_type')} — {cr.get('exception_subtype')}
  Crashed in: {cr.get('crashed_thread')}
  App note: {cr.get('app_specific_info', '')[:300]}
  Stack (top 4):
"""
        for f in cr.get("stack_frames", [])[:4]:
            crash_block += f"    {f['library']} {f['symbol']}\n"

    snippet_block = "RAW LOG SNIPPETS (condensed):\n" + "\n".join(raw_snippets[:15])

    stats = (
        f"Stats: {analysis['total_entries']} entries, "
        f"{analysis['error_count']} errors, "
        f"{analysis['critical_count']} critical, "
        f"{analysis['crash_count']} crashes, "
        f"time range: {analysis.get('time_range',{}).get('start','')} → "
        f"{analysis.get('time_range',{}).get('end','')}"
    )

    prompt = f"""You are a senior macOS platform engineer and reliability expert. A business-critical enterprise macOS app is experiencing failures. You have been given structured log analysis output below. The customer is NOT available for clarification — you must reason purely from the evidence.

{stats}

{sig_block}
{cluster_block}
{crash_block}
{snippet_block}

Produce a structured root cause analysis in the following JSON format (respond ONLY with valid JSON, no markdown):

{{
  "executive_summary": "2-3 sentence plain-English summary for a non-technical stakeholder",
  "root_cause_hypotheses": [
    {{
      "rank": 1,
      "title": "Short hypothesis title",
      "confidence": "HIGH|MEDIUM|LOW",
      "evidence": ["list of specific log lines or patterns that support this"],
      "explanation": "Technical explanation (3-5 sentences)",
      "causal_chain": "A → B → C narrative showing how one failure led to another"
    }}
  ],
  "immediate_actions": [
    {{
      "action": "What to do right now",
      "owner": "Engineering|IT/MDM|DevOps|End User",
      "effort": "minutes|hours|days",
      "rationale": "Why this is the most important immediate step"
    }}
  ],
  "systemic_fixes": [
    {{
      "fix": "Longer-term architectural or process fix",
      "prevents": "What class of failure this eliminates",
      "complexity": "LOW|MEDIUM|HIGH"
    }}
  ],
  "data_gaps": ["Things you would want to confirm or collect from the user/device to increase confidence"],
  "severity_assessment": {{
    "overall": "CRITICAL|HIGH|MEDIUM|LOW",
    "blast_radius": "How many users / workflows are affected",
    "time_sensitivity": "Why this should or should not be addressed urgently"
  }}
}}"""

    return prompt


async def run_ai_analysis(analysis: dict, crashes: list, raw_log_lines: List[str]) -> dict:
    """
    Call Claude API for root cause analysis.
    Returns parsed JSON result or an error dict.
    """
    import httpx

    prompt = _build_prompt(analysis, crashes, raw_log_lines)

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": os.environ.get("ANTHROPIC_API_KEY", ""),
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-opus-4-6",
                    "max_tokens": 2048,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            raw_text = data["content"][0]["text"].strip()

            # Strip any accidental markdown fences
            raw_text = re.sub(r"^```json\s*", "", raw_text)
            raw_text = re.sub(r"\s*```$", "", raw_text)

            return json.loads(raw_text)

    except Exception as e:
        # Return a graceful fallback built from rule-based analysis
        return _fallback_analysis(analysis, crashes, str(e))


def _fallback_analysis(analysis: dict, crashes: list, error_msg: str = "") -> dict:
    """
    Rule-based fallback analysis when Claude API is unavailable.
    Still produces a useful structured output.
    """
    sigs = analysis.get("matched_signatures", [])
    crashes_count = analysis.get("crash_count", 0)

    # Build hypotheses from matched signatures
    hypotheses = []
    for i, sig in enumerate(sigs[:3], 1):
        hyp = {
            "rank": i,
            "title": sig["name"],
            "confidence": "HIGH" if sig["severity"] in ("HIGH", "CRITICAL") else "MEDIUM",
            "evidence": [f"Signature matched: {sig['id']}"],
            "explanation": sig["description"],
            "causal_chain": "Pattern matched in logs → " + sig["name"],
        }
        hypotheses.append(hyp)

    if not hypotheses:
        hypotheses.append({
            "rank": 1,
            "title": "Unclassified errors require manual review",
            "confidence": "LOW",
            "evidence": [f"{analysis.get('error_count',0)} errors found"],
            "explanation": "No matching signature patterns were found. Manual log review required.",
            "causal_chain": "Unknown",
        })

    immediate = []
    for sig in sigs[:2]:
        if sig.get("remediation"):
            immediate.append({
                "action": sig["remediation"][0],
                "owner": "Engineering",
                "effort": "hours",
                "rationale": sig["description"][:120],
            })

    return {
        "executive_summary": analysis.get("summary", "Log analysis complete. See findings below."),
        "root_cause_hypotheses": hypotheses,
        "immediate_actions": immediate or [{"action": "Review error clusters and matched signatures", "owner": "Engineering", "effort": "hours", "rationale": "No immediate remediations auto-detected"}],
        "systemic_fixes": [
            {"fix": s["remediation"][-1] if s.get("remediation") else "See signature details", "prevents": s["name"], "complexity": "MEDIUM"}
            for s in sigs[:3]
        ],
        "data_gaps": [
            "Full device system profile (macOS version, hardware model)",
            "MDM configuration profile for VPN and network settings",
            "Output of `codesign --verify --deep --strict` for the app bundle",
            "Confirmation of whether issue is reproducible across all users or specific accounts",
        ],
        "severity_assessment": {
            "overall": "CRITICAL" if (crashes_count > 0 or any(s["severity"] == "CRITICAL" for s in sigs)) else "HIGH",
            "blast_radius": "All users running this app version in this network environment",
            "time_sensitivity": "App is in a degraded/crashed state — immediate investigation warranted",
        },
        "_fallback": True,
        "_fallback_reason": error_msg[:200] if error_msg else "API unavailable",
    }
