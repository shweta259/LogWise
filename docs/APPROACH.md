# Engineering Approach

## Problem Framing

The challenge is not *parsing logs* — that's solved. The challenge is:

1. **Silent OS-layer failures.** macOS Sandbox, AMFI, Jetsam, and mDNSResponder all fail silently from the app's perspective. The app logs `NSURLErrorDomain -1009`. The real cause — `kernel: sandbox deny network-outbound` — is in a completely different log format in a completely different file.

2. **Cascade failures.** One root cause creates 5+ distinct symptoms. Without understanding the causal chain, engineers chase symptoms indefinitely.

3. **No customer access.** You cannot ask follow-up questions. The logs are the only witness.

The core design principle: **extract maximum signal from what you have, without asking for anything more.**

---

## Why Four Stages?

Each stage removes a different category of noise:

### Stage 1 — Parse: Remove Format Noise
Three log files, three completely different formats. Without normalization, you cannot even put events on the same timeline. The parser converts every line — regardless of source — into a single `LogEntry(timestamp, level, source, message, pid, thread, log_file)` dataclass. Everything is then sorted by timestamp.

**Key insight:** The macOS Unified System Log (from `kernel`, `configd`, `amfid`) almost always contains the smoking gun. App logs almost never do. You *must* read both.

### Stage 2 — Cluster: Remove Frequency Noise
Without clustering, 50 identical `SQLITE_BUSY` errors look like 50 separate problems. The engineer's eye naturally de-duplicates; the computer doesn't.

The fingerprinter strips variable parts from each message:
- Hex addresses → `ADDR`
- Numbers / PIDs → `NUM`
- File paths → `PATH`
- UUIDs → `UUID`
- Quoted strings → `STR`
- Email addresses → `EMAIL`

What remains is the structural skeleton. Same skeleton = same cluster. `SQLITE_BUSY: lock held by PID 4219` and `SQLITE_BUSY: lock held by PID 9912` become one cluster with `count=2`, not two separate issues.

This is similar to how tools like Sentry fingerprint errors — but implemented from scratch with macOS-specific variable patterns.

### Stage 3 — Match: Apply Expert Knowledge
After clustering, you know *what* errors exist and *how often*. You still don't know *what they mean*.

The signature library encodes the knowledge of a macOS platform expert as 8 compiled regex patterns. Each signature carries:
- A human-readable name and description
- Severity (CRITICAL / HIGH / MEDIUM / LOW)
- Category (Security, Auth, Network, Data Layer, Performance, Code Signing)
- 4–5 specific, actionable remediation steps

Signatures run against the **full log corpus** (not line-by-line), which allows cross-line pattern detection. For example, the `auth_cascade` signature requires evidence of both an auth failure and a sync abort in the same log session.

**Why regex, not ML?**
- Zero training data required
- Fully explainable — you can read the pattern and understand exactly what it matches
- Works offline, air-gapped, and on restricted enterprise networks
- Zero false positives when patterns are written carefully (tested explicitly)
- Adding a new signature takes 10 minutes, not a model retraining cycle

### Stage 4 — Reason: Synthesize Causal Chains
The first three stages produce structured facts. A list of facts is not a diagnosis.

What engineers actually need is: *"Here is what caused what, here is the chain of events, here is what to do first."*

This is where Claude comes in. The prompt sends:
- Matched signature names, categories, and descriptions
- Top error clusters with frequency
- Crash report details (exception type, stack frames, app-specific notes)
- Raw error log snippets for grounding

Claude is asked to return structured JSON with:
- `root_cause_hypotheses` — ranked by likelihood, with confidence, evidence list, and causal chain narrative
- `immediate_actions` — with owner (Engineering/IT/DevOps) and time estimate
- `systemic_fixes` — longer-term architectural improvements
- `data_gaps` — what would increase confidence if available

**Why use AI here and not earlier?**
- LLMs are unreliable at regex-level pattern matching (hallucinate matches, miss edge cases)
- LLMs are excellent at reasoning over structured context and writing for humans
- The rule-based stages give Claude reliable structured input to reason over — without them, the AI would be guessing

**Why a fallback?**
Enterprise environments often restrict outbound network connections. The tool must work everywhere. The `_fallback_analysis()` function synthesizes the same structured output from the rule-based findings alone, without any API call.

---

## Data Flow

```
Input Files
    │
    ▼
parse_all({filename: content})
    │  Detects format by filename/content
    │  Returns: {entries: [LogEntry...], crashes: [CrashReport...]}
    │
    ▼
analyze(parsed)
    │  Counts by level
    │  Fingerprints error/warn entries → clusters
    │  Runs MACOS_SIGNATURES against full log text
    │  Builds timeline (error/warn events sorted)
    │  Returns: AnalysisResult dataclass
    │
    ▼
run_ai_analysis(analysis_dict, crashes, snippets)
    │  Builds structured prompt
    │  Calls Claude API
    │  Falls back to _fallback_analysis() on any error
    │  Returns: dict (root_cause_hypotheses, immediate_actions, ...)
    │
    ▼
/api/analyze JSON response
    │  {analysis, crashes, ai, file_count, file_names}
    │
    ▼
Dashboard renders
```

---

## Output Schema

The `/api/analyze` endpoint returns:

```json
{
  "analysis": {
    "total_entries": 55,
    "error_count": 23,
    "critical_count": 4,
    "crash_count": 1,
    "unique_error_clusters": 28,
    "time_range": {"start": "...", "end": "..."},
    "matched_signatures": [ { "id", "name", "severity", "category", "description", "remediation" } ],
    "error_clusters": [ { "fingerprint", "representative_message", "count", "severity" } ],
    "timeline": [ { "timestamp", "level", "source", "message" } ],
    "top_error_sources": [ { "source", "count" } ]
  },
  "crashes": [ { "process", "exception_type", "stack_frames", ... } ],
  "ai": {
    "executive_summary": "...",
    "root_cause_hypotheses": [ { "rank", "title", "confidence", "evidence", "causal_chain" } ],
    "immediate_actions": [ { "action", "owner", "effort", "rationale" } ],
    "systemic_fixes": [ { "fix", "prevents", "complexity" } ],
    "data_gaps": [ "..." ],
    "severity_assessment": { "overall", "blast_radius", "time_sensitivity" }
  }
}
```

---

## Adding a New Signature

In `src/analyzer.py`, append to `MACOS_SIGNATURES`:

```python
{
    "id": "unique_snake_case_id",
    "name": "Human Readable Name",
    "pattern": re.compile(r"your|regex|pattern|here", re.I),
    "category": "Security|Auth|Network|Data Layer|Performance|Code Signing",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "description": "What this means, why it happens, what system component is involved.",
    "remediation": [
        "Step 1: Most impactful immediate action",
        "Step 2: Follow-up verification",
        "Step 3: Longer-term fix",
        "Step 4: How to verify the fix worked",
    ],
}
```

Then add a test in `tests/test_logwise.py`:

```python
@pytest.mark.parametrize("sig_id,log_text", [
    ("unique_snake_case_id", "text that should match your pattern"),
])
def test_your_signature_matches(self, sig_id, log_text):
    sig = next(s for s in MACOS_SIGNATURES if s["id"] == sig_id)
    assert sig["pattern"].search(log_text)
```

---

## Adding a New Log Format

In `src/log_parser.py`:

1. Write a new regex:
```python
MY_FORMAT_RE = re.compile(r"(?P<ts>...)(?P<level>...)(?P<message>...)")
```

2. Write a parser function:
```python
def parse_my_format(content: str, filename: str = "") -> List[LogEntry]:
    entries = []
    for i, line in enumerate(content.splitlines(), 1):
        m = MY_FORMAT_RE.match(line.strip())
        if m:
            entries.append(LogEntry(
                timestamp=m.group("ts"),
                level=_normalize_level(m.group("level")),
                source=m.group("source"),
                message=m.group("message"),
                raw=line, log_file=filename, line_number=i,
            ))
    return entries
```

3. Add detection in `parse_all()`:
```python
elif "my_format_indicator" in fname_lower:
    all_entries.extend(parse_my_format(content, filename))
```

---

## Correctness Properties

**Idempotency:** The same input files always produce the same output. No random seeds, no time-dependent logic, no side effects. Verified in `TestIntegration::test_output_structure_constant_across_runs`.

**Zero false positives on clean logs:** All 8 signatures are tested against a "healthy app" log string that contains no failures. None fire. Verified in `TestSignatureMatching::test_no_false_positives_on_clean_log`.

**Graceful degradation:** Empty dict, empty log files, garbage lines, truncated crash reports — none raise unhandled exceptions. Verified in `TestEdgeCases`.

**JSON serializability:** All output is verified to be JSON-serializable. No sets, no dataclasses, no custom types in the API response. Verified across multiple test classes.

---

## What This Is Not

- Not a real-time monitoring system (v2 roadmap)
- Not a SIEM replacement
- Not a general-purpose log analysis tool — it is specifically tuned for macOS enterprise app failures
- Not a substitute for human judgment before executing remediations — the AI output should be reviewed
- Not a tool for Windows, Linux, or iOS (different failure modes require different signatures)
