# Scope, Assumptions & Known Risks

## Scope

### In Scope (v1)

| Area | Detail |
|---|---|
| Log formats | App logs (timestamp/level/component), macOS Unified System Log (`log show` output), Apple crash reports (.ips/.crash) |
| Platform | macOS 10.15 Catalina and later |
| Analysis mode | Post-hoc (analyze existing log files) |
| AI integration | Claude API (optional) with rule-based fallback |
| Failure signatures | 8 macOS-specific patterns (Sandbox, AMFI, Keychain, VPN/DNS, SQLite, Jetsam, HTTP 403, dylib) |
| Deployment | Single-device, single-incident analysis |
| Network | Works offline / air-gapped via fallback |

### Out of Scope (v1)

| Area | Reason |
|---|---|
| Real-time log streaming | Requires persistent SSH connection + `log stream` — planned for v2 |
| Cross-device fleet analysis | Requires centralized log aggregation — planned for v2 |
| Windows / Linux / iOS logs | Different subsystems, different failure modes — separate product |
| Automatic MDM remediation | Safety concern — require human approval — planned for v3 |
| SIEM integration | Splunk/Datadog/Elastic have different APIs — future integration layer |
| Logs behind authentication | Tool cannot SSH in or fetch logs; user must provide files |
| User behavioral analysis | No telemetry, no usage data processed |

---

## Assumptions Register

### ✅ Known (we are confident these are true)

**A1 — App uses structured logging**  
The app being diagnosed uses a consistent log format: `TIMESTAMP [LEVEL] [thread] [subsystem] Component - message`. This is true of any app using a standard logging library (os_log, CocoaLumberjack, SwiftyBeaver, etc.).

**A2 — macOS System Log is available**  
`log show` output can be obtained by IT or the engineer. This requires either admin access to the affected machine or a remotely captured log bundle.

**A3 — Python 3.8+ is available on the analyst's machine**  
The tool runs on the engineer's machine, not the affected endpoint. Python 3.8+ is standard on any developer machine.

---

### ⚠️ Assumed (we believe these are true but haven't verified)

**A4 — Logs are complete and un-truncated**  
We assume log rotation hasn't purged entries that predate the failure. macOS default log retention is 7 days for the unified log. If the failure is older than 7 days, the system log may be incomplete.  
*Mitigation: Check log timestamps; warn the user if the analysis window seems truncated.*

**A5 — Timestamps are synchronized**  
Timeline correlation across files depends on synchronized system clocks. MDM-managed corporate machines sync via NTP and should be accurate. Non-managed or misconfigured machines may drift.  
*Mitigation: If timestamps appear inconsistent, note it in the analysis. Cross-reference event ordering by content, not just timestamps.*

**A6 — The failure is reproducible or ongoing**  
We analyze a snapshot. A one-time transient failure (race condition, momentary network blip, cosmic-ray bit flip) may match signatures accurately but may not recur.  
*Mitigation: Note this in data gaps. Recommend verifying the fix by reproducing the issue in a test environment.*

**A7 — Log format is consistent across app versions**  
Different versions of the same app may use different log formats. The parser assumes the format described in A1. A major refactor of the logging layer could break parsing silently.  
*Mitigation: Add version detection to `parse_all()` before fleet-wide deployment.*

---

### ❌ Known Risks (these may cause incorrect results)

**R1 — AI output may be confident but wrong**  
Claude synthesizes from the structured analysis results. If the signature matching is incorrect (false positive, missed pattern), the AI will build a plausible-sounding but incorrect causal chain. Human review is required before executing any remediation.  
*Mitigation: The AI output is explicitly labeled as hypotheses with confidence levels, not facts. The rule-based analysis (signatures, clusters) is presented separately and is verifiable.*

**R2 — 8 signatures do not cover all failure modes**  
The signature library covers the most common macOS enterprise failure patterns as of macOS 14. Novel failures — new macOS APIs introduced in newer OS versions, custom MDM configurations, third-party kernel extensions, unusual hardware — will not match any signature and will fall through to raw cluster analysis only.  
*Mitigation: The tool shows unmatched clusters with raw messages. Engineers can add new signatures in minutes by following the pattern in APPROACH.md.*

**R3 — Sandbox/AMFI logs may be missing if privacy controls are enabled**  
On hardened enterprise deployments with strict MDM privacy policies, `log show` may omit kernel-level Sandbox and AMFI entries. This would cause the root cause (Sandbox denial) to be invisible in the system log.  
*Mitigation: Note in analysis if no kernel-level entries are present in the system log.*

**R4 — App log format may change without notice**  
If the app team changes their logging format (e.g., migrates from custom format to structured JSON logs), the parser regex will stop matching and return empty results without an obvious error.  
*Mitigation: The parser returns empty list (not an exception) on no matches. The dashboard shows "0 entries parsed" which makes the failure obvious. Add a parser test that verifies against a known log sample after any app version update.*

---

## Design Constraints

**Must work offline**  
Enterprise networks often block outbound connections to third-party APIs. The AI analysis is optional; the tool must provide useful output without it.

**Must not require endpoint access**  
The engineer analyzing the logs may not have SSH or MDM access to the affected machine. The tool accepts files dropped by IT or exported from MDM.

**Must not store or transmit PII**  
Log files may contain usernames, email addresses, and file names. The tool processes everything locally. The only external call is to the Anthropic API (when enabled), which receives log message text. For highly sensitive environments, use the rule-based mode only.

**Must be explainable**  
Every finding must trace back to a specific log line or pattern. The tool must not produce findings that cannot be verified by a human reading the logs.
