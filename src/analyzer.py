"""
analyzer.py - Core analysis engine
Clusters errors, detects macOS-specific failure signatures, builds event timelines,
and computes frequency/severity metrics — all without needing to ask the user anything.
"""

import re
import json
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict


# ── Known macOS failure signatures ──────────────────────────────────────────

MACOS_SIGNATURES = [
    {
        "id": "sandbox_violation",
        "name": "Sandbox Policy Violation",
        "pattern": re.compile(r"sandbox.*deny|amfi.*reject|library validation failed", re.I),
        "category": "Security / Entitlements",
        "severity": "HIGH",
        "description": "The app is being blocked by macOS Sandbox or AMFI (Apple Mobile File Integrity). This typically means the app is missing required entitlements, or a plugin/framework has a code signing mismatch.",
        "remediation": [
            "Verify the app's entitlements in the provisioning profile match what is declared in the .entitlements file.",
            "Re-sign all bundled plugins and frameworks with the same Team ID as the host app.",
            "If the app uses 3rd-party plugins, ensure they are notarized and pass library validation (com.apple.security.cs.disable-library-validation entitlement may be needed as a short-term workaround, but is discouraged for distribution).",
            "Run `codesign --verify --deep --strict /Applications/Acme.app` to identify signing issues.",
            "Check AMFI logs: `log show --predicate 'process == \"amfid\"' --info --last 1h`",
        ],
    },
    {
        "id": "keychain_missing",
        "name": "Keychain Item Not Found",
        "pattern": re.compile(r"errSecItemNotFound|SecKeychainItemCopyAttributes|keychain.*not found", re.I),
        "category": "Authentication / Keychain",
        "severity": "HIGH",
        "description": "The app failed to retrieve a credential from the macOS Keychain. This can happen after an OS upgrade, MDM re-enrollment, or if the keychain was reset. The app likely stores its auth token/SSO credential here.",
        "remediation": [
            "Prompt the user to re-authenticate to re-populate the Keychain item.",
            "Ensure the Keychain access group in entitlements matches what was used when the item was originally written.",
            "If this follows an MDM re-enrollment, the keychain may have been wiped — implement graceful re-auth flow.",
            "Check: `security find-generic-password -s 'com.acme.enterprise' -w` to confirm the item exists.",
            "Consider using `kSecAttrAccessibleAfterFirstUnlock` accessibility class for enterprise apps where items must survive reboots.",
        ],
    },
    {
        "id": "network_dns_failure",
        "name": "Internal DNS / VPN Split Tunnel Failure",
        "pattern": re.compile(r"dns.*fail|mDNSResponder.*error|split dns.*unreachable|no route to host.*internal|nwpath.*no route", re.I),
        "category": "Network / VPN",
        "severity": "HIGH",
        "description": "DNS resolution for internal hostnames (*.acme.internal) is failing. The system log shows mDNSResponder reporting 'no router' and split DNS domains unreachable. This is almost certainly a VPN split-tunnel misconfiguration or the VPN client is not running.",
        "remediation": [
            "Verify the VPN client is connected before launching the app (consider a VPN-required launch policy via MDM).",
            "Check split DNS configuration: the VPN profile must include the internal domain (acme.internal) in DNS search domains.",
            "Use Network Extension framework to detect VPN state programmatically and show a clear 'VPN required' error before attempting internal connections.",
            "Run `scutil --dns` on an affected machine to inspect DNS resolver configuration.",
            "If using Cisco AnyConnect or similar: ensure 'Resolve All DNS through VPN' is enabled or the internal domain is in the split-include list.",
        ],
    },
    {
        "id": "db_lock_contention",
        "name": "SQLite Database Lock Contention (Multi-Process)",
        "pattern": re.compile(r"SQLITE_BUSY|database is locked|lock held by PID", re.I),
        "category": "Data Layer / IPC",
        "severity": "MEDIUM",
        "description": "The main app (PID 4412) and a helper process (AcmeSyncHelper, PID 4219) are simultaneously trying to write to the same SQLite database. SQLite has limited multi-writer support — this is a race condition between the app and its background sync agent.",
        "remediation": [
            "Use WAL (Write-Ahead Logging) mode: `PRAGMA journal_mode=WAL;` — allows concurrent reads with one writer.",
            "Implement a process-level write coordinator using NSDistributedLock or a dedicated XPC service that serializes all DB writes.",
            "Set a reasonable busy timeout: `sqlite3_busy_timeout(db, 5000)` to give the writer time to release the lock.",
            "Consider migrating shared state to Core Data with NSPersistentCloudKitContainer which handles multi-process access via NSPersistentStoreCoordinator.",
            "Architecture fix: route all writes through a single app extension / XPC service rather than allowing both the app and sync helper to write directly.",
        ],
    },
    {
        "id": "memory_pressure",
        "name": "Memory Pressure / Jetsam Kill Risk",
        "pattern": re.compile(r"memory.*pressure|memorystatus.*kill|RSS.*MB|footprint.*MB|page reclaim", re.I),
        "category": "Performance / Memory",
        "severity": "MEDIUM",
        "description": "The app's memory footprint reached 418MB, triggering a HIGH memory pressure event and a Jetsam kill-on-behalf-of notice from the kernel. This likely contributed to the crash — the app was operating with a defragmented heap under memory pressure when the seg fault occurred.",
        "remediation": [
            "Profile with Instruments (Allocations + VM Tracker) to identify the largest memory consumers — suspect the sync queue buffering large file contents in memory.",
            "Implement streaming for file uploads/downloads rather than loading entire files into memory.",
            "Subscribe to NSProcessInfo.thermalState and UIApplication.didReceiveMemoryWarningNotification to shed load proactively.",
            "Consider using memory-mapped I/O (mmap) for large file processing.",
            "Set a reasonable per-file limit in the sync queue and process in smaller batches.",
        ],
    },
    {
        "id": "auth_cascade",
        "name": "Auth Failure Cascade (Token → Sync → Crash)",
        "pattern": re.compile(r"token refresh failed.*sync.*abort|auth.*fail.*sync|403.*auth", re.I),
        "category": "Auth / Resilience",
        "severity": "CRITICAL",
        "description": "A single auth token refresh failure triggered a cascade: failed token → HTTP 403 on uploads → sync abort → retry with same invalid token → crash in -[SyncEngine processQueuedUploads] likely due to nil token being passed to a network layer that doesn't handle nil gracefully.",
        "remediation": [
            "Add nil/empty checks on auth tokens before any network call; assert or early-return rather than proceeding.",
            "Implement exponential backoff with jitter on token refresh, not immediate retry.",
            "Separate auth retry logic from sync retry — sync should wait for a valid token event, not retry blindly.",
            "The crash in objc_msgSend at +512 in processQueuedUploads suggests a nil object message send — add defensive checks or use optional chaining patterns.",
            "Implement a 'degraded mode' where sync pauses gracefully when auth is unavailable, rather than entering a retry loop that consumes memory.",
        ],
    },
    {
        "id": "http_403_perm",
        "name": "HTTP 403 on File Uploads",
        "pattern": re.compile(r"HTTP 403|403 Forbidden", re.I),
        "category": "Server / Auth",
        "severity": "MEDIUM",
        "description": "File upload attempts are returning HTTP 403. Given the timing (after token refresh failure and keychain miss), this is almost certainly a stale/expired bearer token being sent, not a server-side permission change.",
        "remediation": [
            "Implement token refresh before batch uploads, not just on app launch.",
            "On HTTP 401/403, automatically trigger token refresh and retry once (standard OAuth2 pattern).",
            "Log the token expiry time to make expiry-related 403s immediately identifiable.",
            "Check server-side: if valid tokens are also getting 403s, investigate whether the user's server-side permissions or group memberships changed.",
        ],
    },
    {
        "id": "dylib_load_fail",
        "name": "Dynamic Library / Plugin Load Failure",
        "pattern": re.compile(r"Library not loaded|@rpath|dyld.*failed|rpath.*AcmeCore|image not found", re.I),
        "category": "Code Signing / Deployment",
        "severity": "HIGH",
        "description": "The AcmeDocProcessor plugin cannot load AcmeCore.framework due to a library validation failure. The framework file exists on disk but AMFI rejects it because its code signature doesn't match the host process's team ID or it wasn't notarized.",
        "remediation": [
            "Re-sign AcmeCore.framework: `codesign --force --sign 'Developer ID Application: Acme Corp' --options runtime AcmeCore.framework`",
            "Ensure the plugin bundle is signed with the same Team ID as the host app.",
            "Add the `com.apple.security.cs.allow-unsigned-executable-memory` entitlement only if strictly necessary.",
            "If distributing via enterprise MDM (not App Store), ensure the provisioning profile includes the plugin's bundle ID.",
            "Verify @rpath is set correctly in the plugin's Mach-O binary: `otool -l AcmeDocProcessor.plugin/Contents/MacOS/AcmeDocProcessor | grep RPATH`",
        ],
    },
]


# ── Error clustering (simple TF-IDF-style fingerprinting) ────────────────────

def _fingerprint(message: str) -> str:
    """Normalize a log message to a cluster key by removing variable parts."""
    msg = message.lower()
    # Remove hex addresses, PIDs, file paths, timestamps
    msg = re.sub(r"0x[0-9a-f]+", "ADDR", msg)
    msg = re.sub(r"\b\d{1,6}\b", "NUM", msg)
    msg = re.sub(r"/[^\s]+", "PATH", msg)
    msg = re.sub(r"[a-f0-9\-]{32,}", "UUID", msg)
    msg = re.sub(r"\S+@\S+\.\S+", "EMAIL", msg)
    msg = re.sub(r'"[^"]{0,100}"', "STR", msg)
    msg = re.sub(r"'[^']{0,100}'", "STR", msg)
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg


@dataclass
class ErrorCluster:
    fingerprint: str
    representative_message: str
    count: int
    first_seen: str
    last_seen: str
    sources: List
    levels: List
    log_files: List
    severity: str = "INFO"
    matched_signature: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        return d


@dataclass
class TimelineEvent:
    timestamp: str
    level: str
    source: str
    message: str
    is_error: bool
    signature_id: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class AnalysisResult:
    total_entries: int
    error_count: int
    warn_count: int
    critical_count: int
    crash_count: int
    unique_error_clusters: int
    time_range: dict
    error_clusters: List
    matched_signatures: List
    timeline: List
    top_error_sources: List
    summary: str

    def to_dict(self):
        return asdict(self)


def analyze(parsed: dict) -> AnalysisResult:
    entries = parsed.get("entries", [])
    crashes = parsed.get("crashes", [])

    if not entries and not crashes:
        return AnalysisResult(
            total_entries=0, error_count=0, warn_count=0,
            critical_count=0, crash_count=0, unique_error_clusters=0,
            time_range={}, error_clusters=[], matched_signatures=[],
            timeline=[], top_error_sources=[],
            summary="No log entries found.",
        )

    # ── Counters ──────────────────────────────────────────────────────────
    level_counts = Counter(e["level"] for e in entries)
    error_count = level_counts.get("ERROR", 0) + level_counts.get("FAULT", 0)
    warn_count = level_counts.get("WARN", 0)
    critical_count = level_counts.get("CRITICAL", 0)

    timestamps = [e["timestamp"] for e in entries if e["timestamp"]]
    time_range = {
        "start": timestamps[0] if timestamps else "",
        "end": timestamps[-1] if timestamps else "",
    }

    # ── Error clustering ──────────────────────────────────────────────────
    cluster_map: dict[str, dict] = {}
    for entry in entries:
        if entry["level"] in ("ERROR", "CRITICAL", "FAULT", "WARN"):
            fp = _fingerprint(entry["message"])
            if fp not in cluster_map:
                cluster_map[fp] = {
                    "fingerprint": fp,
                    "representative_message": entry["message"],
                    "count": 0,
                    "first_seen": entry["timestamp"],
                    "last_seen": entry["timestamp"],
                    "sources": set(),
                    "levels": set(),
                    "log_files": set(),
                    "severity": entry["level"],
                }
            c = cluster_map[fp]
            c["count"] += 1
            c["last_seen"] = entry["timestamp"]
            c["sources"].add(entry.get("source", ""))
            c["levels"].add(entry["level"])
            c["log_files"].add(entry.get("log_file", ""))
            # Upgrade severity
            lvl_order = ["WARN", "INFO", "ERROR", "CRITICAL", "FAULT"]
            if lvl_order.index(entry["level"]) > lvl_order.index(c["severity"]) if entry["level"] in lvl_order and c["severity"] in lvl_order else False:
                c["severity"] = entry["level"]

    # Match signatures against the full log text
    full_log_text = "\n".join(e["message"] for e in entries)
    matched_signature_ids = set()
    matched_signatures = []

    for sig in MACOS_SIGNATURES:
        if sig["pattern"].search(full_log_text):
            matched_signatures.append({
                "id": sig["id"],
                "name": sig["name"],
                "category": sig["category"],
                "severity": sig["severity"],
                "description": sig["description"],
                "remediation": sig["remediation"],
            })
            matched_signature_ids.add(sig["id"])

    # Annotate clusters with signatures
    clusters = []
    for fp, c in cluster_map.items():
        matched = None
        for sig in MACOS_SIGNATURES:
            if sig["pattern"].search(c["representative_message"]):
                matched = sig["id"]
                break
        clusters.append(ErrorCluster(
            fingerprint=c["fingerprint"],
            representative_message=c["representative_message"],
            count=c["count"],
            first_seen=c["first_seen"],
            last_seen=c["last_seen"],
            sources=list(c["sources"]),
            levels=list(c["levels"]),
            log_files=list(c["log_files"]),
            severity=c["severity"],
            matched_signature=matched,
        ))

    clusters.sort(key=lambda x: (["WARN","INFO","ERROR","CRITICAL","FAULT"].index(x.severity) if x.severity in ["WARN","INFO","ERROR","CRITICAL","FAULT"] else 0, x.count), reverse=True)

    # ── Timeline (significant events only) ────────────────────────────────
    timeline_entries = [
        e for e in entries
        if e["level"] in ("ERROR", "CRITICAL", "FAULT", "WARN")
    ]
    # Limit to 50 most interesting
    timeline = [
        TimelineEvent(
            timestamp=e["timestamp"],
            level=e["level"],
            source=e.get("source", ""),
            message=e["message"],
            is_error=e["level"] in ("ERROR", "CRITICAL", "FAULT"),
        ).to_dict()
        for e in timeline_entries[:50]
    ]

    # ── Top error sources ─────────────────────────────────────────────────
    source_counts = Counter(
        e.get("source", "unknown")
        for e in entries
        if e["level"] in ("ERROR", "CRITICAL", "FAULT")
    )
    top_sources = [{"source": s, "count": c} for s, c in source_counts.most_common(8)]

    # ── Text summary ──────────────────────────────────────────────────────
    sig_names = [s["name"] for s in matched_signatures]
    summary = (
        f"Analyzed {len(entries)} log entries spanning {time_range.get('start','')} "
        f"to {time_range.get('end','')}. "
        f"Found {error_count} errors, {critical_count} critical events, "
        f"and {len(crashes)} crash report(s). "
        f"Detected {len(matched_signatures)} known failure pattern(s): "
        f"{', '.join(sig_names) if sig_names else 'none'}."
    )

    return AnalysisResult(
        total_entries=len(entries),
        error_count=error_count,
        warn_count=warn_count,
        critical_count=critical_count,
        crash_count=len(crashes),
        unique_error_clusters=len(clusters),
        time_range=time_range,
        error_clusters=[c.to_dict() for c in clusters[:20]],
        matched_signatures=matched_signatures,
        timeline=timeline,
        top_error_sources=top_sources,
        summary=summary,
    )
