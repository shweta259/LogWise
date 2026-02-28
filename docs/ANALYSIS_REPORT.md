# Incident Analysis Report

**App:** Acme Enterprise (v4.2.1, build 1041)  
**Platform:** macOS 14.1.1 (Sonoma)  
**Incident Date:** 2025-11-14  
**Analysis Window:** 08:00:58 → 09:00:00 (59 minutes)  
**Overall Severity:** 🔴 CRITICAL  
**Status:** Crash confirmed, app in degraded state

---

## Executive Summary

The app crashed at 08:30:15 due to a null pointer dereference inside the sync retry loop. The root cause is **VPN not connected** — which caused a cascade through internal DNS failure, Keychain access denial, auth token expiry, file upload rejections, memory pressure, and ultimately a fatal crash. Six of the seven detected failure signatures trace back to this single root cause. The seventh (SQLite lock contention) and eighth (plugin AMFI rejection) are independent concurrent issues.

**An IT admin deploying the VPN configuration and clearing the stale Keychain item would resolve the primary failure in under 30 minutes.**

---

## Timeline of Failure

```
08:00:58  kernel (Sandbox)    DENY file-read-data config.plist
          ↑ First error — before the app even logs anything
          ↑ Sandbox policy is blocking config file read

08:01:00  kernel (Sandbox)    DENY mach-lookup keychain-proxy
          security.keychain   errSecItemNotFound: item not found in Keychain
          ↑ Keychain access blocked AND the item doesn't exist anyway

08:01:02  AppDelegate          Application launched v4.2.1

08:01:03  configd              nwpath: no route to host (acme.internal)
          kernel (Sandbox)    DENY network-outbound to auth.acme.internal:443
          AuthService         Token refresh failed: NSURLErrorDomain -1009
          ↑ THREE independent confirmations of the same root cause:
            1. configd says VPN routing is absent
            2. Sandbox says the outbound call was blocked
            3. App sees "offline" error

08:01:03  AuthService          Falling back to cached credentials (age: 43200s)
          ↑ 12-hour-old stale token — will fail on server

08:01:04  SyncEngine           Upload failed: Q4_Report_FINAL.xlsx — HTTP 403
          SyncEngine           Upload failed: client_contacts.csv — HTTP 403
          SyncEngine           SYNC ABORTED after 2 consecutive auth failures
          ↑ Server correctly rejects expired token

08:15:00  AcmeSyncHelper[4219] Acquired SQLite write lock  ← helper process
          DatabaseManager      SQLITE_BUSY: lock held by PID 4219 (attempt 1/5)
          DatabaseManager      SQLITE_BUSY: lock held by PID 4219 (attempt 2/5)
          DatabaseManager      SQLITE_BUSY: lock held by PID 4219 (attempt 3/5)
          DatabaseManager      Exceeded retry limit. Operation ABORTED.
          ↑ Independent issue: two processes fighting over the database

08:30:11  kernel (Jetsam)      killing_on_behalf_of pid 4412 [Acme], footprint 418MB
          kernel (VM)          Acme[4412] page reclaim pressure level HIGH
          MemoryMonitor        Memory pressure HIGH — RSS: 412MB (threshold: 400MB)
          ↑ Sync retry queue has buffered unsent files in memory

08:30:15  💥 CRASH             EXC_BAD_ACCESS (SIGSEGV) at 0x0000000000000000
          Thread 0             objc_msgSend +28 → -[SyncEngine processQueuedUploads] +512
          ↑ nil auth token passed to network layer → null pointer dereference

08:45:03  AMFI                 Rejecting load: library validation failed
          PluginManager        AcmeDocProcessor disabled
          ↑ Independent issue: plugin code-signing mismatch

09:00:00  configd              Split DNS domains unreachable: [acme.internal, auth.acme.internal]
          HealthCheck          3 of 5 health checks FAILED. App in degraded state.
```

---

## Root Cause Analysis

### Hypothesis #1 — VPN Not Running (Confidence: HIGH)

**Evidence:**
- `configd: nwpath evaluation error: no route to host (acme.internal)` [system.log 08:01:03]
- `kernel: sandbox violation: deny network-outbound to auth.acme.internal:443` [system.log 08:01:03]
- `configd: Split DNS domains unreachable: [acme.internal, auth.acme.internal]` [system.log 09:00:00]
- `configd: DNS proxy unavailable - mDNSResponder error: kDNSServiceErr_NoRouter` [system.log 09:00:00]

**Causal chain:**
```
VPN client not running
    → Split DNS cannot resolve *.acme.internal
    → auth.acme.internal unreachable
    → Sandbox blocks outbound network call (defense-in-depth policy)
    → Token refresh fails: NSURLErrorDomain -1009
    → Stale 12-hour-old token used as fallback
    → Server rejects uploads: HTTP 403 Forbidden
    → Sync engine aborts and retries with same invalid token
    → Retry queue accumulates unsent files in memory
    → Memory pressure HIGH (418MB)
    → processQueuedUploads called with nil auth token
    → objc_msgSend to nil → EXC_BAD_ACCESS SIGSEGV → 💥 CRASH
```

**Why this is the root cause and not a symptom:** The Sandbox denial and DNS failure appear at 08:00:58 and 08:01:00 respectively — *before* the app even logs its first line at 08:01:02. The app cannot have caused these; they were pre-existing conditions when the app launched.

---

### Hypothesis #2 — Keychain Item Missing (Confidence: HIGH, contributing factor)

**Evidence:**
- `kernel: sandbox deny mach-lookup com.apple.security.keychain-proxy` [system.log 08:01:00]
- `security.keychain: errSecItemNotFound: The specified item could not be found` [system.log 08:01:00]

**Analysis:** Even if the VPN were connected, the Keychain item for `com.acme.enterprise` does not exist. This likely happened due to a recent macOS upgrade, MDM re-enrollment, or Keychain migration. The app would need to re-authenticate from scratch regardless of VPN state.

**Causal chain:** Keychain miss → no stored token → forced token refresh → token refresh fails (VPN is also down) → double failure

---

### Hypothesis #3 — AMFI Plugin Rejection (Confidence: HIGH, independent)

**Evidence:**
- `kernel: (AMFI) Acme[4412]: rejecting load of AcmeDocProcessor.plugin: library validation failed` [system.log 08:45:03]
- `PluginManager: Library not loaded: @rpath/AcmeCore.framework — code signature not valid for use in process using Library Validation` [app_errors.log 08:45:03]

**Analysis:** This is independent of the VPN/auth cascade. The plugin exists on disk but Apple Mobile File Integrity (AMFI) rejects it because its code signature was made with a different Team ID than the host app. This is a deployment/signing issue, not a network issue.

**Not related to the crash** — the plugin failure happens at 08:45:03, 15 minutes *after* the crash at 08:30:15.

---

### Hypothesis #4 — SQLite Multi-Process Lock Contention (Confidence: HIGH, independent)

**Evidence:**
- `AcmeSyncHelper[4219]: Acquired SQLite write lock` [system.log 08:15:00]
- `DatabaseManager: SQLITE_BUSY: lock held by PID 4219` [app_errors.log 08:15:00, 3 occurrences]
- `DatabaseManager: Exceeded retry limit. Operation aborted.` [app_errors.log 08:15:01]

**Analysis:** Both the main app (PID 4412) and the background sync helper (PID 4219) attempt simultaneous SQLite writes. SQLite in WAL-off mode allows only one writer at a time. This is an architecture issue — not caused by the VPN outage.

---

## Crash Analysis

**Process:** Acme [4412]  
**Exception:** `EXC_BAD_ACCESS (SIGSEGV)` — Segmentation fault  
**Address:** `0x0000000000000000` — Null pointer dereference  
**Crashed thread:** Thread 0 (main thread)

**Stack trace:**
```
#0  libobjc.A.dylib          objc_msgSend + 28
#1  Acme                     -[SyncEngine processQueuedUploads] + 512
#2  Acme                     -[SyncEngine backgroundSyncTask] + 88
#3  Foundation                __NSThreadPerformPerform + 124
```

**Root cause of crash:** `objc_msgSend` at address +28 with target address `0x0` means a message was sent to a nil Objective-C object. In `-[SyncEngine processQueuedUploads]`, the auth token (a string or object) was nil, and the code passed it to a network layer method that dereferenced it without a nil check.

**Why at this moment:** The app was under memory pressure (418MB, threshold 400MB) when the crash occurred. The sync retry loop had accumulated queued files in memory. Jetsam had already issued a soft kill notice 4 seconds earlier.

**Contributing factors:**
1. Nil auth token not checked before use in `processQueuedUploads`
2. Memory pressure degraded heap state
3. Retry loop kept attempting with invalid state instead of waiting for a valid auth token event

---

## Detected Signatures Summary

| # | Signature | Severity | Status |
|---|---|---|---|
| 1 | VPN / Split DNS Failure | HIGH | ✅ Matched |
| 2 | Sandbox Policy Violation | HIGH | ✅ Matched |
| 3 | Keychain Item Not Found | HIGH | ✅ Matched |
| 4 | Auth Failure Cascade | CRITICAL | ✅ Matched |
| 5 | HTTP 403 on Uploads | MEDIUM | ✅ Matched |
| 6 | SQLite Lock Contention | MEDIUM | ✅ Matched |
| 7 | Memory Pressure / Jetsam | MEDIUM | ✅ Matched |
| 8 | AMFI Library Rejection | HIGH | ✅ Matched |

7/8 signatures matched. Only `dylib_load_fail` pattern was also matched (AMFI rejection). All 8 signatures relevant.

---

## Error Statistics

| Metric | Value |
|---|---|
| Total log entries | 55 |
| ERROR level | 16 |
| CRITICAL level | 4 |
| FAULT level (kernel) | 7 |
| WARN level | 3 |
| Crash reports | 1 |
| Unique error clusters | 28 |
| Matched signatures | 7 |
| Analysis window | 59 minutes |

**Top error sources by frequency:**
1. `SyncEngine` — 4 errors (auth + sync failures)
2. `DatabaseManager` — 3 errors (SQLITE_BUSY)
3. `AuthService` — 2 errors (token refresh)
4. `kernel` — 3 faults (sandbox + memory + AMFI)
5. `configd` — 3 errors (DNS/network)

---

## Immediate Actions (Prioritized)

### 🔴 Do Now (< 30 minutes, IT/MDM team)

1. **Verify and push VPN configuration**
   ```bash
   scutil --nc list                          # list VPN configs on device
   scutil --dns | grep acme.internal         # confirm split-DNS is configured
   ```
   If VPN client is absent: push via MDM (Jamf/Intune) immediately.

2. **Clear stale Keychain item**
   ```bash
   security delete-generic-password -s com.acme.enterprise
   ```
   App will prompt for re-authentication on next launch.

3. **Force app re-launch** (after VPN is confirmed)
   ```bash
   killall Acme
   open /Applications/Acme.app
   ```

### 🟡 Fix This Week (Engineering team)

4. **Add nil-check on auth token before network calls**
   In `-[SyncEngine processQueuedUploads]`, add:
   ```objc
   if (!self.authToken || self.authToken.length == 0) {
       [self scheduleAuthRefreshAndRetry];
       return;
   }
   ```

5. **Separate sync retry from auth retry**
   Sync should pause and wait for a `AuthTokenRefreshedNotification`, not loop independently.

6. **Re-sign AcmeDocProcessor plugin**
   ```bash
   codesign --force --sign "Developer ID Application: Acme Corp (TEAMID)" \
     --options runtime \
     /Library/Application\ Support/Acme/Plugins/AcmeDocProcessor.plugin
   codesign --verify --deep --strict AcmeDocProcessor.plugin
   ```

### 🟢 Fix This Quarter (Architecture)

7. **Enable SQLite WAL mode**
   ```c
   sqlite3_exec(db, "PRAGMA journal_mode=WAL;", 0, 0, 0);
   sqlite3_busy_timeout(db, 5000);
   ```
   Or route all DB writes through a single XPC service.

8. **Stream file uploads instead of buffering**
   Replace `[NSData dataWithContentsOfFile:]` with streaming upload to cap memory at ~50MB regardless of queue depth.

9. **Add VPN presence check on launch**
   Before attempting any internal connections, check `NWPathMonitor` for reachability of `auth.acme.internal` and show a clear *"VPN required"* UI state rather than entering a silent retry loop.

---

## Data Gaps (What Would Increase Confidence)

1. **Full device system profile** — macOS version, hardware model, RAM. Confirms whether 418MB RSS is unusual for this hardware.
2. **MDM configuration profile** — VPN payload configuration. Confirms whether split-DNS is correctly defined.
3. **Confirmation of VPN client state at incident time** — was it installed? Not running? Misconfigured?
4. **App version history** — did this start after a specific app update or macOS update?
5. **Whether issue is reproducible across all users or just this account** — if just one user, MDM profile delivery failure is more likely than a widespread VPN config issue.

---

## Blast Radius Estimate

Without fleet data, estimating based on failure mode:

- **If root cause is VPN config issue in MDM profile:** Affects all users whose device received this MDM profile version — potentially hundreds to thousands of endpoints.
- **If root cause is this user's device-specific state:** Isolated to this device.

**Recommendation:** Check MDM console for devices where the VPN profile was last updated, and cross-reference with support tickets in the same timeframe.

---

*Report generated by LogWise v1.0 · Analysis engine: rule-based + Claude AI*
