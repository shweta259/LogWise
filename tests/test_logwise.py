"""
test_logwise.py — Comprehensive test suite for LogWise
Run: pytest test_logwise.py -v --tb=short
Coverage: pytest test_logwise.py --cov=src --cov-report=term-missing
"""

import pytest
import sys
import json
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from log_parser import (
    parse_app_log, parse_system_log, parse_crash_report,
    parse_all, LogEntry, CrashReport, _normalize_level
)
from analyzer import (
    analyze, _fingerprint, MACOS_SIGNATURES,
    ErrorCluster, AnalysisResult
)
from ai_engine import _fallback_analysis, _build_prompt


# ═══════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def app_log_single():
    return "2025-11-14 08:01:03.442 [ERROR] [auth] AuthService - Token refresh failed: NSURLErrorDomain -1009"

@pytest.fixture
def app_log_multiline():
    return """\
2025-11-14 08:01:02.341 [INFO] [main] AppDelegate - Application launched (version 4.2.1)
2025-11-14 08:01:03.100 [INFO] [auth] AuthService - Attempting SSO token refresh
2025-11-14 08:01:03.442 [ERROR] [auth] AuthService - Token refresh failed: NSURLErrorDomain -1009
2025-11-14 08:01:04.312 [ERROR] [sync] SyncEngine - Upload failed for file "report.xlsx": HTTP 403
2025-11-14 08:01:04.901 [CRITICAL] [sync] SyncEngine - Sync aborted after 2 consecutive auth failures
2025-11-14 08:15:00.021 [ERROR] [db] DatabaseManager - SQLite error: SQLITE_BUSY - database is locked
2025-11-14 08:30:12.006 [WARN] [perf] MemoryMonitor - Memory pressure HIGH - RSS: 412MB
"""

@pytest.fixture
def system_log_multiline():
    return """\
Timestamp                       Thread     Type        Activity             PID    TTL
2025-11-14 08:01:00.001 +0000   0x3f21     Error       0x0                  312    0    com.apple.security.keychain: errSecItemNotFound
2025-11-14 08:01:03.441 +0000   0x4a02     Error       0x0                  4412   0    Acme[4412]: NSURLSession task failed
2025-11-14 08:01:03.441 +0000   0x1000     Fault       0x0                  1      0    kernel: sandbox violation: deny network-outbound
2025-11-14 08:15:00.011 +0000   0x4b11     Default     0x0                  4219   0    AcmeSyncHelper[4219]: Acquired SQLite write lock
2025-11-14 08:30:12.000 +0000   0x1b01     Fault       0x0                  1      0    kernel: (VM) Acme[4412] page reclaim pressure HIGH
2025-11-14 09:00:00.098 +0000   0x5600     Error       0x0                  247    0    configd: Split DNS domains unreachable: [acme.internal]
"""

@pytest.fixture
def crash_report_text():
    return """\
Process:               Acme [4412]
Path:                  /Applications/Acme.app/Contents/MacOS/Acme
Version:               4.2.1 (1041)
OS Version:            macOS 14.1.1 (23B81)
Date/Time:             2025-11-14 08:30:15.441 +0000
Exception Type:        EXC_BAD_ACCESS (SIGSEGV)
Exception Subtype:     KERN_INVALID_ADDRESS at 0x0000000000000000
Termination Reason:    Namespace SIGNAL, Code 0xb

Thread 0 Crashed:: Dispatch queue: com.apple.main-thread
0   libobjc.A.dylib    0x00000001913ab5fc objc_msgSend + 28
1   Acme               0x0000000100d8a201 -[SyncEngine processQueuedUploads] + 512
2   Foundation         0x00000001918abcd4 __NSThreadPerformPerform + 124

Application Specific Information:
Crashed during sync retry after auth failure. Memory footprint was 418MB at time of crash.

Binary Images:
0x100d44000 com.acme.enterprise (4.2.1)
"""

@pytest.fixture
def minimal_parsed():
    return {
        "entries": [
            {"timestamp": "2025-11-14 08:01:03", "level": "ERROR", "source": "AuthService",
             "process": "AuthService", "message": "Token refresh failed: -1009", "raw": "", "log_file": "test.log", "thread": None, "pid": None, "line_number": 1},
            {"timestamp": "2025-11-14 08:01:04", "level": "CRITICAL", "source": "SyncEngine",
             "process": "SyncEngine", "message": "Sync aborted after 2 consecutive auth failures", "raw": "", "log_file": "test.log", "thread": None, "pid": None, "line_number": 2},
            {"timestamp": "2025-11-14 08:15:00", "level": "ERROR", "source": "DatabaseManager",
             "process": "DatabaseManager", "message": "SQLITE_BUSY - database is locked", "raw": "", "log_file": "test.log", "thread": None, "pid": None, "line_number": 3},
        ],
        "crashes": []
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 1: LOG PARSER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogParser:

    # ── App log parsing ──────────────────────────────────────────────────
    def test_parse_app_log_single_error(self, app_log_single):
        entries = parse_app_log(app_log_single)
        assert len(entries) == 1
        e = entries[0]
        assert e.level == "ERROR"
        assert e.source in ("auth", "AuthService")
        assert "NSURLErrorDomain" in e.message
        assert e.timestamp == "2025-11-14 08:01:03.442"

    def test_parse_app_log_multi_levels(self, app_log_multiline):
        entries = parse_app_log(app_log_multiline)
        levels = [e.level for e in entries]
        assert "INFO" in levels
        assert "ERROR" in levels
        assert "CRITICAL" in levels
        assert "WARN" in levels

    def test_parse_app_log_count(self, app_log_multiline):
        entries = parse_app_log(app_log_multiline)
        assert len(entries) == 7

    def test_parse_app_log_empty_string(self):
        entries = parse_app_log("")
        assert entries == []

    def test_parse_app_log_blank_lines_ignored(self):
        log = "\n\n2025-11-14 08:01:03.442 [ERROR] [auth] AuthService - Token refresh failed\n\n"
        entries = parse_app_log(log)
        assert len(entries) == 1

    def test_parse_app_log_preserves_message(self):
        log = '2025-11-14 08:01:04.312 [ERROR] [sync] SyncEngine - Upload failed: HTTP 403 Forbidden'
        entries = parse_app_log(log)
        assert "HTTP 403 Forbidden" in entries[0].message

    def test_parse_app_log_filename_stored(self, app_log_single):
        entries = parse_app_log(app_log_single, filename="my_app.log")
        assert entries[0].log_file == "my_app.log"

    # ── System log parsing ───────────────────────────────────────────────
    def test_parse_system_log_skips_header(self, system_log_multiline):
        entries = parse_system_log(system_log_multiline)
        for e in entries:
            assert e.message != "Thread"  # header line not parsed
            assert "Timestamp" not in e.message

    def test_parse_system_log_fault_level(self, system_log_multiline):
        entries = parse_system_log(system_log_multiline)
        faults = [e for e in entries if e.level == "FAULT"]
        assert len(faults) >= 2  # kernel sandbox + memory pressure

    def test_parse_system_log_extracts_pid(self, system_log_multiline):
        entries = parse_system_log(system_log_multiline)
        pids = [e.pid for e in entries if e.pid is not None]
        assert len(pids) > 0
        assert all(isinstance(p, int) for p in pids)

    def test_parse_system_log_extracts_thread(self, system_log_multiline):
        entries = parse_system_log(system_log_multiline)
        threads = [e.thread for e in entries if e.thread]
        assert all(t.startswith("0x") for t in threads)

    def test_parse_system_log_empty(self):
        entries = parse_system_log("")
        assert entries == []

    # ── Crash report parsing ─────────────────────────────────────────────
    def test_parse_crash_report_extracts_process(self, crash_report_text):
        cr = parse_crash_report(crash_report_text)
        assert cr is not None
        assert "Acme" in cr.process

    def test_parse_crash_report_exception_type(self, crash_report_text):
        cr = parse_crash_report(crash_report_text)
        assert "EXC_BAD_ACCESS" in cr.exception_type
        assert "SIGSEGV" in cr.exception_type

    def test_parse_crash_report_os_version(self, crash_report_text):
        cr = parse_crash_report(crash_report_text)
        assert "macOS 14" in cr.os_version

    def test_parse_crash_report_stack_frames(self, crash_report_text):
        cr = parse_crash_report(crash_report_text)
        assert len(cr.stack_frames) >= 2
        symbols = [f["symbol"] for f in cr.stack_frames]
        assert any("SyncEngine" in s for s in symbols)

    def test_parse_crash_report_app_info(self, crash_report_text):
        cr = parse_crash_report(crash_report_text)
        assert "sync retry" in cr.app_specific_info.lower() or "418MB" in cr.app_specific_info

    def test_parse_crash_report_version(self, crash_report_text):
        cr = parse_crash_report(crash_report_text)
        assert "4.2.1" in cr.version

    # ── Level normalization ───────────────────────────────────────────────
    @pytest.mark.parametrize("raw,expected", [
        ("error", "ERROR"), ("ERROR", "ERROR"),
        ("fault", "FAULT"), ("Fault", "FAULT"),
        ("warning", "WARN"), ("WARN", "WARN"),
        ("info", "INFO"), ("Info", "INFO"),
        ("debug", "DEBUG"),
        ("default", "INFO"),
        ("critical", "CRITICAL"),
    ])
    def test_normalize_level(self, raw, expected):
        assert _normalize_level(raw) == expected

    def test_normalize_level_unknown_defaults_to_info(self):
        assert _normalize_level("unknown_level") == "INFO"

    # ── parse_all integration ────────────────────────────────────────────
    def test_parse_all_multi_file(self, app_log_multiline, system_log_multiline):
        result = parse_all({
            "app.log": app_log_multiline,
            "system.log": system_log_multiline,
        })
        assert "entries" in result
        assert "crashes" in result
        assert len(result["entries"]) > 0

    def test_parse_all_detects_crash_by_extension(self, app_log_multiline, crash_report_text):
        result = parse_all({
            "app.log": app_log_multiline,
            "Acme_crash.ips": crash_report_text,
        })
        assert len(result["crashes"]) == 1

    def test_parse_all_sorted_by_timestamp(self, app_log_multiline, system_log_multiline):
        result = parse_all({
            "app.log": app_log_multiline,
            "system.log": system_log_multiline,
        })
        timestamps = [e["timestamp"] for e in result["entries"]]
        assert timestamps == sorted(timestamps)

    def test_parse_all_empty_dict(self):
        result = parse_all({})
        assert result["entries"] == []
        assert result["crashes"] == []

    def test_parse_all_returns_serializable_dicts(self, app_log_multiline):
        result = parse_all({"app.log": app_log_multiline})
        # Must be JSON-serializable (no sets, dataclasses, etc.)
        json_str = json.dumps(result)
        assert len(json_str) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 2: ANALYZER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestFingerprinting:

    def test_strips_hex_addresses(self):
        fp = _fingerprint("error at 0x1a4f2300 in process")
        assert "0x" not in fp
        assert "ADDR" in fp

    def test_strips_numbers(self):
        fp = _fingerprint("SQLITE_BUSY: lock held by PID 4219")
        assert "4219" not in fp
        assert "NUM" in fp

    def test_strips_file_paths(self):
        fp = _fingerprint("failed to read /Library/Application Support/config.plist")
        assert "/Library" not in fp
        assert "PATH" in fp

    def test_strips_email_addresses(self):
        fp = _fingerprint("token refresh failed for user@acme.com")
        assert "user@acme.com" not in fp
        assert "EMAIL" in fp

    def test_identical_messages_same_fingerprint(self):
        fp1 = _fingerprint("SQLITE_BUSY: lock held by PID 4219 at 0x1a4f")
        fp2 = _fingerprint("SQLITE_BUSY: lock held by PID 9912 at 0xdeadbeef")
        assert fp1 == fp2

    def test_different_messages_different_fingerprint(self):
        fp1 = _fingerprint("SQLITE_BUSY: database is locked")
        fp2 = _fingerprint("Token refresh failed: NSURLErrorDomain")
        assert fp1 != fp2

    def test_case_insensitive(self):
        fp1 = _fingerprint("SQLITE_BUSY database locked")
        fp2 = _fingerprint("sqlite_busy database locked")
        assert fp1 == fp2

    def test_strips_quoted_strings(self):
        fp = _fingerprint('upload failed for "Q4_Report_FINAL.xlsx": HTTP 403')
        assert "Q4_Report_FINAL.xlsx" not in fp


class TestSignatureMatching:

    def test_all_signatures_have_required_fields(self):
        required = {"id", "name", "pattern", "category", "severity", "description", "remediation"}
        for sig in MACOS_SIGNATURES:
            missing = required - set(sig.keys())
            assert not missing, f"Signature '{sig.get('name')}' missing: {missing}"

    def test_all_signatures_have_remediations(self):
        for sig in MACOS_SIGNATURES:
            assert len(sig["remediation"]) >= 2, f"{sig['name']} needs >= 2 remediation steps"

    def test_all_severities_valid(self):
        valid = {"HIGH", "MEDIUM", "LOW", "CRITICAL"}
        for sig in MACOS_SIGNATURES:
            assert sig["severity"] in valid

    def test_sandbox_signature_matches(self):
        sig = next(s for s in MACOS_SIGNATURES if s["id"] == "sandbox_violation")
        assert sig["pattern"].search("kernel: sandbox deny network-outbound")
        assert sig["pattern"].search("AMFI: rejecting load library validation failed")
        assert not sig["pattern"].search("normal info message")

    def test_db_lock_signature_matches(self):
        sig = next(s for s in MACOS_SIGNATURES if s["id"] == "db_lock_contention")
        assert sig["pattern"].search("SQLITE_BUSY: database is locked")
        assert sig["pattern"].search("lock held by PID 4219")

    def test_dns_signature_matches(self):
        sig = next(s for s in MACOS_SIGNATURES if s["id"] == "network_dns_failure")
        assert sig["pattern"].search("Split DNS domains unreachable: [acme.internal]")
        assert sig["pattern"].search("kDNSServiceErr_NoRouter")

    def test_keychain_signature_matches(self):
        sig = next(s for s in MACOS_SIGNATURES if s["id"] == "keychain_missing")
        assert sig["pattern"].search("errSecItemNotFound")
        assert sig["pattern"].search("SecKeychainItemCopyAttributesAndData: item not found")

    def test_memory_signature_matches(self):
        sig = next(s for s in MACOS_SIGNATURES if s["id"] == "memory_pressure")
        assert sig["pattern"].search("memorystatus: killing_on_behalf_of pid 4412")
        assert sig["pattern"].search("Memory pressure HIGH RSS: 412MB")

    def test_no_false_positives_on_clean_log(self):
        clean = "Application started successfully. All services online. Sync completed."
        matched = [s for s in MACOS_SIGNATURES if s["pattern"].search(clean)]
        assert len(matched) == 0

    @pytest.mark.parametrize("sig_id,log_text", [
        ("sandbox_violation",  "sandbox deny mach-lookup keychain"),
        ("keychain_missing",   "errSecItemNotFound code=-25300"),
        ("network_dns_failure","Split DNS domains unreachable"),
        ("db_lock_contention", "SQLITE_BUSY database is locked"),
        ("memory_pressure",    "Memory pressure HIGH RSS: 430MB"),
        ("http_403_perm",      "HTTP 403 Forbidden"),
        ("dylib_load_fail",    "Library not loaded @rpath AcmeCore"),
    ])
    def test_each_signature_matches_expected_text(self, sig_id, log_text):
        sig = next(s for s in MACOS_SIGNATURES if s["id"] == sig_id)
        assert sig["pattern"].search(log_text), f"{sig_id} failed to match: {log_text}"


class TestAnalyzer:

    def test_analyze_returns_analysis_result(self, minimal_parsed):
        result = analyze(minimal_parsed)
        assert isinstance(result, AnalysisResult)

    def test_analyze_counts_errors(self, minimal_parsed):
        result = analyze(minimal_parsed)
        assert result.error_count == 2  # 2 ERRORs (not CRITICAL)

    def test_analyze_counts_critical(self, minimal_parsed):
        result = analyze(minimal_parsed)
        assert result.critical_count == 1

    def test_analyze_total_entries(self, minimal_parsed):
        result = analyze(minimal_parsed)
        assert result.total_entries == 3

    def test_analyze_empty_input(self):
        result = analyze({"entries": [], "crashes": []})
        assert result.total_entries == 0
        assert result.error_count == 0
        assert "No log entries" in result.summary

    def test_analyze_time_range(self, minimal_parsed):
        result = analyze(minimal_parsed)
        assert result.time_range["start"] == "2025-11-14 08:01:03"
        assert result.time_range["end"] == "2025-11-14 08:15:00"

    def test_analyze_detects_sqlite_signature(self, minimal_parsed):
        result = analyze(minimal_parsed)
        sig_ids = [s["id"] for s in result.matched_signatures]
        assert "db_lock_contention" in sig_ids

    def test_analyze_clusters_errors(self):
        repeated_log = {
            "entries": [
                {"timestamp": f"2025-11-14 08:01:0{i}", "level": "ERROR",
                 "source": "DB", "process": "DB",
                 "message": f"SQLITE_BUSY: lock held by PID {1000+i}",
                 "raw": "", "log_file": "test.log", "thread": None, "pid": None, "line_number": i}
                for i in range(5)
            ],
            "crashes": []
        }
        result = analyze(repeated_log)
        assert result.unique_error_clusters < 5  # clustered, not 5 separate

    def test_analyze_cluster_count_matches(self, repeated_log=None):
        data = {
            "entries": [
                {"timestamp": "2025-11-14 08:01:01", "level": "ERROR", "source": "A",
                 "process": "A", "message": "SQLITE_BUSY: lock PID 100", "raw": "", "log_file": "f", "thread": None, "pid": None, "line_number": 1},
                {"timestamp": "2025-11-14 08:01:02", "level": "ERROR", "source": "A",
                 "process": "A", "message": "SQLITE_BUSY: lock PID 200", "raw": "", "log_file": "f", "thread": None, "pid": None, "line_number": 2},
                {"timestamp": "2025-11-14 08:01:03", "level": "ERROR", "source": "B",
                 "process": "B", "message": "Token refresh failed: -1009", "raw": "", "log_file": "f", "thread": None, "pid": None, "line_number": 3},
            ],
            "crashes": []
        }
        result = analyze(data)
        assert result.unique_error_clusters == 2  # SQLITE_BUSY cluster + token cluster

    def test_analyze_top_error_sources(self):
        data = {
            "entries": [
                {"timestamp": "2025-11-14 08:01:0" + str(i), "level": "ERROR",
                 "source": "AuthService", "process": "A", "message": "fail", "raw": "",
                 "log_file": "f", "thread": None, "pid": None, "line_number": i}
                for i in range(5)
            ] + [
                {"timestamp": "2025-11-14 08:01:06", "level": "ERROR",
                 "source": "SyncEngine", "process": "B", "message": "sync fail",
                 "raw": "", "log_file": "f", "thread": None, "pid": None, "line_number": 6}
            ],
            "crashes": []
        }
        result = analyze(data)
        sources = [s["source"] for s in result.top_error_sources]
        assert sources[0] == "AuthService"  # most errors

    def test_analyze_counts_crashes(self, crash_report_text):
        from log_parser import parse_crash_report
        cr = parse_crash_report(crash_report_text)
        data = {"entries": [], "crashes": [cr.to_dict()]}
        result = analyze(data)
        assert result.crash_count == 1

    def test_analyze_result_is_json_serializable(self, minimal_parsed):
        result = analyze(minimal_parsed)
        json_str = json.dumps(result.to_dict())
        assert len(json_str) > 0

    def test_analyze_summary_contains_counts(self, minimal_parsed):
        result = analyze(minimal_parsed)
        assert str(result.error_count) in result.summary
        assert str(result.total_entries) in result.summary

    def test_analyze_timeline_sorted(self):
        """Timeline events must always be chronological"""
        entries = [
            {"timestamp": "2025-11-14 09:00:00", "level": "ERROR", "source": "X",
             "process": "X", "message": "late error", "raw": "", "log_file": "f", "thread": None, "pid": None, "line_number": 1},
            {"timestamp": "2025-11-14 08:00:00", "level": "ERROR", "source": "Y",
             "process": "Y", "message": "early error", "raw": "", "log_file": "f", "thread": None, "pid": None, "line_number": 2},
        ]
        result = analyze({"entries": entries, "crashes": []})
        tl_times = [e["timestamp"] for e in result.timeline]
        assert tl_times == sorted(tl_times)


# ═══════════════════════════════════════════════════════════════════════════════
# MODULE 3: AI ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAIEngine:

    @pytest.fixture
    def sample_analysis(self, minimal_parsed):
        return analyze(minimal_parsed).to_dict()

    def test_fallback_returns_dict(self, sample_analysis):
        result = _fallback_analysis(sample_analysis, [])
        assert isinstance(result, dict)

    def test_fallback_has_all_required_keys(self, sample_analysis):
        result = _fallback_analysis(sample_analysis, [])
        required = {
            "executive_summary", "root_cause_hypotheses",
            "immediate_actions", "systemic_fixes",
            "data_gaps", "severity_assessment"
        }
        assert required.issubset(set(result.keys()))

    def test_fallback_hypotheses_are_ranked(self, sample_analysis):
        result = _fallback_analysis(sample_analysis, [])
        hyps = result["root_cause_hypotheses"]
        ranks = [h["rank"] for h in hyps]
        assert ranks == sorted(ranks)

    def test_fallback_confidence_values_valid(self, sample_analysis):
        result = _fallback_analysis(sample_analysis, [])
        valid_conf = {"HIGH", "MEDIUM", "LOW"}
        for h in result["root_cause_hypotheses"]:
            assert h["confidence"] in valid_conf

    def test_fallback_severity_valid(self, sample_analysis):
        result = _fallback_analysis(sample_analysis, [])
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert result["severity_assessment"]["overall"] in valid

    def test_fallback_is_critical_when_crash_present(self, minimal_parsed):
        minimal_parsed["crashes"] = [{"process": "Acme", "exception_type": "EXC_BAD_ACCESS"}]
        analysis = analyze(minimal_parsed).to_dict()
        analysis["crash_count"] = 1
        result = _fallback_analysis(analysis, minimal_parsed["crashes"])
        assert result["severity_assessment"]["overall"] == "CRITICAL"

    def test_fallback_is_json_serializable(self, sample_analysis):
        result = _fallback_analysis(sample_analysis, [])
        json_str = json.dumps(result)
        assert len(json_str) > 0

    def test_fallback_marks_itself(self, sample_analysis):
        result = _fallback_analysis(sample_analysis, [], "test error")
        assert result.get("_fallback") is True

    def test_fallback_data_gaps_not_empty(self, sample_analysis):
        result = _fallback_analysis(sample_analysis, [])
        assert len(result["data_gaps"]) > 0

    def test_build_prompt_contains_signature_names(self):
        analysis = {
            "total_entries": 10,
            "error_count": 5,
            "critical_count": 1,
            "crash_count": 1,
            "time_range": {"start": "08:00", "end": "09:00"},
            "matched_signatures": [
                {"id": "sandbox_violation", "name": "Sandbox Policy Violation",
                 "severity": "HIGH", "description": "Test", "category": "Security"}
            ],
            "error_clusters": [],
        }
        prompt = _build_prompt(analysis, [], [])
        assert "Sandbox Policy Violation" in prompt

    def test_build_prompt_contains_stats(self):
        analysis = {
            "total_entries": 42,
            "error_count": 7,
            "critical_count": 3,
            "crash_count": 2,
            "time_range": {"start": "08:00", "end": "09:00"},
            "matched_signatures": [],
            "error_clusters": [],
        }
        prompt = _build_prompt(analysis, [], [])
        assert "42" in prompt
        assert "7" in prompt

    def test_build_prompt_includes_crash_info(self, crash_report_text):
        from log_parser import parse_crash_report
        cr = parse_crash_report(crash_report_text).to_dict()
        analysis = {
            "total_entries": 5, "error_count": 2, "critical_count": 1,
            "crash_count": 1, "time_range": {"start": "", "end": ""},
            "matched_signatures": [], "error_clusters": []
        }
        prompt = _build_prompt(analysis, [cr], [])
        assert "EXC_BAD_ACCESS" in prompt or "SIGSEGV" in prompt

    def test_build_prompt_includes_snippets(self):
        analysis = {
            "total_entries": 5, "error_count": 2, "critical_count": 0,
            "crash_count": 0, "time_range": {"start": "", "end": ""},
            "matched_signatures": [], "error_clusters": []
        }
        snippets = ["[ERROR] Token refresh failed", "[CRITICAL] Sync aborted"]
        prompt = _build_prompt(analysis, [], snippets)
        assert "Token refresh failed" in prompt


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegration:

    def test_full_pipeline_with_all_three_files(
        self, app_log_multiline, system_log_multiline, crash_report_text
    ):
        parsed = parse_all({
            "app_errors.log": app_log_multiline,
            "system.log": system_log_multiline,
            "Acme.ips": crash_report_text,
        })
        assert len(parsed["entries"]) > 0
        assert len(parsed["crashes"]) == 1

        result = analyze(parsed)
        assert result.total_entries > 0
        assert result.crash_count == 1
        assert len(result.matched_signatures) > 0

        ai = _fallback_analysis(result.to_dict(), parsed["crashes"])
        assert ai["severity_assessment"]["overall"] == "CRITICAL"
        assert len(ai["root_cause_hypotheses"]) > 0

    def test_pipeline_detects_cascade_signatures(
        self, app_log_multiline, system_log_multiline
    ):
        parsed = parse_all({
            "app.log": app_log_multiline,
            "system.log": system_log_multiline,
        })
        result = analyze(parsed)
        sig_ids = {s["id"] for s in result.matched_signatures}
        # The cascade: db lock + memory pressure should both be caught
        assert "db_lock_contention" in sig_ids
        assert "memory_pressure" in sig_ids

    def test_empty_pipeline_does_not_crash(self):
        parsed = parse_all({})
        result = analyze(parsed)
        ai = _fallback_analysis(result.to_dict(), [])
        assert ai is not None

    def test_app_only_log_still_produces_findings(self, app_log_multiline):
        parsed = parse_all({"app.log": app_log_multiline})
        result = analyze(parsed)
        assert result.total_entries == 7
        assert result.error_count >= 2

    def test_output_structure_constant_across_runs(self, app_log_multiline):
        """Idempotency: same input must produce same output shape"""
        parsed1 = parse_all({"app.log": app_log_multiline})
        parsed2 = parse_all({"app.log": app_log_multiline})
        r1 = analyze(parsed1).to_dict()
        r2 = analyze(parsed2).to_dict()
        assert r1["total_entries"] == r2["total_entries"]
        assert r1["error_count"] == r2["error_count"]
        assert set(s["id"] for s in r1["matched_signatures"]) == \
               set(s["id"] for s in r2["matched_signatures"])


# ═══════════════════════════════════════════════════════════════════════════════
# EDGE CASE & ROBUSTNESS TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_malformed_log_line_does_not_crash(self):
        garbage = "this is not a log line at all @@##$$"
        entries = parse_app_log(garbage)
        assert entries == []  # gracefully returns empty

    def test_unicode_in_log_message(self):
        log = "2025-11-14 08:01:03.442 [ERROR] [auth] AuthService - Échec de l'authentification: 错误"
        entries = parse_app_log(log)
        # Should parse without crashing; message may or may not be captured
        assert isinstance(entries, list)

    def test_very_large_log_does_not_oom(self):
        """10,000 log lines should parse in reasonable time"""
        lines = "\n".join(
            f"2025-11-14 08:{i//60:02d}:{i%60:02d}.000 [ERROR] [x] X - error {i}"
            for i in range(10000)
        )
        entries = parse_app_log(lines)
        assert len(entries) == 10000

    def test_analyze_with_only_info_logs(self):
        data = {
            "entries": [
                {"timestamp": "2025-11-14 08:01:00", "level": "INFO", "source": "App",
                 "process": "App", "message": "Started", "raw": "", "log_file": "f",
                 "thread": None, "pid": None, "line_number": 1}
            ],
            "crashes": []
        }
        result = analyze(data)
        assert result.error_count == 0
        assert result.unique_error_clusters == 0

    def test_fingerprint_handles_empty_string(self):
        fp = _fingerprint("")
        assert isinstance(fp, str)

    def test_crash_report_missing_fields_does_not_crash(self):
        minimal = "Process: App\nException Type: EXC_BAD_ACCESS\n"
        cr = parse_crash_report(minimal)
        assert cr is not None  # partial parse is ok

    def test_analyze_warn_not_counted_as_error(self):
        data = {
            "entries": [
                {"timestamp": "2025-11-14 08:01:00", "level": "WARN", "source": "A",
                 "process": "A", "message": "something slow", "raw": "", "log_file": "f",
                 "thread": None, "pid": None, "line_number": 1}
            ],
            "crashes": []
        }
        result = analyze(data)
        assert result.error_count == 0
        assert result.warn_count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# COVERAGE TARGETS (for --cov report)
# Expected: log_parser ~92%, analyzer ~88%, ai_engine ~85%
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-q"])
