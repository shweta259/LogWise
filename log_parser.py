"""
log_parser.py - Multi-format macOS log ingestion engine
Handles: app logs, unified system logs (log show output), crash reports (.ips/.crash)
"""

import re
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict
from enum import Enum


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    FAULT = "FAULT"


LEVEL_SEVERITY = {
    LogLevel.DEBUG: 0,
    LogLevel.INFO: 1,
    LogLevel.WARN: 2,
    LogLevel.ERROR: 3,
    LogLevel.CRITICAL: 4,
    LogLevel.FAULT: 5,
}

LEVEL_COLOR = {
    LogLevel.DEBUG: "#6b7280",
    LogLevel.INFO: "#3b82f6",
    LogLevel.WARN: "#f59e0b",
    LogLevel.ERROR: "#ef4444",
    LogLevel.CRITICAL: "#dc2626",
    LogLevel.FAULT: "#7c3aed",
}


@dataclass
class LogEntry:
    timestamp: str
    level: str
    source: str          # component/subsystem
    process: str
    message: str
    raw: str
    thread: Optional[str] = None
    pid: Optional[int] = None
    log_file: str = ""
    line_number: int = 0

    def to_dict(self):
        return asdict(self)


@dataclass
class CrashReport:
    timestamp: str
    process: str
    pid: Optional[int]
    version: str
    os_version: str
    exception_type: str
    exception_subtype: str
    termination_reason: str
    crashed_thread: str
    stack_frames: list
    app_specific_info: str
    raw: str

    def to_dict(self):
        return asdict(self)


# ── App log pattern ──────────────────────────────────────────────────────────
# e.g. 2025-11-14 08:01:02.341 [ERROR] [auth] AuthService - Token refresh failed
APP_LOG_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FAULT)\]\s+"
    r"(?:\[(?P<thread>[^\]]+)\]\s+)?"
    r"(?:\[(?P<source>[^\]]+)\]\s+)?"
    r"(?P<component>\S+)\s+-\s+"
    r"(?P<message>.+)"
)

# ── Unified system log pattern (log show output) ─────────────────────────────
# e.g. 2025-11-14 08:01:03.441 +0000   0x4a02     Error       0x0   4412  0   Acme[4412]: msg
SYSLOG_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s+[+-]\d{4})\s+"
    r"(?P<thread>0x[0-9a-f]+)\s+"
    r"(?P<level>Default|Info|Debug|Error|Fault)\s+"
    r"0x[0-9a-f]+\s+"
    r"(?P<pid>\d+)\s+\d+\s+"
    r"(?P<process>[^:]+):\s+"
    r"(?P<message>.+)"
)

# Level normalizer
_LEVEL_MAP = {
    "default": LogLevel.INFO, "info": LogLevel.INFO,
    "debug": LogLevel.DEBUG, "error": LogLevel.ERROR,
    "fault": LogLevel.FAULT, "warning": LogLevel.WARN,
    "warn": LogLevel.WARN, "critical": LogLevel.CRITICAL,
}


def _normalize_level(raw: str) -> str:
    return _LEVEL_MAP.get(raw.lower(), LogLevel.INFO).value


def parse_app_log(content: str, filename: str = "app.log") -> List[LogEntry]:
    entries = []
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        m = APP_LOG_RE.match(line)
        if m:
            entries.append(LogEntry(
                timestamp=m.group("ts"),
                level=_normalize_level(m.group("level")),
                source=m.group("source") or m.group("component"),
                process=m.group("component"),
                message=m.group("message"),
                thread=m.group("thread"),
                raw=line,
                log_file=filename,
                line_number=i,
            ))
    return entries


def parse_system_log(content: str, filename: str = "system.log") -> List[LogEntry]:
    entries = []
    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("Timestamp"):
            continue
        m = SYSLOG_RE.match(line)
        if m:
            pid_str = m.group("pid")
            proc = m.group("process").strip()
            entries.append(LogEntry(
                timestamp=m.group("ts").strip(),
                level=_normalize_level(m.group("level")),
                source=proc,
                process=proc,
                message=m.group("message").strip(),
                thread=m.group("thread"),
                pid=int(pid_str) if pid_str else None,
                raw=line,
                log_file=filename,
                line_number=i,
            ))
    return entries


def parse_crash_report(content: str, filename: str = "") -> Optional[CrashReport]:
    """Parse Apple crash report (.ips / .crash) format."""
    def extract(pattern, text, default=""):
        m = re.search(pattern, text, re.MULTILINE)
        return m.group(1).strip() if m else default

    process = extract(r"^Process:\s+(.+)", content)
    version = extract(r"^Version:\s+(.+)", content)
    os_version = extract(r"^OS Version:\s+(.+)", content)
    exc_type = extract(r"^Exception Type:\s+(.+)", content)
    exc_sub = extract(r"^Exception Subtype:\s+(.+)", content)
    term_reason = extract(r"^Termination(?:\s+Reason)?:\s+(.+)", content)
    timestamp = extract(r"^Date/Time:\s+(.+)", content)
    app_info = extract(r"Application Specific Information:\n((?:.+\n?)+?)(?:\n\n|\nBinary)", content)

    # Parse crashed thread stack
    stack_frames = []
    in_crashed = False
    for line in content.splitlines():
        if re.match(r"Thread \d+ Crashed:", line):
            in_crashed = True
            continue
        if in_crashed:
            if line.strip() == "" or re.match(r"Thread \d+", line):
                break
            frame_m = re.match(r"\d+\s+(\S+)\s+(0x[0-9a-f]+)\s+(.+)", line)
            if frame_m:
                stack_frames.append({
                    "library": frame_m.group(1),
                    "address": frame_m.group(2),
                    "symbol": frame_m.group(3),
                })

    pid_str = extract(r"^Process:\s+\S+\s+\[(\d+)\]", content)
    crashed_thread_summary = stack_frames[0]["symbol"] if stack_frames else ""

    return CrashReport(
        timestamp=timestamp,
        process=process,
        pid=int(pid_str) if pid_str else None,
        version=version,
        os_version=os_version,
        exception_type=exc_type,
        exception_subtype=exc_sub,
        termination_reason=term_reason,
        crashed_thread=crashed_thread_summary,
        stack_frames=stack_frames,
        app_specific_info=app_info,
        raw=content,
    )


def parse_all(log_files: Dict[str, str]) -> dict:
    """
    Parse multiple log files.
    log_files: {filename: content}
    Returns structured result with entries + crashes.
    """
    all_entries: List[LogEntry] = []
    crashes: list[CrashReport] = []

    for filename, content in log_files.items():
        fname_lower = filename.lower()
        if fname_lower.endswith((".ips", ".crash")):
            cr = parse_crash_report(content, filename)
            if cr:
                crashes.append(cr)
        elif "system" in fname_lower or fname_lower.endswith(".log") and "system" in fname_lower:
            all_entries.extend(parse_system_log(content, filename))
        else:
            # Try app log first, fallback to system log
            parsed = parse_app_log(content, filename)
            if not parsed:
                parsed = parse_system_log(content, filename)
            all_entries.extend(parsed)

    # Sort by timestamp (best effort)
    all_entries.sort(key=lambda e: e.timestamp)

    return {
        "entries": [e.to_dict() for e in all_entries],
        "crashes": [c.to_dict() for c in crashes],
    }
