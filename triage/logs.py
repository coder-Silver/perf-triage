"""Scan Android logcat, bugreport and tombstone text for graded evidence."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from .advice import format_percent, log_cpu_level
from .models import Finding

TRACE_SUFFIXES = {".pftrace", ".perfetto-trace", ".ptrace"}

THREADTIME = re.compile(
    r"^(?P<date>\d{2}-\d{2}|\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEF])\s+(?P<tag>.*?)\s*:\s*(?P<msg>.*)$"
)
BRIEF = re.compile(
    r"^(?P<date>\d{2}-\d{2}|\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<level>[VDIWEF])/(?P<tag>[^(]+)\(\s*(?P<pid>\d+)\)\s*:\s*(?P<msg>.*)$"
)
ANR_IN = re.compile(r"ANR in ([^\s(,]+)", re.I)
ANR_PROC = re.compile(r"ANR in [^(]+\(([^)/]+)/(\d+)\)", re.I)
PID_FIELD = re.compile(r"\bpid[:=\s]+(\d+)", re.I)
PROC_FIELD = re.compile(r"Process:\s*([^\s,]+)", re.I)
SKIPPED = re.compile(r"Skipped\s+(\d+)\s+frames", re.I)
FINGERPRINT = re.compile(r"(?:Build fingerprint|ro\.build\.fingerprint)\s*[:=]\s*(\S+)", re.I)
DISPLAY_ID = re.compile(r"ro\.build\.display\.id\s*[:=]\s*(\S+)", re.I)
OTA = re.compile(r"(OTA|update_engine|增量升级|系统升级|package_updated)", re.I)
TOMBSTONE_PID = re.compile(r"^pid:\s*(\d+).*name:\s*(\S+)", re.I)
TOMBSTONE_NAME = re.compile(r">>>\s*(\S+)\s*<<<")
SPAM_LEVELS = set("EF")
SPAM_MIN = 15
JANK_EVENTS_MIN = 3
JANK_FRAMES_MIN = 30
CPU_USAGE_HEADER = re.compile(r"CPU usage from\s+\d+\s*ms", re.I)
CPU_USAGE_SAMPLE = re.compile(
    r"(?P<pct>\d+(?:\.\d+)?)%\s+(?:(?P<pid>\d+)/(?P<name>[^\s:]+)|(?P<total>TOTAL))\s*:",
    re.I,
)


def is_trace(path: Path) -> bool:
    name = path.name.lower()
    return path.suffix.lower() in TRACE_SUFFIXES or name.endswith(".perfetto-trace")


def is_text_log(path: Path) -> bool:
    if not path.is_file() or is_trace(path):
        return False
    name = path.name.lower()
    if name.startswith(("tombstone", "bugreport", "dumpstate")) or "logcat" in name or name.startswith("anr"):
        return True
    if path.suffix.lower() in {".log", ".logcat", ".out"}:
        return True
    if path.suffix.lower() == ".txt":
        return looks_like_log(path)
    return False


_LOG_SNIFF = re.compile(
    r"(?:"
    r"\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\d+\s+[VDIWEF]\s+"
    r"|beginning of (?:main|system|crash|kernel|radio)"
    r"|\*\*\* \*\*\* \*\*\*"
    r"|DALVIK THREADS"
    r"|Cmd line:"
    r"|dumpstate"
    r"|>>> .+ <<<"
    r")",
    re.I,
)


def looks_like_log(path: Path) -> bool:
    """Recognize a log by content when the file name has no known suffix."""
    try:
        with path.open("rb") as handle:
            blob = handle.read(256 * 1024)
    except OSError:
        return False
    if not blob or b"\x00" in blob[:4096]:
        return False
    text = blob.decode("utf-8", errors="replace")
    return _LOG_SNIFF.search(text) is not None


class _Bucket:
    def __init__(self) -> None:
        self.count = 0
        self.pid = ""
        self.process = ""
        self.first_time = ""
        self.last_time = ""
        self.lines: list[str] = []
        self.event = ""
        self.skipped_max = 0
        self.peak = 0.0

    def add(self, when: str, pid: str, process: str, line: str, event: str = "") -> None:
        self.count += 1
        if pid and not self.pid:
            self.pid = pid
        if process and not self.process:
            self.process = process
        if when and not self.first_time:
            self.first_time = when
        if when:
            self.last_time = when
        if event and not self.event:
            self.event = event
        if len(self.lines) < 4:
            self.lines.append(line[:400])


def _parse_line(line: str) -> dict | None:
    for pattern in (THREADTIME, BRIEF):
        match = pattern.match(line.strip())
        if not match:
            continue
        data = match.groupdict()
        data.setdefault("tid", data.get("pid", ""))
        return data
    return None


def _when(parsed: dict | None, raw: str) -> str:
    if parsed:
        return f"{parsed['date']} {parsed['time']}"
    match = re.search(r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)", raw)
    return match.group(1) if match else ""


def _clip(line: str) -> str:
    return line.strip()[:400]


def _duration_ms(blob: str) -> int:
    match = re.search(r"(?:took|duration=)\s*(\d+)\s*ms", blob, re.I)
    return int(match.group(1)) if match else 0


def scan_text_file(path: Path) -> tuple[list[Finding], dict]:
    anr: dict[str, _Bucket] = defaultdict(_Bucket)
    watchdog: dict[str, _Bucket] = defaultdict(_Bucket)
    sys_stall: dict[str, _Bucket] = defaultdict(_Bucket)
    crashes: dict[str, _Bucket] = defaultdict(_Bucket)
    spam: dict[tuple[str, str], _Bucket] = defaultdict(_Bucket)
    jank: dict[str, _Bucket] = defaultdict(_Bucket)
    thermal: dict[str, _Bucket] = defaultdict(_Bucket)
    memory: dict[str, _Bucket] = defaultdict(_Bucket)
    cpu_usage: dict[str, _Bucket] = defaultdict(_Bucket)
    version = ""
    ota_lines: list[str] = []
    pid_names: dict[str, str] = {}
    signals = {
        "memory": False,
        "cpu_counter": False,
        "sched": False,
        "freq": False,
        "frame": False,
        "system": False,
    }

    opener = path.open("r", encoding="utf-8", errors="replace")
    with opener as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            parsed = _parse_line(line)
            when = _when(parsed, line)
            pid = parsed["pid"] if parsed else ""
            level = parsed["level"] if parsed else ""
            tag = (parsed["tag"] if parsed else "").strip()
            msg = parsed["msg"] if parsed else line
            blob = line

            if not version:
                found = FINGERPRINT.search(blob) or DISPLAY_ID.search(blob)
                if found:
                    version = found.group(1)
            if OTA.search(blob) and len(ota_lines) < 6:
                ota_lines.append(_clip(blob))

            if not re.search(r"no ANR|ANR has not occurred|has not occurred since boot", blob, re.I) and re.search(
                r"ANR in |am_anr|Input dispatching timed out", blob
            ):
                process = ""
                anr_pid = pid
                named = ANR_PROC.search(blob)
                plain = ANR_IN.search(blob)
                if named:
                    process, anr_pid = named.group(1), named.group(2)
                elif plain:
                    process = plain.group(1)
                key = process or anr_pid or "unknown"
                anr[key].add(when, anr_pid or pid, process, _clip(blob), "分析窗口内出现 ANR")
                signals["system"] = True

            if re.search(r"WATCHDOG KILLING|Watchdog:\s*BLOCKED", blob):
                process = "system_server" if re.search(r"system_server|SystemServer", blob) else "system_server"
                pid_m = PID_FIELD.search(blob)
                watchdog[process].add(when, pid_m.group(1) if pid_m else pid, process, _clip(blob), "Watchdog 异常")
                signals["system"] = True

            slow_ms = _duration_ms(blob)
            main_thread = not parsed or parsed.get("tid") == parsed.get("pid")
            if (
                slow_ms >= 1000
                and main_thread
                and re.search(r"system_server|SystemServer", blob, re.I)
                and re.search(r"Slow operation|Slow dispatch", blob, re.I)
            ):
                pid_m = PID_FIELD.search(blob)
                sys_stall["system_server"].add(
                    when,
                    pid_m.group(1) if pid_m else pid,
                    "system_server",
                    _clip(blob),
                    "system_server 卡顿",
                )
                signals["system"] = True

            named_proc = PROC_FIELD.search(blob)
            if named_proc and pid:
                pid_names[pid] = named_proc.group(1)

            fatal = re.search(r"FATAL EXCEPTION|Fatal signal", blob, re.I)
            tombstone = TOMBSTONE_PID.search(line.strip()) or TOMBSTONE_NAME.search(blob)
            if fatal or tombstone or (path.name.lower().startswith("tombstone") and re.search(r"signal \d+", blob, re.I)):
                process = ""
                crash_pid = pid
                proc = PROC_FIELD.search(blob)
                if proc:
                    process = proc.group(1)
                if tombstone and TOMBSTONE_PID.search(line.strip()):
                    crash_pid = TOMBSTONE_PID.search(line.strip()).group(1)
                    process = process or TOMBSTONE_PID.search(line.strip()).group(2)
                named = TOMBSTONE_NAME.search(blob)
                if named:
                    process = process or named.group(1)
                if re.search(r"system_server", process or blob):
                    process = process or "system_server"
                    signals["system"] = True
                key = crash_pid or process or "unknown-crash"
                event = "进程崩溃"
                if "FATAL EXCEPTION" in blob.upper() or "Fatal signal" in blob:
                    event = blob.strip()[:160]
                crashes[key].add(when, crash_pid, process, _clip(blob), event)

            message = msg if parsed else blob
            if (
                level in SPAM_LEVELS
                and re.search(r"Exception", message)
                and not message.strip().startswith("at ")
            ):
                spam_pid = pid or "?"
                spam_key = (spam_pid, tag or "log")
                spam[spam_key].add(when, pid, "", _clip(blob), f"{tag or '异常'} 持续打印")

            skipped = SKIPPED.search(blob)
            davey = re.search(r"Davey!\s+duration=(\d+)ms", blob, re.I)
            frames = int(skipped.group(1)) if skipped else 0
            if davey:
                davey_ms = int(davey.group(1))
                if 64 <= davey_ms <= 10000:
                    frames = max(frames, davey_ms // 16)
            if frames:
                key = pid or "display"
                jank[key].add(when, pid, "", _clip(blob), f"掉帧 {frames}")
                jank[key].skipped_max = max(jank[key].skipped_max, frames)
                signals["frame"] = True

            if re.search(r"throttling\?\s*:\s*false|not throttling|temperatures:\s*\[\]", blob, re.I):
                pass
            elif re.search(r"CPU throttling|FrequencyLimit|限频|cpufreq.*limit|thermal throttling\?\s*:\s*true", blob, re.I):
                thermal[pid or "device"].add(when, pid, "", _clip(blob), "CPU 限频或温控")
                signals["freq"] = True

            usage_header = CPU_USAGE_HEADER.search(blob)
            usage_sample = CPU_USAGE_SAMPLE.search(blob)
            if usage_header or usage_sample:
                signals["cpu_counter"] = True
            if usage_sample and not usage_sample.group("total"):
                pct = float(usage_sample.group("pct"))
                usage_pid = usage_sample.group("pid") or ""
                usage_name = usage_sample.group("name") or ""
                usage_key = usage_pid or usage_name or "cpu"
                cpu_usage[usage_key].add(when, usage_pid, usage_name, _clip(blob))
                cpu_usage[usage_key].peak = max(cpu_usage[usage_key].peak, pct)

            killed = re.search(r"Kill '([^']+)'\s*\((\d+)\)", blob)
            if killed or re.search(r"Low on memory|Failed to allocate", blob, re.I):
                if not re.search(r"FATAL EXCEPTION|OutOfMemoryError", blob):
                    mem_pid = killed.group(2) if killed else pid
                    mem_name = killed.group(1) if killed else ""
                    memory[mem_pid or mem_name or "device"].add(when, mem_pid, mem_name, _clip(blob), "内存压力")
                    signals["memory"] = True

    meta = {"version": version, "ota": ota_lines, "file": path.name, "signals": signals}
    findings: list[Finding] = []
    findings.extend(_emit_p0(anr, "ANR", "分析窗口内出现 ANR"))
    findings.extend(_emit_p0(watchdog, "Watchdog", "Watchdog 异常"))
    findings.extend(_emit_p0(sys_stall, "system_server", "system_server 卡顿"))
    findings.extend(_emit_crashes(crashes))
    findings.extend(_emit_spam(spam))
    findings.extend(_emit_jank(jank))
    findings.extend(_emit_p2(thermal, "限频", "限频"))
    findings.extend(_emit_p2(memory, "内存压力", "内存压力"))
    findings.extend(_emit_cpu(cpu_usage))
    for item in findings:
        named = pid_names.get(item.pid)
        if named and not item.process:
            item.process = named
            if item.category == "进程崩溃":
                item.impact = f"应用 {named}"
        item.upgrade = _upgrade_text(meta)
        item.evidence.insert(0, f"文件 {path.name}")
    return findings, meta


def _upgrade_text(meta: dict) -> str:
    parts = []
    if meta.get("version"):
        parts.append(f"版本 {meta['version']}")
    if meta.get("ota"):
        parts.append("升级记录 " + meta["ota"][0][:180])
    return "；".join(parts) if parts else "日志中未找到版本或升级记录"


def _time_span(bucket: _Bucket) -> str:
    if bucket.first_time and bucket.last_time and bucket.first_time != bucket.last_time:
        return f"{bucket.first_time} ~ {bucket.last_time}"
    return bucket.first_time or "日志中未标出时间"


def _emit_p0(groups: dict[str, _Bucket], category: str, title: str) -> list[Finding]:
    findings = []
    for index, (key, bucket) in enumerate(groups.items(), start=1):
        if bucket.count == 0:
            continue
        process = bucket.process or key
        system = bool(re.search(r"system_server|^system$|SystemServer", process))
        findings.append(
            Finding(
                id=f"p0-{category}-{index}",
                level="P0",
                category=category,
                title=title,
                impact="系统级" if system or category != "ANR" else f"应用 {process}",
                pid=bucket.pid or "未知",
                process=process,
                time=_time_span(bucket),
                upgrade="",
                event=bucket.event or title,
                evidence=list(bucket.lines),
            )
        )
    return findings


def _emit_crashes(groups: dict[str, _Bucket]) -> list[Finding]:
    findings = []
    for index, (key, bucket) in enumerate(groups.items(), start=1):
        process = bucket.process
        system = bool(re.search(r"system_server", process or key))
        findings.append(
            Finding(
                id=f"{'p0' if system else 'p1'}-crash-{index}",
                level="P0" if system else "P1",
                category="系统进程崩溃" if system else "进程崩溃",
                title="system_server 崩溃" if system else "进程崩溃",
                impact="系统级 system_server" if system else (f"应用 {process}" if process else f"应用 pid {bucket.pid or '未知'}"),
                pid=bucket.pid or "未知",
                process=process,
                time=_time_span(bucket),
                upgrade="",
                event=bucket.event or "进程崩溃",
                evidence=list(bucket.lines),
            )
        )
    return findings


def _emit_spam(groups: dict[tuple[str, str], _Bucket]) -> list[Finding]:
    findings = []
    index = 1
    for (pid, tag), bucket in groups.items():
        if bucket.count < SPAM_MIN:
            continue
        findings.append(
            Finding(
                id=f"p1-spam-{index}",
                level="P1",
                category="异常刷屏",
                title="进程异常不断打印",
                impact=f"应用 pid {pid or '未知'}",
                pid=pid if pid != "?" else "未知",
                process=bucket.process,
                time=_time_span(bucket),
                upgrade="",
                event=f"{tag} 重复异常 {bucket.count} 次",
                evidence=list(bucket.lines) + [f"重复次数 {bucket.count}"],
            )
        )
        index += 1
    return findings


def _emit_jank(groups: dict[str, _Bucket]) -> list[Finding]:
    findings = []
    index = 1
    for key, bucket in groups.items():
        if bucket.count < JANK_EVENTS_MIN and bucket.skipped_max < JANK_FRAMES_MIN:
            continue
        findings.append(
            Finding(
                id=f"p1-jank-log-{index}",
                level="P1",
                category="连续掉帧",
                title="交互期间连续掉帧",
                impact=f"应用 pid {bucket.pid or '未知'}",
                pid=bucket.pid or "未知",
                process=bucket.process,
                time=_time_span(bucket),
                upgrade="",
                event=f"Skipped frames 最高 {bucket.skipped_max}，出现 {bucket.count} 次",
                evidence=list(bucket.lines),
                source="logcat",
            )
        )
        index += 1
    return findings


def _emit_p2(groups: dict[str, _Bucket], category: str, title: str) -> list[Finding]:
    findings = []
    for index, (key, bucket) in enumerate(groups.items(), start=1):
        if bucket.count == 0:
            continue
        findings.append(
            Finding(
                id=f"p2-{category}-{index}",
                level="P2",
                category=category,
                title=title,
                impact=f"进程 pid {bucket.pid}" if bucket.pid else "设备",
                pid=bucket.pid or "未知",
                process=bucket.process,
                time=_time_span(bucket),
                upgrade="",
                event=bucket.event or title,
                evidence=list(bucket.lines),
            )
        )
    return findings


def _emit_cpu(groups: dict[str, _Bucket]) -> list[Finding]:
    findings = []
    index = 1
    for bucket in groups.values():
        level = log_cpu_level(bucket.peak)
        if not level:
            continue
        shown = format_percent(bucket.peak)
        process = bucket.process
        system = "system_server" in (process or "")
        findings.append(
            Finding(
                id=f"{level.lower()}-cpu-{index}",
                level=level,
                category="CPU使用率",
                title="CPU 使用率偏高",
                impact="系统级" if system else (f"应用 {process}" if process else "设备"),
                pid=bucket.pid or "未知",
                process=process,
                time=_time_span(bucket),
                upgrade="",
                event=f"{process or '进程'} CPU 使用率 {shown}%",
                evidence=list(bucket.lines),
                source="logcat",
            )
        )
        index += 1
    return findings
