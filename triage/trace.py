"""Read Perfetto traces for scheduling, jank, frequency and memory evidence."""

from __future__ import annotations

from pathlib import Path

from .advice import format_percent, trace_cpu_level
from .flame import read_flame
from .models import Finding

RUNNABLE_MS = 50
UNINTERRUPTIBLE_MS = 20
JANK_COUNT = 5


def bundled_shell() -> str | None:
    root = Path(__file__).resolve().parents[1] / "vendor"
    for name in ("trace_processor_shell.exe", "trace_processor_shell"):
        candidate = root / name
        if candidate.is_file():
            return str(candidate)
    return None


def scan_trace(path: Path) -> tuple[list[Finding], list[str], dict | None, dict]:
    blank = _blank_signals()
    try:
        from perfetto.trace_processor import TraceProcessor, TraceProcessorConfig
    except ImportError:
        return [], [
            f"{path.name} 是 Perfetto trace。当前环境没有 perfetto 包，调度和帧时间线未分析。日志结论仍然有效。"
        ], None, blank

    notes: list[str] = []
    shell = bundled_shell()
    config = TraceProcessorConfig(bin_path=shell) if shell else TraceProcessorConfig()
    try:
        processor = TraceProcessor(trace=str(path), config=config)
    except Exception as exc:
        return [], [f"无法打开 {path.name}：{exc}"], None, blank

    try:
        signals = _signals(processor)
        findings = []
        findings.extend(_sched(processor, path.name))
        findings.extend(_jank(processor, path.name))
        findings.extend(_freq(processor, path.name))
        findings.extend(_memory(processor, path.name))
        findings.extend(_cpu_usage(processor, path.name))
        flame = read_flame(processor, path.name)
        return findings, notes, flame if flame and flame.get("root") else None, signals
    finally:
        close = getattr(processor, "close", None)
        if close:
            close()


def _blank_signals() -> dict:
    return {
        "memory": False,
        "cpu_counter": False,
        "sched": False,
        "freq": False,
        "frame": False,
        "system": False,
    }


def _has_rows(processor, sql: str) -> bool:
    """True only when the query returns a row. A missing table counts as no data."""
    return bool(_query(processor, sql))


def _signals(processor) -> dict:
    signals = _blank_signals()
    signals["sched"] = _has_rows(processor, "SELECT 1 FROM sched LIMIT 1") or _has_rows(
        processor, "SELECT 1 FROM thread_state LIMIT 1"
    )
    # cpu_counter_track also holds cpufreq and cpuidle. Those are not usage.
    signals["cpu_counter"] = _has_rows(
        processor,
        """
        SELECT c.id AS id
        FROM counter c
        JOIN counter_track ct ON c.track_id = ct.id
        WHERE (
            lower(IFNULL(ct.name, '')) GLOB 'cpu.times.*'
            OR lower(IFNULL(ct.name, '')) GLOB '*usage*'
            OR lower(IFNULL(ct.name, '')) GLOB '*util*'
            OR lower(IFNULL(ct.name, '')) GLOB 'cpu.user*'
            OR lower(IFNULL(ct.name, '')) GLOB 'cpu.nice*'
            OR lower(IFNULL(ct.name, '')) GLOB 'cpu.sys*'
            OR lower(IFNULL(ct.name, '')) GLOB 'cpu.system*'
        )
          AND lower(IFNULL(ct.name, '')) NOT GLOB '*cpufreq*'
          AND lower(IFNULL(ct.name, '')) NOT GLOB '*cpu.freq*'
          AND lower(IFNULL(ct.name, '')) NOT GLOB '*cpu_freq*'
          AND lower(IFNULL(ct.name, '')) NOT GLOB '*frequency*'
          AND lower(IFNULL(ct.name, '')) NOT GLOB '*cpuidle*'
        LIMIT 1
        """,
    )
    signals["freq"] = _has_rows(
        processor,
        """
        SELECT c.id AS id
        FROM counter c
        JOIN counter_track ct ON c.track_id = ct.id
        WHERE lower(IFNULL(ct.name, '')) GLOB '*cpufreq*'
           OR lower(IFNULL(ct.name, '')) GLOB '*cpu.freq*'
           OR lower(IFNULL(ct.name, '')) GLOB '*cpu_freq*'
           OR lower(IFNULL(ct.name, '')) GLOB '*frequency*'
        LIMIT 1
        """,
    )
    signals["frame"] = _has_rows(
        processor, "SELECT 1 FROM actual_frame_timeline_slice LIMIT 1"
    ) or _has_rows(processor, "SELECT 1 FROM expected_frame_timeline_slice LIMIT 1")
    signals["memory"] = _has_rows(
        processor,
        """
        SELECT id FROM slice
        WHERE name GLOB '*lmk*' OR name GLOB '*LowMemory*' OR name GLOB '*lowmemory*'
        LIMIT 1
        """,
    ) or _has_rows(
        processor,
        """
        SELECT c.id AS id
        FROM counter c
        JOIN counter_track ct ON c.track_id = ct.id
        WHERE lower(IFNULL(ct.name, '')) GLOB '*mem*'
           OR lower(IFNULL(ct.name, '')) GLOB '*rss*'
           OR lower(IFNULL(ct.name, '')) GLOB '*oom*'
           OR lower(IFNULL(ct.name, '')) GLOB '*lmk*'
        LIMIT 1
        """,
    )
    signals["system"] = _has_rows(
        processor,
        """
        SELECT id FROM slice
        WHERE name GLOB '*ANR*' OR name GLOB '*Watchdog*' OR name GLOB '*watchdog*'
        LIMIT 1
        """,
    )
    return signals


def _query(processor, sql: str) -> list:
    try:
        return list(processor.query(sql))
    except Exception:
        return []


def _ms(value) -> float:
    try:
        return float(value) / 1e6
    except (TypeError, ValueError):
        return 0.0


def _sched(processor, filename: str) -> list[Finding]:
    rows = _query(
        processor,
        """
        SELECT p.name AS process_name, p.pid AS pid, t.name AS thread_name,
               ts.state AS state, ts.dur AS dur
        FROM thread_state ts
        JOIN thread t ON ts.utid = t.utid
        JOIN process p ON t.upid = p.upid
        WHERE t.tid = p.pid
          AND ts.state IN ('R', 'R+', 'D', 'DK')
          AND ts.dur > 0
        ORDER BY ts.dur DESC
        LIMIT 80
        """,
    )
    runnable: dict[str, dict] = {}
    blocked: dict[str, dict] = {}
    for row in rows:
        dur_ms = _ms(row.dur)
        state = str(row.state)
        process = str(row.process_name or "")
        pid = str(row.pid or "")
        key = f"{process}:{pid}"
        target = runnable if state.startswith("R") else blocked
        limit = RUNNABLE_MS if state.startswith("R") else UNINTERRUPTIBLE_MS
        if dur_ms < limit:
            continue
        current = target.get(key)
        if current is None or dur_ms > current["ms"]:
            target[key] = {
                "process": process,
                "pid": pid,
                "ms": dur_ms,
                "thread": str(row.thread_name or ""),
            }
    findings = []
    for index, item in enumerate(runnable.values(), start=1):
        findings.append(
            Finding(
                id=f"p1-runnable-{index}",
                level="P1",
                category="调度",
                title="主线程可运行却未分到 CPU",
                impact=f"应用 {item['process'] or '未知进程'}",
                pid=item["pid"] or "未知",
                process=item["process"],
                time="trace 内最长一段",
                upgrade="",
                event=f"主线程 Runnable {item['ms']:.0f} ms",
                evidence=[
                    f"文件 {filename}",
                    f"thread {item['thread']} state=R duration={item['ms']:.0f}ms",
                ],
                source="perfetto",
            )
        )
    for index, item in enumerate(blocked.values(), start=1):
        findings.append(
            Finding(
                id=f"p1-dstate-{index}",
                level="P1",
                category="调度",
                title="主线程不可中断睡眠",
                impact=f"应用 {item['process'] or '未知进程'}",
                pid=item["pid"] or "未知",
                process=item["process"],
                time="trace 内最长一段",
                upgrade="",
                event=f"主线程 D 状态 {item['ms']:.0f} ms",
                evidence=[
                    f"文件 {filename}",
                    f"thread {item['thread']} state=D duration={item['ms']:.0f}ms",
                ],
                source="perfetto",
            )
        )
    return findings


def _jank(processor, filename: str) -> list[Finding]:
    rows = _query(
        processor,
        """
        SELECT p.name AS process_name, p.pid AS pid, s.jank_type AS jank_type, s.dur AS dur
        FROM actual_frame_timeline_slice s
        JOIN process p ON s.upid = p.upid
        WHERE s.jank_type IS NOT NULL AND s.jank_type != 'None' AND s.jank_type != ''
        """,
    )
    grouped: dict[str, dict] = {}
    for row in rows:
        process = str(row.process_name or "")
        pid = str(row.pid or "")
        key = f"{process}:{pid}"
        item = grouped.setdefault(key, {"process": process, "pid": pid, "count": 0, "max_ms": 0.0, "types": set()})
        item["count"] += 1
        item["max_ms"] = max(item["max_ms"], _ms(row.dur))
        if row.jank_type:
            item["types"].add(str(row.jank_type))
    findings = []
    for index, item in enumerate(grouped.values(), start=1):
        if item["count"] < JANK_COUNT and item["max_ms"] < 64:
            continue
        kinds = "、".join(sorted(item["types"])[:4]) or "jank"
        findings.append(
            Finding(
                id=f"p1-jank-trace-{index}",
                level="P1",
                category="连续掉帧",
                title="交互期间连续掉帧",
                impact=f"应用 {item['process'] or '未知进程'}",
                pid=item["pid"] or "未知",
                process=item["process"],
                time="trace 帧时间线",
                upgrade="",
                event=f"FrameTimeline 卡顿 {item['count']} 帧，最长 {item['max_ms']:.0f} ms，类型 {kinds}",
                evidence=[f"文件 {filename}", f"jank frames={item['count']} max={item['max_ms']:.0f}ms"],
                source="perfetto",
            )
        )
    return findings


def _freq(processor, filename: str) -> list[Finding]:
    rows = _query(
        processor,
        """
        SELECT ct.name AS track, MIN(c.value) AS min_v, MAX(c.value) AS max_v
        FROM counter c
        JOIN counter_track ct ON c.track_id = ct.id
        WHERE ct.name GLOB '*cpufreq*' OR ct.name GLOB '*cpu.freq*'
        GROUP BY ct.name
        """,
    )
    limits = []
    peaks = []
    for row in rows:
        name = str(row.track or "")
        try:
            low = float(row.min_v)
            high = float(row.max_v)
        except (TypeError, ValueError):
            continue
        if "limit" in name or name.endswith("max"):
            limits.append((name, low, high))
        else:
            peaks.append(high)
    if not limits or not peaks:
        return []
    peak = max(peaks)
    if peak <= 0:
        return []
    tight = [item for item in limits if item[1] < peak * 0.7]
    if not tight:
        return []
    name, low, high = min(tight, key=lambda item: item[1])
    return [
        Finding(
            id="p2-freq-trace-1",
            level="P2",
            category="限频",
            title="限频",
            impact="设备级背景",
            pid="未知",
            process="cpufreq",
            time="trace 计数器",
            upgrade="",
            event=f"{name} 最低 {low:.0f}，观测最高频率 {peak:.0f}",
            evidence=[f"文件 {filename}", f"{name} min={low:.0f} max={high:.0f} peak_freq={peak:.0f}"],
            source="perfetto",
        )
    ]


def _memory(processor, filename: str) -> list[Finding]:
    rows = _query(
        processor,
        """
        SELECT name FROM slice
        WHERE name GLOB '*lmk*' OR name GLOB '*LowMemory*'
        LIMIT 8
        """,
    )
    if not rows:
        return []
    names = [str(row.name) for row in rows[:4]]
    return [
        Finding(
            id="p2-mem-trace-1",
            level="P2",
            category="内存压力",
            title="内存压力",
            impact="设备级背景",
            pid="未知",
            process="lmk",
            time="trace slice",
            upgrade="",
            event="trace 中出现低内存相关 slice",
            evidence=[f"文件 {filename}", *names],
            source="perfetto",
        )
    ]


def _cpu_usage(processor, filename: str) -> list[Finding]:
    percent = _cpu_times_percent(processor)
    if percent is None:
        return []
    level = trace_cpu_level(percent)
    if not level:
        return []
    shown = format_percent(percent)
    return [
        Finding(
            id=f"{level.lower()}-cpu-trace-1",
            level=level,
            category="CPU使用率",
            title="CPU 使用率偏高",
            impact="设备级",
            pid="未知",
            process="整机",
            time="trace 内 cpu.times 首尾",
            upgrade="",
            event=f"整机 CPU 使用率 {shown}%",
            evidence=[f"文件 {filename}", f"cpu.times busy={shown}%"],
            source="perfetto",
        )
    ]


def _cpu_times_percent(processor) -> float | None:
    """Device busy ratio from cpu.times deltas. A single sample has no ratio."""
    rows = _query(
        processor,
        """
        SELECT c.track_id AS track_id, ct.name AS name, c.ts AS ts, c.value AS value
        FROM counter c
        JOIN counter_track ct ON c.track_id = ct.id
        WHERE lower(ct.name) GLOB 'cpu.times.*'
        ORDER BY c.track_id, c.ts
        """,
    )
    if not rows:
        return None
    first: dict[int, tuple[int, float, str]] = {}
    last: dict[int, tuple[int, float, str]] = {}
    for row in rows:
        track = int(row.track_id)
        ts = int(row.ts)
        value = float(row.value)
        name = str(row.name or "")
        if track not in first or ts < first[track][0]:
            first[track] = (ts, value, name)
        if track not in last or ts >= last[track][0]:
            last[track] = (ts, value, name)
    idle = 0.0
    total = 0.0
    for track, (ts0, value0, name) in first.items():
        ts1, value1, _name = last[track]
        if ts1 <= ts0:
            continue
        delta = value1 - value0
        if delta < 0:
            continue
        total += delta
        if name.endswith("idle_ns"):
            idle += delta
    if total <= 0 or idle > total:
        return None
    return (total - idle) / total * 100.0
