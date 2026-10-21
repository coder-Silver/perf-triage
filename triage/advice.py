"""Preliminary severity analysis and optimization directions for a trace view."""

from __future__ import annotations

_DIMENSIONS = {
    "ANR": "系统异常",
    "Watchdog": "系统异常",
    "system_server": "系统异常",
    "系统进程崩溃": "系统异常",
    "进程崩溃": "稳定性",
    "异常刷屏": "稳定性",
    "连续掉帧": "显示卡顿",
    "调度": "调度",
    "限频": "功耗",
    "内存压力": "内存",
    "CPU使用率": "CPU 使用率",
}

_ADVICE = {
    "ANR": "在时间线里对齐 ANR 时间点，看主线程是在等锁、Binder 还是自己执行太久。优化方向是把重活移出主线程，缩短输入事件处理。",
    "Watchdog": "系统进程被 Watchdog 盯上，通常是 system_server 主线程或关键锁长时间不返回。优化方向是避免在持锁时做磁盘、网络或大锁等待。",
    "system_server": "system_server 主线程慢操作会拖住整机。优化方向是缩短系统服务在主线程上的工作，避开开机和切换场景的重活。",
    "系统进程崩溃": "系统进程已经崩溃，优先修崩溃再谈性能。优化方向是对照 tombstone 或致命信号，先恢复 system_server 稳定。",
    "进程崩溃": "进程已崩溃。优化方向是先看致命异常栈，修掉崩溃后再看卡顿和调度。",
    "异常刷屏": "同一异常反复打印会占 CPU 和日志。优化方向是修掉循环里的异常，不要在热路径上反复抛出和捕获。",
    "连续掉帧": "交互帧预算被用完。优化方向是拆开 doFrame 里的测量、布局和绘制，减少主线程同步锁。",
    "调度": "主线程有活但长时间分不到 CPU，或陷在不可中断睡眠。优化方向是查同核竞争、优先级和 IO，减少后台线程抢占。",
    "限频": "CPU 频率被压低。优化方向是降低持续满载，给温控留余量，避免长时间顶满大核。",
    "内存压力": "内存压力已经导致查杀或分配失败。优化方向是减缓存、查泄漏，并降低后台常驻内存。",
    "CPU使用率": "CPU 占用偏高。优化方向是找出占满的线程，把重活移出主线程，并降低后台持续占用。",
}

_LEVEL_ORDER = {"P0": 0, "P1": 1, "P2": 2}

_BELOW = "有数据但未达到 P0/P1/P2"

# Log lines from `CPU usage from` are percent of one core over the sample window
# and may exceed 100. cpu.times ratios are device busy/total, on a 0-100 scale.
LOG_CPU_P2 = 80
LOG_CPU_P1 = 150
TRACE_CPU_P2 = 70
TRACE_CPU_P1 = 90


def format_percent(percent: float) -> str:
    if abs(percent - round(percent)) < 0.05:
        return str(int(round(percent)))
    return f"{percent:.1f}"


def log_cpu_level(percent: float) -> str:
    """Grade an Android per-core process percentage. TOTAL is not graded here."""
    if percent >= LOG_CPU_P1:
        return "P1"
    if percent >= LOG_CPU_P2:
        return "P2"
    return ""


def trace_cpu_level(percent: float) -> str:
    """Grade device utilization derived from cpu.times, which is 0-100."""
    if percent >= TRACE_CPU_P1:
        return "P1"
    if percent >= TRACE_CPU_P2:
        return "P2"
    return ""

# A direction is emitted only when one of its signals was actually captured,
# or a graded finding already belongs to it. Absent directions are omitted.
_DIRECTION_SPECS = (
    {
        "id": "memory",
        "title": "内存",
        "signals": ("memory",),
        "categories": frozenset({"内存压力"}),
        "fallback": "减缓存、查泄漏，并降低后台常驻内存。",
    },
    {
        "id": "cpu",
        "title": "CPU 使用率",
        "signals": ("cpu_counter",),
        "categories": frozenset({"CPU使用率"}),
        "fallback": "降低持续满载，减少主线程和后台线程长时间占满 CPU。",
    },
    {
        "id": "frame",
        "title": "显示帧率",
        "signals": ("frame",),
        "categories": frozenset({"连续掉帧"}),
        "fallback": "拆开 doFrame 里的测量、布局和绘制，减少主线程同步锁。",
    },
    {
        "id": "sched",
        "title": "调度",
        "signals": ("sched",),
        "categories": frozenset({"调度"}),
        "fallback": "查同核竞争、优先级和 IO，减少后台线程抢占。",
    },
    {
        "id": "power",
        "title": "限频/功耗",
        "signals": ("freq",),
        "categories": frozenset({"限频"}),
        "fallback": "降低持续满载，给温控留余量，避免长时间顶满大核。",
    },
    {
        "id": "system",
        "title": "系统异常",
        "signals": ("system",),
        "categories": frozenset({"ANR", "Watchdog", "system_server", "系统进程崩溃"}),
        "fallback": "对齐异常时间点，把重活移出主线程，避免持锁时做磁盘、网络或长时间等锁。",
    },
)


def trace_analysis(report: dict | None) -> dict:
    findings = (report or {}).get("findings") or []
    signals = (report or {}).get("signals") if isinstance((report or {}).get("signals"), dict) else {}
    problems = []
    usable = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        usable.append(item)
        category = str(item.get("category") or "")
        evidence = [
            line
            for line in (item.get("evidence") or [])
            if line and not str(line).startswith("文件 ")
        ]
        problems.append(
            {
                "level": item.get("level") or "",
                "process": item.get("process") or "",
                "pid": item.get("pid") or "",
                "dimension": _DIMENSIONS.get(category, category or "其他"),
                "title": item.get("title") or "",
                "event": item.get("event") or "",
                "time": item.get("time") or "",
                "advice": _ADVICE.get(category, "先在时间线里定位该时间点的线程状态，再决定改主线程、调度还是内存。"),
                "evidence": evidence[0] if evidence else "",
            }
        )
    problems.sort(key=lambda item: (_LEVEL_ORDER.get(item["level"], 9), item["process"]))
    summary = (report or {}).get("summary") or {}
    return {
        "summary": summary,
        "upgrade": (report or {}).get("upgrade") or "",
        "problems": problems,
        "directions": _directions(usable, signals),
    }


def _directions(findings: list[dict], signals: dict) -> list[dict]:
    present = []
    for spec in _DIRECTION_SPECS:
        matched = [item for item in findings if str(item.get("category") or "") in spec["categories"]]
        captured = bool(matched) or any(bool(signals.get(key)) for key in spec["signals"])
        if not captured:
            continue
        conclusion, severity = _conclusion(matched)
        present.append(
            {
                "id": spec["id"],
                "title": spec["title"],
                "present": True,
                "conclusion": conclusion,
                "severity": severity,
                "advice": _advice(matched, spec["fallback"]),
                "evidence": _evidence(matched),
            }
        )
    return present


def _conclusion(items: list[dict]) -> tuple[str, str]:
    graded = [item for item in items if str(item.get("level") or "") in _LEVEL_ORDER]
    if not graded:
        return _BELOW, ""
    graded.sort(key=lambda item: (_LEVEL_ORDER.get(str(item.get("level") or ""), 9), str(item.get("process") or "")))
    severity = str(graded[0].get("level") or "")
    parts = []
    for item in graded:
        bits = [
            str(item.get("level") or ""),
            str(item.get("process") or ""),
            str(item.get("event") or item.get("title") or ""),
        ]
        piece = " ".join(bit for bit in bits if bit and bit != "未知")
        if piece and piece not in parts:
            parts.append(piece)
    return f"严重程度 {severity}。{'；'.join(parts[:6])}", severity


def _advice(items: list[dict], fallback: str) -> str:
    lines = []
    for item in items:
        text = _ADVICE.get(str(item.get("category") or ""))
        if text and text not in lines:
            lines.append(text)
    if lines:
        return " ".join(lines)
    return fallback


def _evidence(items: list[dict]) -> list[str]:
    lines = []
    for item in items:
        for line in item.get("evidence") or []:
            text = str(line).strip()
            if not text or text.startswith("文件 "):
                continue
            if text not in lines:
                lines.append(text)
    return lines[:8]
