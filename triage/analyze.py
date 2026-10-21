"""Combine log files and Perfetto traces into one graded report."""

from __future__ import annotations

from pathlib import Path

from .ai import explain
from .logs import is_text_log, is_trace, looks_like_log, scan_text_file
from .models import Finding
from .trace import scan_trace

MAX_FILE_BYTES = 512 * 1024 * 1024
_SIGNAL_KEYS = ("memory", "cpu_counter", "sched", "freq", "frame", "system")
_CATEGORY_SIGNAL = {
    "内存压力": "memory",
    "连续掉帧": "frame",
    "调度": "sched",
    "限频": "freq",
    "CPU使用率": "cpu_counter",
    "ANR": "system",
    "Watchdog": "system",
    "system_server": "system",
    "系统进程崩溃": "system",
}


def analyze_paths(
    paths: list[Path],
    base_url: str,
    api_key: str,
    model: str,
    labels: list[str] | None = None,
    prep_notes: list[str] | None = None,
) -> dict:
    findings: list[Finding] = []
    notes: list[str] = list(prep_notes or [])
    flames: list[dict] = []
    used: list[str] = []
    version = ""
    ota: list[str] = []
    signals = {key: False for key in _SIGNAL_KEYS}

    for index, path in enumerate(paths):
        try:
            size = path.stat().st_size
        except OSError as exc:
            notes.append(f"无法读取 {path}: {exc}")
            continue
        if size > MAX_FILE_BYTES:
            notes.append(f"跳过 {path.name}，文件超过 512MB。")
            continue
        used.append(labels[index] if labels and index < len(labels) else path.name)
        if is_trace(path):
            trace_findings, trace_notes, flame, trace_signals = scan_trace(path)
            findings.extend(trace_findings)
            notes.extend(trace_notes)
            _merge_signals(signals, trace_signals)
            if flame and flame.get("root"):
                flames.append(flame)
            continue
        if is_text_log(path) or looks_like_log(path):
            file_findings, meta = scan_text_file(path)
            findings.extend(file_findings)
            _merge_signals(signals, meta.get("signals"))
            if meta.get("version") and not version:
                version = meta["version"]
            ota.extend(meta.get("ota") or [])

    upgrade = _upgrade(version, ota)
    for item in findings:
        if not item.upgrade or item.upgrade.startswith("日志中未找到"):
            item.upgrade = upgrade
        if item.level == "P0":
            item.impact = f"{item.impact}；pid {item.pid}；{item.upgrade}"

    findings = _dedupe(findings)
    for item in findings:
        key = _CATEGORY_SIGNAL.get(item.category)
        if key:
            signals[key] = True
    for index, item in enumerate(findings, start=1):
        item.id = f"{item.level.lower()}-{index}"

    ai_error = explain(findings, base_url, api_key, model)
    counts = {"P0": 0, "P1": 0, "P2": 0}
    for item in findings:
        counts[item.level] = counts.get(item.level, 0) + 1
    return {
        "summary": {
            "p0": counts["P0"],
            "p1": counts["P1"],
            "p2": counts["P2"],
            "files": len(used),
        },
        "upgrade": upgrade,
        "notes": [note for note in notes if _is_problem_note(note)],
        "files": used,
        "findings": [item.to_dict() for item in findings],
        "processes": _problem_processes(findings),
        "flames": flames,
        "signals": signals,
        "ai_error": ai_error,
        "rules_only": not bool(api_key and model),
    }


def _merge_signals(base: dict, extra) -> None:
    if not isinstance(extra, dict):
        return
    for key in _SIGNAL_KEYS:
        if extra.get(key):
            base[key] = True


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
_LEVEL_ORDER = {"P0": 0, "P1": 1, "P2": 2}


def _is_problem_note(note: str) -> bool:
    return any(word in note for word in ("无法", "失败", "超过", "不安全", "加密"))


def _problem_processes(findings: list[Finding]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for item in findings:
        if item.process and ("." in item.process or item.process in {"system_server", "system"}):
            key = "name:" + item.process
        elif str(item.pid).isdigit():
            key = "pid:" + str(item.pid)
        else:
            key = item.process or item.id
        current = grouped.get(key)
        if current is None:
            current = {
                "pid": item.pid,
                "process": item.process or "",
                "level": item.level,
                "problems": [],
            }
            grouped[key] = current
        if _LEVEL_ORDER.get(item.level, 9) < _LEVEL_ORDER.get(current["level"], 9):
            current["level"] = item.level
        if _better_process_name(item.process, current["process"]):
            current["process"] = item.process
        current["problems"].append(
            {
                "level": item.level,
                "dimension": _DIMENSIONS.get(item.category, item.category),
                "title": item.title,
                "impact": item.impact,
                "time": item.time,
                "event": item.event,
                "upgrade": item.upgrade if item.level == "P0" else "",
                "cause": item.cause,
                "evidence": item.evidence[:4],
            }
        )
    processes = list(grouped.values())
    for item in processes:
        item["problems"].sort(key=lambda problem: _LEVEL_ORDER.get(problem["level"], 9))
        if not item["process"]:
            item["process"] = f"pid {item['pid']}"
    processes.sort(key=lambda item: (_LEVEL_ORDER.get(item["level"], 9), item["process"]))
    return processes


def _better_process_name(candidate: str, current: str) -> bool:
    if not candidate or candidate == current:
        return False
    if not current or current.startswith("pid "):
        return True
    return "." in candidate and "." not in current


def _upgrade(version: str, ota: list[str]) -> str:
    parts = []
    if version:
        parts.append(f"版本 {version}")
    if ota:
        parts.append("升级记录 " + ota[0][:180])
    return "；".join(parts) if parts else "日志中未找到版本或升级记录"


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple, Finding] = {}
    for item in findings:
        key = (item.level, item.category, item.pid, item.event)
        current = seen.get(key)
        if current is None:
            seen[key] = item
            continue
        for line in item.evidence:
            if line not in current.evidence and len(current.evidence) < 6:
                current.evidence.append(line)
    order = {"P0": 0, "P1": 1, "P2": 2}
    return sorted(seen.values(), key=lambda item: (order.get(item.level, 9), item.category, item.pid))
