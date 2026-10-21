"""Keep analyzed Perfetto traces available for the separate viewer page."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .logs import is_trace

CACHE = Path.home() / ".perf-triage" / "trace-cache"


def store_traces(files: list[Path], labels: list[str] | None = None) -> list[dict]:
    if CACHE.exists():
        shutil.rmtree(CACHE)
    CACHE.mkdir(parents=True, exist_ok=True)
    stored = []
    for index, path in enumerate(files):
        if not path.is_file() or not is_trace(path):
            continue
        label = labels[index] if labels and index < len(labels) else path.name
        folder = CACHE / str(len(stored))
        folder.mkdir()
        target = folder / path.name
        shutil.copyfile(path, target)
        stored.append(
            {
                "id": str(len(stored)),
                "name": path.name,
                "label": label,
                "size": target.stat().st_size,
            }
        )
    (CACHE / "manifest.json").write_text(
        json.dumps(stored, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return stored


def list_traces() -> list[dict]:
    manifest = CACHE / "manifest.json"
    if not manifest.is_file():
        return []
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def trace_file(trace_id: str) -> Path | None:
    if not trace_id.isdigit():
        return None
    for item in list_traces():
        if str(item.get("id")) != trace_id:
            continue
        name = Path(str(item.get("name") or "")).name
        if not name or name != item.get("name"):
            return None
        path = (CACHE / trace_id / name).resolve()
        root = (CACHE / trace_id).resolve()
        if root not in path.parents or not path.is_file():
            return None
        return path
    return None


_SECRET_FIELDS = {
    "api_key",
    "apikey",
    "api-key",
    "authorization",
    "token",
    "secret",
    "password",
    "keys",
}
_LEVEL_ORDER = {"P0": 0, "P1": 1, "P2": 2}


def save_analysis(payload: dict) -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    (CACHE / "analysis.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def load_analysis() -> dict:
    return _read_dict(CACHE / "analysis.json") or {}


def save_home_report(report: dict) -> dict:
    """Persist the fields the homepage needs so a new tab can redraw the conclusion."""
    snapshot = public_home_report(report)
    CACHE.mkdir(parents=True, exist_ok=True)
    (CACHE / "report.json").write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return snapshot


def load_home_report() -> dict | None:
    """Return the last successful homepage conclusion, or None when nothing was saved."""
    saved = _read_dict(CACHE / "report.json")
    if isinstance(saved, dict) and isinstance(saved.get("summary"), dict):
        return public_home_report(saved)
    return _home_from_analysis(load_analysis())


def public_home_report(report: dict | None) -> dict:
    source = report if isinstance(report, dict) else {}
    summary = source.get("summary")
    processes = source.get("processes")
    findings = source.get("findings")
    traces = source.get("traces")
    ai_error = source.get("ai_error")
    upgrade = source.get("upgrade")
    path = source.get("path")
    rules_only = source.get("rules_only")
    return {
        "summary": _scrub(summary) if isinstance(summary, dict) else {},
        "upgrade": upgrade if isinstance(upgrade, str) else "",
        "notes": _string_list(source.get("notes")),
        "processes": _scrub(processes) if isinstance(processes, list) else [],
        "findings": _scrub(findings) if isinstance(findings, list) else [],
        "traces": _scrub(traces) if isinstance(traces, list) else [],
        "rules_only": rules_only if isinstance(rules_only, bool) else False,
        "ai_error": ai_error if isinstance(ai_error, str) else None,
        "path": path if isinstance(path, str) else "",
    }


def _home_from_analysis(analysis: dict) -> dict | None:
    """Best-effort conclusion when only the older trace analysis file is on disk."""
    if not analysis or not any(key in analysis for key in ("summary", "problems", "directions")):
        return None
    summary = analysis.get("summary")
    upgrade = analysis.get("upgrade")
    snapshot = {
        "summary": _scrub(summary) if isinstance(summary, dict) else {},
        "upgrade": upgrade if isinstance(upgrade, str) else "",
        "notes": [],
        "processes": _processes_from_problems(analysis.get("problems")),
        "findings": [],
        "traces": list_traces(),
        "ai_error": None,
        "path": "",
    }
    return snapshot


def _processes_from_problems(problems) -> list[dict]:
    if not isinstance(problems, list):
        return []
    grouped: dict[str, dict] = {}
    for item in problems:
        if not isinstance(item, dict):
            continue
        process = str(item.get("process") or "")
        pid = str(item.get("pid") or "")
        key = process or pid or str(item.get("title") or "未知进程")
        level = str(item.get("level") or "")
        current = grouped.get(key)
        if current is None:
            current = {
                "pid": pid,
                "process": process or (f"pid {pid}" if pid else "未知进程"),
                "level": level,
                "problems": [],
            }
            grouped[key] = current
        elif _LEVEL_ORDER.get(level, 9) < _LEVEL_ORDER.get(str(current.get("level") or ""), 9):
            current["level"] = level
        evidence = item.get("evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence] if evidence else []
        elif isinstance(evidence, list):
            evidence = [str(line) for line in evidence if isinstance(line, str) and line]
        else:
            evidence = []
        current["problems"].append(
            {
                "level": level,
                "dimension": str(item.get("dimension") or ""),
                "title": str(item.get("title") or ""),
                "impact": "",
                "time": str(item.get("time") or ""),
                "event": str(item.get("event") or ""),
                "upgrade": "",
                "cause": "",
                "evidence": evidence[:4],
            }
        )
    listed = list(grouped.values())
    listed.sort(
        key=lambda entry: (
            _LEVEL_ORDER.get(str(entry.get("level") or ""), 9),
            str(entry.get("process") or ""),
        )
    )
    return listed


def _read_dict(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _scrub(value):
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if str(key).lower() in _SECRET_FIELDS:
                continue
            cleaned[str(key)] = _scrub(item)
        return cleaned
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None
