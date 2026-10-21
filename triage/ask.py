"""Answer a follow-up from the current graded report."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .providers import chat_completions_url

_GENERIC = ("总结", "有哪些", "什么问题", "哪些问题", "全部", "列出", "概况", "结论", "概述", "为什么")
_LEVELS = ("P0", "P1", "P2")
_DIMENSIONS = {
    "内存": "内存",
    "限频": "功耗",
    "功耗": "功耗",
    "发热": "功耗",
    "掉帧": "显示卡顿",
    "卡顿": "显示卡顿",
    "显示": "显示卡顿",
    "调度": "调度",
    "主线程": "调度",
    "崩溃": "稳定性",
    "异常": "稳定性",
    "刷屏": "稳定性",
    "anr": "系统异常",
    "watchdog": "系统异常",
    "系统": "系统异常",
}


def answer_question(
    report: dict | None,
    question: str,
    history: list[dict],
    base_url: str,
    api_key: str,
    model: str,
) -> dict:
    text = (question or "").strip()
    if not text:
        return {"error": "请输入问题"}
    if report is None:
        return {"error": "请先分析一份日志，再继续提问"}
    local = answer_locally(report, text)
    if not api_key or not model:
        return {"answer": local, "source": "rules"}
    try:
        model_text = _ask_model(report, text, history, base_url, api_key, model)
    except Exception as exc:
        return {
            "answer": local,
            "source": "rules",
            "note": f"模型没有回答，已改用规则结论。{_safe_error(exc, api_key)}",
        }
    if not model_text:
        return {"answer": local, "source": "rules", "note": "模型没有返回内容，已改用规则结论。"}
    return {"answer": model_text, "source": "model"}


def answer_locally(report: dict, question: str) -> str:
    processes = report.get("processes") or []
    if not processes:
        return "这次日志里没有达到 P0 / P1 / P2 的问题进程。"
    chosen = _select(processes, question)
    if not chosen:
        names = "、".join(item["process"] for item in processes[:12])
        return f"这次结论里没有和这个问题对应的证据。有问题的进程是：{names}。"
    lines = ["根据这次的规则结论："]
    for proc in chosen:
        pid = proc.get("pid") or "未知"
        lines.append(f"{proc.get('level')} {proc.get('process')}，pid {pid}")
        for problem in proc.get("problems") or []:
            lines.append(
                f"- {problem.get('level')} {problem.get('dimension')}：{problem.get('title')}。"
                f"{problem.get('event')}。时间 {problem.get('time')}。"
            )
            evidence = [
                line
                for line in (problem.get("evidence") or [])
                if line and not str(line).startswith("文件 ")
            ]
            if evidence:
                lines.append(f"  原文：{evidence[0]}")
    lines.append("以上只转述已经定级的证据，没有调用模型补充原因。")
    return "\n".join(lines)


def _select(processes: list[dict], question: str) -> list[dict]:
    folded = question.casefold()
    levels = {level for level in _LEVELS if level.casefold() in folded}
    dimensions = {name for word, name in _DIMENSIONS.items() if word.casefold() in folded}
    named = [
        proc
        for proc in processes
        if (proc.get("process") and str(proc["process"]).casefold() in folded)
        or (str(proc.get("pid") or "").isdigit() and str(proc["pid"]) in question)
    ]
    pool = named or processes
    if levels:
        pool = [proc for proc in pool if proc.get("level") in levels or _problem_has(proc, "level", levels)]
    if dimensions:
        pool = [proc for proc in pool if _problem_has(proc, "dimension", dimensions)]
    if named or levels or dimensions:
        return pool
    if any(word in question for word in _GENERIC) or len(question.strip()) <= 8:
        return processes
    return []


def _problem_has(proc: dict, field: str, wanted: set[str]) -> bool:
    if field == "level" and proc.get("level") in wanted:
        return True
    return any(problem.get(field) in wanted for problem in proc.get("problems") or [])


def _ask_model(report: dict, question: str, history: list[dict], base_url: str, api_key: str, model: str) -> str:
    brief = []
    for proc in (report.get("processes") or [])[:30]:
        brief.append(
            {
                "level": proc.get("level"),
                "process": proc.get("process"),
                "pid": proc.get("pid"),
                "problems": [
                    {
                        "level": problem.get("level"),
                        "dimension": problem.get("dimension"),
                        "title": problem.get("title"),
                        "event": problem.get("event"),
                        "time": problem.get("time"),
                        "impact": problem.get("impact"),
                        "evidence": (problem.get("evidence") or [])[:2],
                    }
                    for problem in (proc.get("problems") or [])[:6]
                ],
            }
        )
    messages = [
        {
            "role": "system",
            "content": (
                "你是 Android 性能初筛助手。只能根据给定的规则结论回答。"
                "不能补充证据里没有的函数名、线程名或用户操作，也不能改等级。"
                "没有对应证据时直接说这次结论里没有。"
                "用简体中文，先点明进程、pid 和等级。"
            ),
        }
    ]
    for turn in history[-6:]:
        role = "assistant" if turn.get("role") == "assistant" else "user"
        content = str(turn.get("text") or "").strip()
        if content:
            messages.append({"role": role, "content": content[:1200]})
    messages.append(
        {
            "role": "user",
            "content": json.dumps({"question": question, "processes": brief}, ensure_ascii=False),
        }
    )
    request = urllib.request.Request(
        chat_completions_url(base_url),
        data=json.dumps(
            {"model": model, "temperature": 0.2, "messages": messages},
            ensure_ascii=False,
        ).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.loads(response.read().decode("utf-8"))
    content = body["choices"][0]["message"].get("content") or ""
    return str(content).strip()


def _safe_error(exc: Exception, secret: str) -> str:
    text = str(exc)
    if secret:
        text = text.replace(secret, "****")
    return " ".join(text.split())[:180]
