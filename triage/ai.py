"""Ask an OpenAI-compatible API to explain already graded evidence."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .models import Finding
from .providers import chat_completions_url


def explain(findings: list[Finding], base_url: str, api_key: str, model: str) -> str | None:
    if not findings:
        return None
    if not api_key or not model:
        return None

    payload_items = [
        {
            "id": item.id,
            "level": item.level,
            "category": item.category,
            "title": item.title,
            "impact": item.impact,
            "pid": item.pid,
            "process": item.process,
            "time": item.time,
            "upgrade": item.upgrade,
            "event": item.event,
            "logs": [line for line in item.evidence if line and not line.startswith("文件 ")][:8],
        }
        for item in findings[:40]
    ]
    prompt = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你正在阅读 Android 日志原文，并按已经判定的等级写出分析结论。"
                    "每条的 level 由规则确定，不能改成别的等级，也不能新增或删除条目。"
                    "cause 必须依据该条 logs 里的原文：说明现象、点明进程和 pid，并给出规则允许的原因。"
                    "原文没有的函数名、线程名或用户操作不要写。"
                    "证据不足时写「证据只能支持到现象」。用简体中文。"
                    "只返回 JSON：{\"items\":[{\"id\":\"...\",\"cause\":\"...\"}]}。"
                ),
            },
            {"role": "user", "content": json.dumps({"logs": payload_items}, ensure_ascii=False)},
        ],
    }
    url = chat_completions_url(base_url)
    request = urllib.request.Request(
        url,
        data=json.dumps(prompt, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        _fallback(findings)
        return f"模型接口返回 {exc.code}：{detail}"
    except Exception as exc:
        _fallback(findings)
        return f"模型接口调用失败：{exc}"

    content = ""
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        _fallback(findings)
        return "模型没有返回可解析的内容。"
    parsed = _extract_json(content)
    causes = {}
    if isinstance(parsed, dict):
        for entry in parsed.get("items", []):
            if isinstance(entry, dict) and entry.get("id"):
                causes[str(entry["id"])] = str(entry.get("cause") or "").strip()
    if not causes:
        _fallback(findings)
        return "模型返回无法对应到具体问题，已保留规则证据。"
    for item in findings:
        item.cause = causes.get(item.id) or "模型没有解释这一条。等级仍以规则证据为准。"
    return None


def _fallback(findings: list[Finding]) -> None:
    for item in findings:
        if not item.cause:
            item.cause = "模型解释失败。等级、进程、时间和原文证据仍然有效。"


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[: text.rfind("```")]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
    return None
