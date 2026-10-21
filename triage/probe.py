"""Check that a saved API key can get a response from the selected model."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .providers import chat_completions_url


def redact(text: str, secret: str) -> str:
    cleaned = text or ""
    if secret:
        cleaned = cleaned.replace(secret, "****")
    return " ".join(cleaned.split())[:240]


def probe_model(base_url: str, api_key: str, model: str, timeout: float = 20) -> dict:
    if not api_key:
        return {"ok": False, "message": "还没有填写 API Key", "latency_ms": 0}
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 8,
        "temperature": 0,
    }
    request = urllib.request.Request(
        chat_completions_url(base_url),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        detail = redact(exc.read().decode("utf-8", errors="replace"), api_key)
        return {
            "ok": False,
            "message": _http_message(exc.code, detail),
            "latency_ms": _elapsed(started),
        }
    except Exception as exc:
        return {
            "ok": False,
            "message": f"无法连接模型服务：{redact(str(exc), api_key)}",
            "latency_ms": _elapsed(started),
        }
    latency = _elapsed(started)
    if status >= 400:
        return {"ok": False, "message": _http_message(status, redact(raw, api_key)), "latency_ms": latency}
    try:
        body = json.loads(raw)
        content = body["choices"][0]["message"].get("content")
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        content = None
    if content is None and "choices" not in raw:
        return {"ok": False, "message": "服务有返回，但不是对话接口的响应", "latency_ms": latency}
    return {"ok": True, "message": f"可用，模型已响应，耗时 {latency} ms", "latency_ms": latency}


def _elapsed(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _http_message(status: int, detail: str) -> str:
    if status in (401, 403):
        return f"不可用：密钥无效或没有权限（HTTP {status}）"
    if status == 404:
        return f"不可用：这个地址或模型不存在（HTTP 404）{(' ' + detail) if detail else ''}"
    if status == 429:
        return "密钥能连上，但当前被限流，请稍后再试"
    return f"不可用：HTTP {status} {detail}".strip()
