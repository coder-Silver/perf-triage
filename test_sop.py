"""Cross-checks for grading, provider binding, and model explanations."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import server
from test_logs import SAMPLE, SPAM, test_grades
from triage.ai import explain
from triage.analyze import analyze_paths
from triage.models import Finding
from triage.probe import probe_model, redact
from triage.providers import PROVIDERS, chat_completions_url, resolve_model

EXPECTED_PAIRS = {
    "deepseek-flash": "https://api.deepseek.com",
    "deepseek-v4-pro": "https://api.deepseek.com",
    "kimi-k3": "https://api.moonshot.cn/v1",
    "glm-4-flash": "https://open.bigmodel.cn/api/paas/v4",
    "glm-4.6": "https://open.bigmodel.cn/api/paas/v4",
    "gpt-5-mini": "https://api.openai.com/v1",
    "gpt-4.1": "https://api.openai.com/v1",
    "qwen-plus": "https://dashscope.aliyuncs.com/compatible-mode/v1",
}


def test_provider_catalog() -> None:
    ids = [item.id for item in PROVIDERS]
    assert len(ids) == len(set(ids))
    assert {item.id: item.base_url for item in PROVIDERS} == EXPECTED_PAIRS
    assert resolve_model("deepseek-chat") is None
    assert resolve_model("nope") is None
    for model_id, base in EXPECTED_PAIRS.items():
        assert chat_completions_url(base).endswith("/chat/completions")
        assert chat_completions_url(base).count("/chat/completions") == 1
        assert resolve_model(model_id).base_url == base


def test_server_binds_address_and_keeps_keys_apart() -> None:
    with tempfile.TemporaryDirectory() as folder:
        server.CONFIG = Path(folder) / "config.json"
        try:
            server.save_config({"model": "kimi-k3", "base_url": "https://evil.example/v1", "api_key": "sk-kimi-test"})
        except Exception:
            raise
        stored = json.loads(server.CONFIG.read_text(encoding="utf-8"))
        assert stored["base_url"] == "https://api.moonshot.cn/v1"
        assert stored["model"] == "kimi-k3"
        assert stored["keys"]["api.moonshot.cn"] == "sk-kimi-test"
        assert "api_key" not in stored
        public = server.public_config(server.load_config())
        assert public["has_key"] is True
        assert "sk-kimi-test" not in json.dumps(public)
        server.save_config({"model": "deepseek-flash", "api_key": "sk-deepseek-test"})
        deepseek = server.public_config(server.load_config())
        assert deepseek["base_url"] == "https://api.deepseek.com"
        assert deepseek["has_key"] is True
        server.save_config({"model": "glm-4-flash"})
        zhipu = server.public_config(server.load_config())
        assert zhipu["base_url"] == "https://open.bigmodel.cn/api/paas/v4"
        assert zhipu["has_key"] is False
        server.save_config({"model": "kimi-k3"})
        assert server.public_config(server.load_config())["has_key"] is True
        try:
            server.save_config({"model": "deepseek-chat"})
            raise AssertionError("retired model id was accepted")
        except server.ConfigError:
            pass
    print("provider binding ok")


def test_explain_attaches_only_matching_ids() -> None:
    findings = [
        Finding("p0-1", "P0", "ANR", "ANR", "应用", "1", "app", "t", "", "ANR", ["line"]),
        Finding("p1-2", "P1", "崩溃", "崩溃", "应用", "2", "app", "t", "", "crash", ["line"]),
    ]

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            body = {"choices": [{"message": {"content": json.dumps({
                "items": [
                    {"id": "p0-1", "cause": "窗口内有 ANR 原文"},
                    {"id": "missing", "cause": "不应写到别的问题上"},
                ]
            }, ensure_ascii=False)}}]}
            return json.dumps(body).encode()

    with patch("triage.ai.urllib.request.urlopen", return_value=Response()):
        error = explain(findings, "https://api.deepseek.com", "sk-test", "deepseek-flash")
    assert error is None
    assert findings[0].cause == "窗口内有 ANR 原文"
    assert findings[1].cause == "模型没有解释这一条。等级仍以规则证据为准。"
    print("explain binding ok")


def test_sample_report_matches_rules_without_model() -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(SAMPLE + "\n" + SPAM, encoding="utf-8")
        report = analyze_paths([path], "https://api.deepseek.com", "", "deepseek-flash")
    kinds = {(item["level"], item["category"]) for item in report["findings"]}
    assert kinds == {
        ("P0", "ANR"),
        ("P0", "Watchdog"),
        ("P0", "system_server"),
        ("P1", "进程崩溃"),
        ("P1", "异常刷屏"),
        ("P1", "连续掉帧"),
        ("P2", "限频"),
        ("P2", "内存压力"),
    }
    anr = next(item for item in report["findings"] if item["category"] == "ANR")
    assert anr["pid"] == "1234"
    assert "RQ1A.210105.003" in anr["upgrade"]
    assert "升级" in anr["upgrade"]
    crash = next(item for item in report["findings"] if item["category"] == "进程崩溃")
    assert "com.demo.game" in crash["impact"]
    assert all(item["cause"] == "" for item in report["findings"])
    assert report["rules_only"] is True
    assert report["processes"]
    assert report["ai_error"] is None
    print("sample cross-check ok", report["summary"])


def test_probe_reports_success_and_hides_key() -> None:
    secret = "sk-secret-value"
    assert secret not in redact(f"bad key {secret}", secret)

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

    with patch("triage.probe.urllib.request.urlopen", return_value=Response()):
        result = probe_model("https://api.deepseek.com", secret, "deepseek-flash")
    assert result["ok"] is True
    assert secret not in result["message"]

    class Denied(Exception):
        pass

    import urllib.error

    def raise_denied(*args, **kwargs):
        raise urllib.error.HTTPError(
            "https://api.deepseek.com/chat/completions",
            401,
            "Unauthorized",
            hdrs=None,
            fp=__import__("io").BytesIO(f"invalid {secret}".encode()),
        )

    with patch("triage.probe.urllib.request.urlopen", side_effect=raise_denied):
        failed = probe_model("https://api.deepseek.com", secret, "deepseek-flash")
    assert failed["ok"] is False
    assert "密钥无效" in failed["message"]
    assert secret not in failed["message"]
    print("probe feedback ok")


if __name__ == "__main__":
    test_grades()
    test_provider_catalog()
    test_server_binds_address_and_keeps_keys_apart()
    test_explain_attaches_only_matching_ids()
    test_sample_report_matches_rules_without_model()
    test_probe_reports_success_and_hides_key()
    print("all sop checks passed")
