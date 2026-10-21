"""Pinned OpenAI-compatible providers. The server, page, and tests share this list."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ProviderModel:
    group: str
    id: str
    label: str
    base_url: str

    def as_dict(self) -> dict:
        return {
            "group": self.group,
            "id": self.id,
            "label": self.label,
            "base_url": self.base_url,
        }


# Official OpenAI-compatible endpoints checked on 2026-10-20.
# DeepSeek retired deepseek-chat / deepseek-reasoner on 2026-07-24.
# Kimi retired the K2 and moonshot-v1 series; kimi-k3 is the current model.
PROVIDERS: tuple[ProviderModel, ...] = (
    ProviderModel("DeepSeek", "deepseek-flash", "DeepSeek Flash", "https://api.deepseek.com"),
    ProviderModel("DeepSeek", "deepseek-v4-pro", "DeepSeek V4 Pro", "https://api.deepseek.com"),
    ProviderModel("Kimi", "kimi-k3", "Kimi K3", "https://api.moonshot.cn/v1"),
    ProviderModel("智谱", "glm-4-flash", "智谱 GLM-4-Flash", "https://open.bigmodel.cn/api/paas/v4"),
    ProviderModel("智谱", "glm-4.6", "智谱 GLM-4.6", "https://open.bigmodel.cn/api/paas/v4"),
    ProviderModel("GPT", "gpt-5-mini", "GPT-5 mini", "https://api.openai.com/v1"),
    ProviderModel("GPT", "gpt-4.1", "GPT-4.1", "https://api.openai.com/v1"),
    ProviderModel("通义千问", "qwen-plus", "通义千问 Plus", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
)

DEFAULT_MODEL_ID = "deepseek-flash"
_BY_ID = {item.id: item for item in PROVIDERS}


def resolve_model(model_id: str) -> ProviderModel | None:
    return _BY_ID.get((model_id or "").strip())


def default_model() -> ProviderModel:
    return _BY_ID[DEFAULT_MODEL_ID]


def host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return (parsed.hostname or "").lower()


def chat_completions_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"
