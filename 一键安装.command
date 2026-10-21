#!/bin/bash
# Mac 一键安装并启动。首次需要能访问网络，用来安装 Python 依赖并下载 trace 分析组件。
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
export PYTHONUNBUFFERED=1

echo "性能初筛：正在准备 Mac 运行环境"

if ! command -v python3 >/dev/null 2>&1; then
  echo "没有找到 python3。请先安装 Python 3.11 或更新版本：https://www.python.org/downloads/macos/"
  echo "安装完成后，再双击本文件。"
  read -r -p "按回车关闭..." _
  exit 1
fi

PY="$ROOT/vendor/mac-venv/bin/python3"
if [[ ! -x "$PY" ]]; then
  echo "正在创建本机运行环境（只需第一次）"
  python3 -m venv "$ROOT/vendor/mac-venv"
  "$PY" -m pip install --upgrade pip
  "$PY" -m pip install -r "$ROOT/requirements.txt"
fi

if ! "$PY" -c "import perfetto.trace_processor" >/dev/null 2>&1; then
  echo "正在安装分析依赖（只需第一次）"
  "$PY" -m pip install -r "$ROOT/requirements.txt"
fi

SHELL_BIN="$ROOT/vendor/trace_processor_shell"
if [[ ! -x "$SHELL_BIN" ]]; then
  ARCH="$(uname -m)"
  case "$ARCH" in
    arm64)
      URL="https://commondatastorage.googleapis.com/perfetto-luci-artifacts/v57.2/mac-arm64/trace_processor_shell"
      SHA="98a41b80e9f60da0373d64aff6455681f8c26b7c391ae5736324a5b11e3dacc2"
      ;;
    x86_64)
      URL="https://commondatastorage.googleapis.com/perfetto-luci-artifacts/v57.2/mac-amd64/trace_processor_shell"
      SHA="c0f61397901da47cbe1bb9a0843624f7c2038ac92176ce15e3736ce9aa0afef0"
      ;;
    *)
      echo "不支持的 Mac 架构：$ARCH"
      read -r -p "按回车关闭..." _
      exit 1
      ;;
  esac
  echo "正在下载调度分析组件（只需第一次）"
  mkdir -p "$ROOT/vendor"
  curl -fL --retry 3 -o "$SHELL_BIN.partial" "$URL"
  echo "$SHA  $SHELL_BIN.partial" | shasum -a 256 -c -
  mv "$SHELL_BIN.partial" "$SHELL_BIN"
  chmod +x "$SHELL_BIN"
fi

if curl -fsS --max-time 2 http://127.0.0.1:8765/api/config >/dev/null 2>&1; then
  PIDS="$(lsof -tiTCP:8765 -sTCP:LISTEN || true)"
  if [[ -n "$PIDS" ]]; then
    kill $PIDS || true
    sleep 1
  fi
fi

echo "正在打开 http://127.0.0.1:8765"
exec "$PY" "$ROOT/server.py"
