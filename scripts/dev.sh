#!/usr/bin/env bash
# 本地调试：不配置 FNGATE_SOCKET，自动回退到 127.0.0.1:9583 便于浏览器访问。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v go >/dev/null 2>&1; then
  for cand in /c/Go/bin/go /usr/local/go/bin/go "$HOME/go/bin/go"; do
    [ -x "$cand" ] && export PATH="$(dirname "$cand"):$PATH" && break
  done
fi
mkdir -p "$ROOT/.localdata"
export FNGATE_DATA_DIR="$ROOT/.localdata"
export FNGATE_LOG_LEVEL="${FNGATE_LOG_LEVEL:-DEBUG}"
cd "$ROOT/src"
exec go run . --web-port "${1:-9583}"
