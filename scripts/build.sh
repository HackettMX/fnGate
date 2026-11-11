#!/usr/bin/env bash
# 构建 fnGate 原生二进制并打包为 .fpk（无需 Docker）
# 用法：bash build.sh [版本号] [架构]
#   例：bash build.sh 1.0.0              # 默认构建 amd64 + arm64 + arm
#       bash build.sh 1.0.0 amd64        # 只构建单一架构
set -euo pipefail

# build.sh 位于 scripts/ 下，项目根为其上级目录
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# 在常见位置探测 go（Windows 上多装在 C:/Go/bin），避免依赖 PATH
if ! command -v go >/dev/null 2>&1; then
  for cand in /c/Go/bin/go /usr/local/go/bin/go "$HOME/go/bin/go"; do
    [ -x "$cand" ] && export PATH="$(dirname "$cand"):$PATH" && break
  done
fi
command -v go >/dev/null 2>&1 || { echo "!! 未找到 go，请先安装 Go 1.21+" >&2; exit 1; }

MANIFEST_VERSION="$(sed -n 's/^version="\(.*\)"/\1/p' fpk/manifest | head -n1)"
VERSION="${1:-${MANIFEST_VERSION:-1.0.0}}"
ARCH_ARG="${2:-all}"
case "$ARCH_ARG" in
  all | "") ARCHES=(amd64 arm64 arm) ;;
  amd64 | x86_64) ARCHES=(amd64) ;;
  arm64 | aarch64) ARCHES=(arm64) ;;
  arm | armv7 | armv7l) ARCHES=(arm) ;;
  *) echo "!! 不支持的架构：$ARCH_ARG（可选 amd64 / arm64 / arm / all）" >&2; exit 1 ;;
esac

# fnOS 桌面/应用中心是按「图标文件路径」做前端缓存的：只要路径不变，换了图片内容
# 也照样显示旧图（飞牛社区与多个 fNOS 应用的实机结论）。这里按版本号生成新的
# 图标文件名并改写 ui/config，让缓存 key 自然失效，无需用户清浏览器缓存。
#   1.0.0 -> images/icon_v1_0_0_{0}.png -> icon_v1_0_0_64.png / icon_v1_0_0_256.png
ICON_TAG="$(printf '%s' "$VERSION" | sed 's/[^0-9A-Za-z]/_/g')"
ICON_DIR="fpk/app/ui/images"
# 清掉历史版本留下的 icon_v*，否则每次发版都会把旧图标一起打进包。
rm -f "${ICON_DIR}"/icon_v*_64.png "${ICON_DIR}"/icon_v*_256.png
for sz in 64 256; do
  if [ -f "${ICON_DIR}/icon_${sz}.png" ]; then
    cp -f "${ICON_DIR}/icon_${sz}.png" "${ICON_DIR}/icon_v${ICON_TAG}_${sz}.png"
  else
    echo "!! 缺少图标源文件 ${ICON_DIR}/icon_${sz}.png" >&2
    exit 1
  fi
done
sed -i -E "s#\"icon\": *\"images/[^\"]*\"#\"icon\": \"images/icon_v${ICON_TAG}_{0}.png\"#" fpk/app/ui/config
echo "==> 图标路径已版本化：images/icon_v${ICON_TAG}_{0}.png"

echo "==> 编译 fnGate ${VERSION}（linux/${ARCHES[*]}，静态链接）"
mkdir -p fpk/app/bin dist
rm -f fpk/app/bin/fngate fpk/app/bin/fngate-*
for GOARCH in "${ARCHES[@]}"; do
  # 32 位 ARM 按 GOARM=6 编译：ARMv6 是 ARMv7 的指令子集，一份二进制同时能跑
  # armv6l 与 armv7l；反之 GOARM=7 的 UDIV/DMB 在 armv6 上会 illegal instruction。
  GOARM_ARG=""
  [ "$GOARCH" = "arm" ] && GOARM_ARG="GOARM=6"
  echo "    -> linux/${GOARCH}${GOARM_ARG:+ ($GOARM_ARG)}"
  env CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH}" ${GOARM_ARG} \
    go build -C src -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${ROOT}/fpk/app/bin/fngate-${GOARCH}" .
done

# Windows 上无法保留 Unix 执行位，这里显式设置；CI 在 Linux 上同样需要
chmod +x fpk/app/bin/fngate-* fpk/cmd/*

echo "==> 查找 fnpack"
FNPACK="$(command -v fnpack || true)"
if [ -z "${FNPACK}" ] && [ -x .tools/fnpack.exe ]; then FNPACK=".tools/fnpack.exe"; fi
if [ -z "${FNPACK}" ] && [ -x .tools/fnpack ]; then FNPACK=".tools/fnpack"; fi
if [ -z "${FNPACK}" ]; then
  echo "!! 未找到 fnpack，请从 https://developer.fnnas.com/docs/cli/fnpack/ 下载放到 .tools/ 或加入 PATH"
  exit 1
fi

echo "==> 打包 .fpk"
"${FNPACK}" build -d fpk

echo "==> 修正权限位与 manifest checksum"
PYTHON="$(command -v python3 || command -v python || true)"
[ -n "${PYTHON}" ] || { echo "!! 需要 python 来修正权限位"; exit 1; }
"${PYTHON}" scripts/fix_fpk_perms.py fngate.fpk

mv -f fngate.fpk "dist/fngate-${VERSION}.fpk"
echo ""
echo "==> 完成：dist/fngate-${VERSION}.fpk"
ls -lh "dist/fngate-${VERSION}.fpk"
