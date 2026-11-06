#!/usr/bin/env bash
# 用法:   bash src/wechat-key-dumper/build-dylib.sh
# 作用:   构建并 ad-hoc 签名 fishhook dumper（arm64 + x86_64）。
# 输入:   wechat-key-dumper.c
# 产出:   WeChatSqlcipherKeyDumper/build/wechat-key-dumper.dylib
# 下一步: 用 DYLD_INSERT_LIBRARIES 注入WeChat副本。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
OUT="$ROOT/build/wechat-key-dumper.dylib"

mkdir -p "$ROOT/build"

if ! command -v xcrun >/dev/null 2>&1; then
  echo "error: xcrun not found; install Xcode Command Line Tools first" >&2
  exit 1
fi

if ! MACOS_SDK="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)"; then
  echo "error: macOS SDK not found; install Xcode Command Line Tools first" >&2
  exit 1
fi

xcrun --sdk macosx clang \
  -isysroot "$MACOS_SDK" \
  -dynamiclib \
  -O2 \
  -fvisibility=hidden \
  -o "$OUT" \
  "$DIR/wechat-key-dumper.c" \
  -arch arm64 -arch x86_64 \
  -mmacosx-version-min=11.0

codesign -f -s - "$OUT"
codesign --verify --strict "$OUT"
echo "built: $OUT"
