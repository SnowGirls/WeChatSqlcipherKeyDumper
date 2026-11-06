#!/usr/bin/env bash
# 用法:   bash src/weixin-key-dumper/build-dylib.sh
# 作用:   构建并 ad-hoc 签名本目录的抓取 dylib（__DATA,__interpose + fishhook 两层挂钩）。
# 输入:   weixin-key-dumper.c、fishhook.c、fishhook.h（均在本目录）
# 产出:   WeChatSqlcipherKeyDumper/build/weixin-key-dumper.dylib
# 下一步: bash src/weixin-key-dumper/test-dylib.sh    # 离线验证 fishhook 层，不启动WeChat
#         bash src/weixin-key-dumper/run-dyld.sh     # DYLD 注入启动工作区WeChat副本
# 配合:   src/inject/build-inject.sh 提供 LC_LOAD_DYLIB 注入方式；
#         bash scripts/build-runtime.sh 准备工作区运行副本。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
OUT="$ROOT/build/weixin-key-dumper.dylib"

mkdir -p "$ROOT/build"

CLANG="clang"
if command -v xcrun >/dev/null 2>&1; then
    CLANG="xcrun --sdk macosx clang"
fi

$CLANG -dynamiclib -O2 -arch arm64 -arch x86_64 \
    -Wl,-undefined,dynamic_lookup \
    -Wl,-weak_reference_mismatches,weak \
    -o "$OUT" "$DIR/weixin-key-dumper.c" "$DIR/fishhook.c"

codesign -f -s - "$OUT"
codesign --verify --strict "$OUT"
echo "built: $OUT"
echo
echo "checks:"
otool -l "$OUT" | grep -A3 -i '__interpose' || true
nm -gU "$OUT" | grep wx_rebind_symbols || true
