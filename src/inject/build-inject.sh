#!/usr/bin/env bash
# 用法:   bash src/inject/build-inject.sh
# 作用:   构建 LC_LOAD_DYLIB 头部空隙注入器，用于把 weixin-key-dumper.dylib 写进副本主可执行文件。
# 输入:   inject.c（本目录）
# 产出:   WeChatSqlcipherKeyDumper/build/inject
# 前置:   先运行 src/weixin-key-dumper/build-dylib.sh 得到 WeChatSqlcipherKeyDumper/build/weixin-key-dumper.dylib
# 下一步: 按 docs/实现-获取WeChat本地数据库-WCDB-SQLCipher-密钥.md 第 5.1 节替换副本可执行文件并重签。
# 配合:   src/weixin-key-dumper/build-dylib.sh（dylib）；日常 DYLD 启动用 src/weixin-key-dumper/run-dyld.sh，无需本注入器。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
OUT="$ROOT/build/inject"

mkdir -p "$ROOT/build"

CLANG="clang"
if command -v xcrun >/dev/null 2>&1; then
    CLANG="xcrun --sdk macosx clang"
fi

$CLANG -O2 -o "$OUT" "$DIR/inject.c"
echo "built: $OUT"
