#!/usr/bin/env bash
# 用法:   bash src/weixin-key-dumper/test-dylib.sh
# 作用:   构建假 SQLite 动态库 + test-host，验证 fishhook 是否改写了符号槽并转发原函数。
# 输入:   test-fixtures/test-host.c、test-fixtures/test-sqlite.c（本目录下）、weixin-key-dumper.c、fishhook.c
# 产出:   build/test-host、build/libtest-sqlite.dylib、build/test-dylib/{tmp,dump}
# 下一步: 检查输出的 hooks/keys；通过后可用 src/weixin-key-dumper/run-dyld.sh 做真机注入。
# 配合:   先由 src/weixin-key-dumper/build-dylib.sh 生成本次验证所用的 weixin-key-dumper.dylib。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BUILD="$ROOT/build"
HOME_DIR="$BUILD/test-dylib"
DUMP_DIR="$BUILD/test-dylib/dump"

bash "$ROOT/src/weixin-key-dumper/build-dylib.sh" >/dev/null

CLANG="clang"
if command -v xcrun >/dev/null 2>&1; then
    CLANG="xcrun --sdk macosx clang"
fi

$CLANG -dynamiclib -O2 -o "$BUILD/libtest-sqlite.dylib" "$DIR/test-fixtures/test-sqlite.c"
$CLANG -O2 -o "$BUILD/test-host" "$DIR/test-fixtures/test-host.c" \
    -L"$BUILD" -ltest-sqlite -Wl,-rpath,@loader_path

rm -f "$HOME_DIR/tmp/weixin-key-dumper.log" "$HOME_DIR/tmp/wechat_db_keys.json"
mkdir -p "$HOME_DIR/tmp" "$DUMP_DIR"

HOME="$HOME_DIR" WX_DUMP_DIR="$DUMP_DIR" \
DYLD_INSERT_LIBRARIES="$BUILD/weixin-key-dumper.dylib" \
    "$BUILD/test-host"

echo
echo "--- hooks ---"
grep -E 'fishhook (sqlite3_key|sql)|addr CCCrypt' "$HOME_DIR/tmp/weixin-key-dumper.log" || true
echo "--- keys ---"
cat "$HOME_DIR/tmp/wechat_db_keys.json"
