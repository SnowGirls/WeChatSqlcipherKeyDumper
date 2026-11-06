#!/usr/bin/env bash
# 用法:   bash src/weixin-key-dumper/run-dyld.sh
# 作用:   通过 DYLD_INSERT_LIBRARIES 启动工作区WeChat副本，并加载 weixin-key-dumper.dylib。
# 前置:   bash src/weixin-key-dumper/build-dylib.sh 已成功；bash scripts/build-runtime.sh 已准备好工作区副本；
#         完全退出WeChat（单实例锁会让副本不开库），WeChat 升级后需重建副本。
# 产出:   ${WX_DUMP_DIR:-WeChatSqlcipherKeyDumper/out}/wechat_db_keys.json、xwechat_files/、weixin-key-dumper.log
#         沙箱拒绝写入时，dumper 启动探测会自动回退到 ~/Downloads
# 下一步: 直接消费 out/；下游解密按 wechat_db_keys.json 的 salt 取 key
# 配合:   运行副本与重签见 docs/实现-获取WeChat本地数据库-WCDB-SQLCipher-密钥.md 第 3、5 节。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DYLIB="$ROOT/build/weixin-key-dumper.dylib"
APP="$ROOT/runtime/WeChat.app/Contents/MacOS/WeChat"
DUMP_DIR="${WX_DUMP_DIR:-$ROOT/out}"

if [ ! -x "$APP" ]; then
    echo "missing runtime copy: $APP" >&2
    echo "create it first (see docs/实现-获取WeChat本地数据库-WCDB-SQLCipher-密钥.md section 3)" >&2
    exit 1
fi
if [ ! -f "$DYLIB" ]; then
    echo "missing dylib: $DYLIB (run src/weixin-key-dumper/build-dylib.sh)" >&2
    exit 1
fi

mkdir -p "$DUMP_DIR" "$ROOT/build"
WX_DUMP_DIR="$DUMP_DIR" DYLD_INSERT_LIBRARIES="$DYLIB" "$APP" > "$ROOT/build/run.out" 2>&1 &
echo "launched pid=$! dump_dir=$DUMP_DIR (sandbox may force ~/Downloads fallback)"
echo "log: $DUMP_DIR/weixin-key-dumper.log"
