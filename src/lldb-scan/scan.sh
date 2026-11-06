#!/usr/bin/env bash
# 用法:   bash src/lldb-scan/scan.sh [WeChat 进程 PID]
# 作用:   用 lldb attach 到运行中的WeChat，扫描内存里 99 字符的 x'<key><salt>'，
#         产出 {salt: raw key}。不需要注入、不需要改WeChat二进制。
# 前置:   已关闭 SIP（lldb attach 系统进程需要）；WeChat正在运行且已登录、
#         至少打开过一次数据库（key 在开库时写入内存）。
# 产出:   WeChatSqlcipherKeyDumper/out/wechat_db_keys.json（权限 600）
# 下一步: 用 out/wechat_db_keys.json 的 salt->key 解密 out/xwechat_files/ 或任意库副本。
# 配合:   与 src/weixin-key-dumper 的 DYLD/LC_LOAD_DYLIB 注入方式互斥，
#         适合作为同一能力的无注入替代路径；与仓库外目录无依赖。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
OUT="$ROOT/out/wechat_db_keys.json"

PID="${1:-}"
if [ -z "$PID" ]; then
    PID="$(pgrep -x WeChat | head -n1 || true)"
fi
if [ -z "$PID" ]; then
    echo "没有找到运行中的 WeChat 进程；先启动并登录WeChat，或传入 PID" >&2
    exit 1
fi
if ! command -v lldb >/dev/null 2>&1; then
    echo "缺少 lldb（安装 Xcode Command Line Tools）" >&2
    exit 1
fi

mkdir -p "$ROOT/out"
WECHAT_SQLCIPHER_OUT="$OUT" lldb -p "$PID" \
    -o "command script import $DIR/scan-keys.py" \
    -o "scan_hexkey_all" \
    -o "detach" -o "quit"

if [ -f "$OUT" ]; then
    chmod 600 "$OUT"
    echo "keys -> $OUT"
else
    echo "扫描完成但没有写出 $OUT（WeChat长跑后 key 可能已释放，重启WeChat后立即重试）" >&2
    exit 1
fi
