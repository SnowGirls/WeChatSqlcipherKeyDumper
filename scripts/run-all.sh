#!/usr/bin/env bash
# 用法:   bash scripts/run-all.sh
# 作用:   一键跑完：按需构建 dylib -> 按需准备 runtime 副本 -> 注入启动 -> 等待密钥与镜像稳定
#         -> 结束副本 -> 回收沙箱回退的 ~/Downloads 产物 -> 校验 -> 按需解密为明文副本。
# 前置:   完全退出 WeChat（含 /Applications 原版）；需要本人账号登录时在提示后完成登录/开库。
# 环境:   WAIT_SECONDS=900     最长等待时间
#         QUIET_SECONDS=15     密钥落盘后需保持稳定的秒数
#         SKIP_BUILD=1         跳过 dylib 构建（默认按源文件新旧判断）
#         SKIP_DECRYPT=1       跳过最后的解密步骤
#         REBUILD_RUNTIME=1    强制重建 runtime 副本（默认按 WeChat 版本判断）
#         WX_DUMP_DIR=<dir>    输出目录（默认 WeChatSqlcipherKeyDumper/out）
# 产出:   <out>/wechat_db_keys.json、xwechat_files/、weixin-key-dumper.log，
#         以及各库同目录的 <NAME>_decrypted.db。
# 说明:   沙箱拒绝写 out/ 时 dumper 自动回退 ~/Downloads，本脚本负责回收并清理副本。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${WX_DUMP_DIR:-$ROOT/out}"
REAL_HOME="$HOME"
APP="$ROOT/runtime/WeChat.app/Contents/MacOS/WeChat"
DYLIB="$ROOT/build/weixin-key-dumper.dylib"
SRC_APP="${WECHAT_APP:-/Applications/WeChat.app}"
WAIT_SECONDS="${WAIT_SECONDS:-900}"
QUIET_SECONDS="${QUIET_SECONDS:-15}"
DL_JSON="$REAL_HOME/Downloads/wechat_db_keys.json"
DL_LOG="$REAL_HOME/Downloads/weixin-key-dumper.log"
DL_MIRROR="$REAL_HOME/Downloads/xwechat_files"
PREV_JSON="$ROOT/build/prev-wechat_db_keys.json"

PID=""
say() { printf '%s\n' "$*"; }
cleanup_prev() { rm -f "$PREV_JSON"; }
trap cleanup_prev EXIT

stop_copy() {
    [ -n "$PID" ] || return 0
    if kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        for _ in $(seq 1 15); do
            kill -0 "$PID" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "$PID" 2>/dev/null || true
    fi
    PID=""
}

on_interrupt() {
    say ""
    say "已中止；未完成的产物保留在 $OUT 或 ~/Downloads。"
    stop_copy
    exit 130
}
trap on_interrupt INT TERM

probe_keys() {
    python3 - "$START" "$OUT/wechat_db_keys.json" "$DL_JSON" <<'PY'
import json, os, sys
start = int(sys.argv[1])
best = None
for p in sys.argv[2:]:
    try:
        if not os.path.exists(p) or os.path.getmtime(p) + 1 < start:
            continue
        with open(p) as f:
            d = json.load(f)
        n = sum(1 for k in d if not k.startswith("_"))
        if n <= 0:
            continue
        mt = os.path.getmtime(p)
        if best is None or mt > best[2]:
            best = (p, n, mt, d.get("_account", ""))
    except Exception:
        pass
if best:
    print("%s|%d|%s" % (best[0], best[1], best[3]))
PY
}

mirror_ready() {
    local dir log
    dir="$(dirname "$KEY_PATH")/xwechat_files"
    log="$(dirname "$KEY_PATH")/weixin-key-dumper.log"
    [ -d "$dir" ] || return 1
    [ -n "$(find "$dir" -type f -size +0c -print -quit 2>/dev/null)" ] || return 1
    grep -Eq "db mirror: [1-9][0-9]* db\(s\), [1-9][0-9]* bytes total" "$log" 2>/dev/null
}

cleanup_failed_downloads() {
    local f
    for f in "$DL_JSON" "$DL_LOG"; do
        if [ -f "$f" ] && [ "$(stat -f %m "$f")" -ge "$((START - 1))" ]; then
            rm -f "$f"
        fi
    done
    if [ -d "$DL_MIRROR" ] && [ "$(stat -f %m "$DL_MIRROR")" -ge "$((START - 1))" ]; then
        rm -rf "$DL_MIRROR"
    fi
}

dylib_stale() {
    [ -f "$DYLIB" ] || return 0
    local f
    for f in "$ROOT/src/weixin-key-dumper/weixin-key-dumper.c" \
             "$ROOT/src/weixin-key-dumper/fishhook.c" \
             "$ROOT/src/weixin-key-dumper/fishhook.h" \
             "$ROOT/src/weixin-key-dumper/build-dylib.sh"; do
        if [ -f "$f" ] && [ "$f" -nt "$DYLIB" ]; then
            return 0
        fi
    done
    return 1
}

runtime_stale() {
    [ -x "$APP" ] || return 0
    [ -d "$SRC_APP" ] || return 1
    local src_ver dst_ver
    src_ver=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
        "$SRC_APP/Contents/Info.plist" 2>/dev/null || true)
    dst_ver=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
        "$ROOT/runtime/WeChat.app/Contents/Info.plist" 2>/dev/null || true)
    if [ -n "$src_ver" ] && [ "$src_ver" != "$dst_ver" ]; then
        return 0
    fi
    [ -f "$ROOT/config/entitlements-${src_ver}-raw.plist" ] || return 0
    return 1
}

decrypt_stale() {
    local db out keys="$OUT/wechat_db_keys.json"
    [ -f "$keys" ] || return 1
    while IFS= read -r db; do
        out="${db%.*}_decrypted.db"
        if [ ! -f "$out" ] || [ "$db" -nt "$out" ] || [ "$keys" -nt "$out" ]; then
            return 0
        fi
        if [ -f "${db}-wal" ] && [ "${db}-wal" -nt "$out" ]; then
            return 0
        fi
        if [ -f "${db}-shm" ] && [ "${db}-shm" -nt "$out" ]; then
            return 0
        fi
    done < <(find "$OUT/xwechat_files" -type f -iname '*.db' \
        ! -name '*_decrypted.db' ! -name '*_decripted.db' 2>/dev/null)
    return 1
}

say "[1/6] 检查 WeChat 是否已退出"
RUNNING="$(pgrep -f 'WeChat\.app/Contents/MacOS/WeChat$' || true)"
if [ -n "$RUNNING" ]; then
    say "WeChat 仍在运行（pid: $(echo "$RUNNING" | tr '\n' ' ')）。"
    say "请完全退出 WeChat（含 /Applications 原版）后重试；单实例锁会让副本无法开库。"
    exit 1
fi

if [ "${SKIP_BUILD:-0}" = "1" ]; then
    say "[2/6] 跳过 dylib 构建（SKIP_BUILD=1）"
elif dylib_stale; then
    say "[2/6] 构建 dumper dylib（缺失或源文件有更新）"
    bash "$ROOT/src/weixin-key-dumper/build-dylib.sh"
else
    say "[2/6] dylib 已是最新，跳过构建"
fi
[ -f "$DYLIB" ] || { say "缺少 dylib: $DYLIB"; exit 1; }

if [ "${REBUILD_RUNTIME:-0}" = "1" ]; then
    say "[3/6] 重建 runtime 副本（REBUILD_RUNTIME=1）"
    bash "$ROOT/scripts/build-runtime.sh"
elif runtime_stale; then
    say "[3/6] 准备 runtime 副本（缺失或 WeChat 版本变化）"
    bash "$ROOT/scripts/build-runtime.sh"
else
    say "[3/6] runtime 副本已是最新，跳过"
fi
[ -x "$APP" ] || { say "缺少 runtime 副本: $APP"; exit 1; }

mkdir -p "$OUT" "$ROOT/build"
rm -f "$PREV_JSON"
if [ -f "$OUT/wechat_db_keys.json" ]; then
    cp "$OUT/wechat_db_keys.json" "$PREV_JSON"
fi
START="$(date +%s)"

say "[4/6] 注入启动副本"
say "      日志: $OUT/weixin-key-dumper.log 或 ~/Downloads/weixin-key-dumper.log（沙箱回退）"
WX_DUMP_DIR="$OUT" DYLD_INSERT_LIBRARIES="$DYLIB" "$APP" > "$ROOT/build/run.out" 2>&1 &
PID=$!
sleep 2
if ! kill -0 "$PID" 2>/dev/null; then
    say "副本启动后立即退出，见 $ROOT/build/run.out"
    tail -20 "$ROOT/build/run.out" 2>/dev/null || true
    exit 1
fi

say "      请在 WeChat 中登录并打开会话；最长等待 ${WAIT_SECONDS}s（Ctrl-C 中止）"
LAST_SIG=""
STABLE=0
LAST_REPORT=0
KEY_PATH=""
KEY_COUNT=0
ACCOUNT=""
TIMED_OUT=0

while :; do
    NOW="$(date +%s)"
    ELAPSED=$((NOW - START))
    if [ "$ELAPSED" -ge "$WAIT_SECONDS" ]; then
        TIMED_OUT=1
        break
    fi

    PROBE="$(probe_keys)"
    if [ -n "$PROBE" ]; then
        IFS='|' read -r KEY_PATH KEY_COUNT ACCOUNT <<< "$PROBE"
        SIG="$KEY_PATH:$KEY_COUNT:$(stat -f %z "$KEY_PATH" 2>/dev/null || echo 0)"
        if [ "$SIG" = "$LAST_SIG" ]; then
            STABLE=$((STABLE + 2))
        else
            STABLE=0
            LAST_SIG="$SIG"
        fi
        if [ "$STABLE" -ge "$QUIET_SECONDS" ] && mirror_ready; then
            break
        fi
    fi

    if [ $((NOW - LAST_REPORT)) -ge 10 ]; then
        if [ -n "$KEY_PATH" ]; then
            say "      ${ELAPSED}s: 已捕获 $KEY_COUNT key(s), account=${ACCOUNT:-未识别}, 等待落盘稳定"
        else
            say "      ${ELAPSED}s: 等待密钥，请登录 WeChat 并打开会话"
        fi
        LAST_REPORT=$NOW
    fi
    sleep 2
done

stop_copy

if [ -z "$KEY_PATH" ]; then
    if [ "$TIMED_OUT" = "1" ]; then
        say "超时：${WAIT_SECONDS}s 内未捕获密钥。副本已结束，可加大 WAIT_SECONDS 后重试。"
    fi
    cleanup_failed_downloads
    exit 1
fi

say "[5/6] 回收并校验结果"
SRC_DIR="$(dirname "$KEY_PATH")"
if [ "$SRC_DIR" != "$OUT" ]; then
    say "      沙箱拒绝写 ${OUT}，从 ${SRC_DIR} 回收"
    cp "$KEY_PATH" "$OUT/wechat_db_keys.json"
    if [ -f "$SRC_DIR/weixin-key-dumper.log" ]; then
        cp "$SRC_DIR/weixin-key-dumper.log" "$OUT/weixin-key-dumper.log"
    fi
    if [ -d "$SRC_DIR/xwechat_files" ]; then
        STAGE="$OUT/.xwechat_files.stage.$$"
        rm -rf "$STAGE"
        cp -R "$SRC_DIR/xwechat_files" "$STAGE"
        rm -rf "$OUT/xwechat_files"
        mv "$STAGE" "$OUT/xwechat_files"
    fi
    rm -f "$KEY_PATH" "$SRC_DIR/weixin-key-dumper.log"
    rm -rf "$SRC_DIR/xwechat_files"
fi

if [ -f "$PREV_JSON" ]; then
    MERGED="$(python3 - "$OUT/wechat_db_keys.json" "$PREV_JSON" <<'PY'
import json, sys
new_path, old_path = sys.argv[1], sys.argv[2]
with open(new_path) as f:
    new = json.load(f)
with open(old_path) as f:
    old = json.load(f)
old_map = old.get("_db_map") or {}
new_map = new.get("_db_map") or {}
added = 0
for salt, key in old.items():
    if salt.startswith("_") or salt in new or salt not in old_map:
        continue
    new[salt] = key
    new_map[salt] = old_map[salt]
    added += 1
if added:
    new["_db_map"] = new_map
    with open(new_path, "w") as f:
        json.dump(new, f, indent=1)
print(added)
PY
)"
    if [ "$MERGED" -gt 0 ]; then
        say "      本次捕获不完整，已合并上次 JSON 中 $MERGED 个 key（按 salt 匹配，仍可解密）"
    fi
    rm -f "$PREV_JSON"
fi
rm -f "$OUT/wx_keys.json"

python3 - "$OUT/wechat_db_keys.json" "$OUT/weixin-key-dumper.log" "$OUT/xwechat_files" <<'PY'
import json, os, re, sys

json_path, log_path, mirror = sys.argv[1:4]
with open(json_path) as f:
    data = json.load(f)
keys = {k: v for k, v in data.items() if not k.startswith("_")}
account = data.get("_account", "")
db_map = data.get("_db_map", {})

bad_salt = [k for k in keys if not re.fullmatch(r"[0-9a-f]{32}", k)]
bad_key = [k for k, v in keys.items() if not re.fullmatch(r"[0-9a-f]{64}", v)]
log = open(log_path, encoding="utf-8", errors="replace").read() if os.path.exists(log_path) else ""
leaked = [k for k, v in keys.items() if v in log]

files = 0
size = 0
for root, _, names in os.walk(mirror):
    for n in names:
        p = os.path.join(root, n)
        files += 1
        size += os.path.getsize(p)

print("  keys      : %d" % len(keys))
print("  account   : %s" % (account or "(empty)"))
print("  db_map    : %d" % len(db_map))
print("  mirror    : %d file(s), %d bytes" % (files, size))
print("  log leaks : %d raw key(s)" % len(leaked))

errors = []
if not keys:
    errors.append("no keys")
if bad_salt:
    errors.append("bad salt: %s" % bad_salt[:3])
if bad_key:
    errors.append("bad key: %s" % bad_key[:3])
if not account:
    errors.append("missing _account")
if len(db_map) != len(keys):
    errors.append("db_map %d != keys %d" % (len(db_map), len(keys)))
if files == 0 or size == 0:
    errors.append("mirror empty")
if leaked:
    errors.append("raw key leaked into log: %s" % leaked[:1])
if errors:
    print("  FAIL: " + "; ".join(errors))
    sys.exit(1)
print("  OK: %s" % json_path)
PY

if [ "${SKIP_DECRYPT:-0}" = "1" ]; then
    say "[6/6] 跳过解密（SKIP_DECRYPT=1）"
elif decrypt_stale; then
    say "[6/6] 解密镜像 -> 各库同目录 <NAME>_decrypted.db"
    if ! bash "$ROOT/scripts/decrypt-dbs.sh" \
            --src "$OUT/xwechat_files" --keys "$OUT/wechat_db_keys.json"; then
        say "警告: 解密未全部完成（缺密钥或失败见上）；密钥与镜像已保存"
    fi
else
    say "[6/6] 明文副本已是最新，跳过解密"
fi
