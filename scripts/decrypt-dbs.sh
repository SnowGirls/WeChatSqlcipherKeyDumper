#!/usr/bin/env bash
# 用法:   bash scripts/decrypt-dbs.sh
#         bash scripts/decrypt-dbs.sh --src out/xwechat_files --keys out/wechat_db_keys.json
# 作用:   只处理 out/xwechat_files/ 下已经存在的 .db（不访问 WeChat 容器），
#         用 out/wechat_db_keys.json 按文件头 salt 匹配 key，就地导出明文副本：
#         <dir>/<NAME>.db -> <dir>/<NAME>_decrypted.db
# 前置:   bash scripts/run-all.sh 已把库镜像到 out/xwechat_files/，并生成 wechat_db_keys.json。
#         （run-all.sh 会在结束后按需自动调用本脚本。）
# 环境:   WX_DB_SRC / WX_KEYS_JSON / WX_OUT 可覆盖默认路径。
# 说明:   加密库用 sqlcipher_export；明文库用 sqlite3 .backup 合并 WAL。
#         原始库只读，临时文件在 build/decrypt-tmp.*，输出权限 600。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ARG=""
SRC_ARG=""
KEYS_ARG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --src)  SRC_ARG="$2";  shift 2 ;;
        --keys) KEYS_ARG="$2"; shift 2 ;;
        --out)  OUT_ARG="$2";  shift 2 ;;
        -h|--help)
            sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "未知参数: $1（可用 --src/--keys/--out）" >&2; exit 2 ;;
    esac
done

OUT="${OUT_ARG:-${WX_OUT:-$ROOT/out}}"
SRC="${SRC_ARG:-${WX_DB_SRC:-$OUT/xwechat_files}}"
KEYS="${KEYS_ARG:-${WX_KEYS_JSON:-$OUT/wechat_db_keys.json}}"
LOG="${WX_DUMP_LOG:-$OUT/weixin-key-dumper.log}"
SUFFIX="_decrypted.db"
PLAIN_HEX="53514c69746520666f726d6174203300"   # "SQLite format 3\0"
RUN_TMP="$ROOT/build/decrypt-tmp.$$"

die() { echo "$*" >&2; exit 1; }
cleanup() { rm -rf "$RUN_TMP"; }
trap cleanup EXIT INT TERM

[ -d "$SRC" ]  || die "缺少库目录: $SRC
先运行 bash scripts/run-all.sh 生成 out/xwechat_files/"
[ -f "$KEYS" ] || die "缺少密钥文件: $KEYS
先运行 bash scripts/run-all.sh"
command -v sqlcipher >/dev/null || die "未找到 sqlcipher，请先 brew install sqlcipher"
command -v sqlite3   >/dev/null || die "未找到 sqlite3"
command -v xxd       >/dev/null || die "未找到 xxd"

mkdir -p "$RUN_TMP"
find "$SRC" -type f -iname '*.db' \
    ! -name "*_decrypted.db" ! -name "*_decripted.db" \
    | LC_ALL=C sort > "$RUN_TMP/dbs.list"
DB_COUNT=$(wc -l < "$RUN_TMP/dbs.list" | tr -d ' ')
[ "$DB_COUNT" -gt 0 ] || die "$SRC 下没有 .db，先完成镜像"

if [ -f "$LOG" ] && ! grep -q "db mirror: .* bytes total" "$LOG"; then
    echo "warning: $LOG 中没有镜像完成记录，xwechat_files 可能仍在写入；建议等 run-all 结束后再解密。" >&2
fi

if command -v jq >/dev/null 2>&1; then
    jq -r 'to_entries[] | select(.key | startswith("_") | not) | "\(.key)\t\(.value)"' \
        "$KEYS" > "$RUN_TMP/keys.tsv"
elif command -v python3 >/dev/null 2>&1; then
    python3 - "$KEYS" > "$RUN_TMP/keys.tsv" <<'PY'
import json, sys
for k, v in json.load(open(sys.argv[1])).items():
    if not k.startswith("_"):
        print("%s\t%s" % (k, v))
PY
else
    die "需要 jq 或 python3 解析 $KEYS"
fi

key_of() {
    awk -F '\t' -v s="$1" '$1 == s { print $2; exit }' "$RUN_TMP/keys.tsv"
}

sql_file_literal() {
    printf "%s" "$1" | sed "s/'/''/g"
}

STATUS=ok
INFO=""

finish_output() {
    local outtmp="$1" out="$2" n="$3" rc="$4" errfile="$5"
    local bytes=0
    if [ -f "$outtmp" ]; then
        bytes=$(wc -c < "$outtmp" | tr -d ' ')
    fi
    if [ ! -f "$outtmp" ]; then
        STATUS=fail
        INFO="$(head -c 200 "$errfile" 2>/dev/null | tr '\n' ' ')"
        [ -n "$INFO" ] || INFO="sqlcipher 无输出"
        return 0
    fi
    if [ -z "$n" ]; then
        STATUS=fail
        INFO="导出后无法读取"
        rm -f "$outtmp"
        return 0
    fi
    case "$n" in
        *[!0-9]*)
            STATUS=fail
            INFO="导出后无法读取"
            rm -f "$outtmp"
            return 0 ;;
    esac
    if [ "$n" -lt 1 ] && { [ "$rc" -ne 0 ] || [ -s "$errfile" ]; }; then
        STATUS=fail
        INFO="$(head -c 200 "$errfile" 2>/dev/null | tr '\n' ' ')"
        [ -n "$INFO" ] || INFO="导出后表数异常"
        rm -f "$outtmp"
        return 0
    fi
    chmod 600 "$outtmp"
    mv -f "$outtmp" "$out"
    if [ "$n" -lt 1 ]; then
        INFO="空库（0 表）"
    else
        INFO="$n objects, $(awk -v b="$bytes" 'BEGIN { printf "%.1f", b / 1000000 }') MB"
    fi
}

process_db() {
    local db="$1"
    local dir="${db%/*}"
    local base="${db##*/}"
    local stem="${base%.*}"
    local out="$dir/${stem}${SUFFIX}"
    local rel="${db#"$SRC"/}"
    local stage="$RUN_TMP/stage"
    local outtmp="$out.tmp.$$"
    local salt key sql n rc

    rm -rf "$stage"
    mkdir -p "$stage"
    cp -p "$db" "$stage/$base"
    local suf
    for suf in -wal -shm; do
        if [ -f "$db$suf" ]; then
            cp -p "$db$suf" "$stage/$base$suf"
        fi
    done
    rm -f "$outtmp"

    salt="$(xxd -p -l 16 "$db" | tr -d '\n')"

    if [ "$salt" = "$PLAIN_HEX" ]; then
        if ! sqlite3 -readonly "$stage/$base" ".backup '$outtmp'" \
                >"$stage/stdout" 2>"$stage/stderr"; then
            rm -f "$outtmp"
            STATUS=fail
            INFO="$(head -c 200 "$stage/stderr" | tr '\n' ' ')"
            [ -n "$INFO" ] || INFO="明文库导出失败"
            printf '%-48s %-4s %s\n' "$rel" "❌" "$INFO"
            return 1
        fi
        n="$(sqlite3 "$outtmp" 'select count(*) from sqlite_master;' 2>/dev/null || true)"
        finish_output "$outtmp" "$out" "$n" 0 "$stage/stderr"
        case "$STATUS" in
            ok)   if [ "$n" -lt 1 ]; then INFO="明文库, 空库（0 表）"; else INFO="明文库直出, $INFO"; fi ;;
        esac
    else
        key="$(key_of "$salt")"
        if [ -z "$key" ]; then
            printf '%-48s %-4s %s\n' "$rel" "⚠️" "无匹配密钥 (salt=${salt:0:8}…)，需重新抓取"
            return 2
        fi
        sql="PRAGMA key = \"x'$key$salt'\";
PRAGMA cipher_compatibility = 4;
ATTACH DATABASE '$(sql_file_literal "$outtmp")' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;"

        if printf '%s\n' "$sql" | sqlcipher "$stage/$base" >"$stage/stdout" 2>"$stage/stderr"; then
            rc=0
        else
            rc=$?
        fi
        n="$(sqlite3 "$outtmp" 'select count(*) from sqlite_master;' 2>/dev/null || true)"
        finish_output "$outtmp" "$out" "$n" "$rc" "$stage/stderr"
    fi

    case "$STATUS" in
        ok)   printf '%-48s %-4s %s\n' "$rel" "✅" "$INFO"; return 0 ;;
        *)    printf '%-48s %-4s %s\n' "$rel" "❌" "$INFO"; return 1 ;;
    esac
}

echo "密钥文件 : $KEYS"
echo "加密库源 : $SRC"
echo "输出位置 : 与各库同目录的 <NAME>${SUFFIX}"
echo "发现 $DB_COUNT 个 .db"
printf '%-48s %-4s %s\n' "库" "结果" "详情"

OK=0; FAIL=0; SKIP=0
while IFS= read -r db; do
    STATUS=ok
    INFO=""
    if process_db "$db"; then
        OK=$((OK + 1))
    else
        rc=$?
        if [ "$rc" -eq 2 ]; then
            SKIP=$((SKIP + 1))
        else
            FAIL=$((FAIL + 1))
        fi
    fi
done < "$RUN_TMP/dbs.list"

echo
echo "完成: 导出 ${OK}，失败 ${FAIL}，缺密钥 ${SKIP}"
[ "$FAIL" -eq 0 ] && [ "$SKIP" -eq 0 ]
