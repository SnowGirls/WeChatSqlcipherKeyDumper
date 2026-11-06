#!/usr/bin/env bash
# 用法:   bash scripts/build-runtime.sh
# 作用:   复制 /Applications/WeChat.app 到 runtime/，导出其 entitlements 并 ad-hoc 重签（去掉 hardened runtime）。
# 输入:   /Applications/WeChat.app（可用 WECHAT_APP 覆盖源路径）
# 产出:   WeChatSqlcipherKeyDumper/runtime/WeChat.app
#         WeChatSqlcipherKeyDumper/config/entitlements-<version>-raw.plist
# 下一步: bash scripts/run-all.sh                  # 一键构建、抓取、回收、解密
# 配合:   首次使用及 WeChat 升级后各执行一次；详见 docs/实现-获取WeChat本地数据库-WCDB-SQLCipher-密钥.md 第 3 节。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_APP="${WECHAT_APP:-/Applications/WeChat.app}"
DST_APP="$ROOT/runtime/WeChat.app"
CONFIG="$ROOT/config"

if [ ! -d "$SRC_APP" ]; then
    echo "missing source app: $SRC_APP (set WECHAT_APP to override)" >&2
    exit 1
fi

if pgrep -f "$DST_APP/Contents/MacOS/WeChat" >/dev/null 2>&1; then
    echo "workspace copy is running; quit it first: $DST_APP" >&2
    exit 1
fi

VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$SRC_APP/Contents/Info.plist")"
PLIST="$CONFIG/entitlements-${VERSION}-raw.plist"
mkdir -p "$CONFIG"

codesign -d --entitlements :- "$SRC_APP" > "$PLIST" 2>/dev/null
if [ ! -s "$PLIST" ]; then
    rm -f "$PLIST"
    echo "failed to export entitlements from $SRC_APP" >&2
    exit 1
fi

rm -rf "$DST_APP"
mkdir -p "$ROOT/runtime"
ditto "$SRC_APP" "$DST_APP"
# bundle 内的 root 属主缓存文件无法去属性，报权限错误不影响签名
xattr -cr "$DST_APP" 2>/dev/null || true

codesign -f -s - --entitlements "$PLIST" "$DST_APP"
codesign --verify --strict "$DST_APP"

echo "runtime:      $DST_APP"
echo "entitlements: $PLIST"
echo
echo "checks:"
codesign -d --verbose=4 "$DST_APP" 2>&1 | grep -E 'flags|TeamIdentifier' || true
