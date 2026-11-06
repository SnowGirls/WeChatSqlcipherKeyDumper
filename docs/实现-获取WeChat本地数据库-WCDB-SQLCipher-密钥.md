# WeChat macOS SQLCipher 密钥抓取与解密流程

> 适用：macOS 上的 WeChat 4.x（本项目在 4.2.0 上验证），仅用于**本机、本人账号**的数据导出。
> 全程不关闭 SIP、不使用 lldb / `task_for_pid`，密钥由启动时注入的动态库在进程内捕获并自校验。

---

## 1. 结论先行

| 问题                                       | 结论                                                                                                                      |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 能否不用 lldb 拿 SQLCipher raw key？           | 能。`DYLD_INSERT_LIBRARIES` + 自签名副本即可                                                                                     |
| 为什么不能用 interpose / fishhook 直接挂 `sqlite3_key`？ | WeChat 的 SQLite codec 是**静态链接**的，`sqlite3_key` 在定义镜像内部被直接调用；interpose 只改动态绑定，fishhook 只改符号槽，两者都看不到这些调用                     |
| 可靠的挂钩层在哪？                                | **CommonCrypto**：`CCCrypt`、`CCKeyDerivationPBKDF`，各镜像都是动态导入，interpose 生效                                                |
| 抓到的 32 字节“密码”是页密钥吗？                      | 不是。它是 PBKDF2 的 **输入**；页密钥是 `CCKeyDerivationPBKDF` 的 **32 字节输出**                                                         |
| 如何保证抓到的 key 是对的？                         | 进程内对数据库第 1 页做 AES-256-CBC 解密，校验恢复出的页头                                                                                   |
| 宿主为什么读不了数据库？                             | TCC 拦截容器路径（`Operation not permitted`）；由注入进程（在 WeChat 沙箱内）把库复制到 `$WX_DUMP_DIR`（默认 `WeChatSqlcipherKeyDumper/out`，沙箱拒绝时回退 `~/Downloads`） |

---

## 2. 原理

### 2.1 为什么 `sqlite3_key` 的 interpose / fishhook 都无效

- `__DATA,__interpose`（dyld interpose）只在**动态符号绑定**时把调用方重定向到替换函数。
- fishhook 走另一条路：解析 Mach-O 后直接改写调用槽（`__got` / `__la_symbol_ptr`），但它同样要求“调用经过符号槽”。
- WeChat 的 SQLite/SQLCipher codec 静态编进自身镜像，`sqlite3_key` 的调用在定义镜像内被直接解析（direct call），既不经过 dyld 绑定，也没有槽。
- 实测：`DYLD_PRINT_INTERPOSING=1` 时，只有 `dlsym` 和本 dylib 自身被替换；替换目标 `sqlite3_key` 地址落在 `/usr/lib/libsqlite3.dylib`（dyld shared cache），没有任何 WeChat 镜像导入它。对整个 `runtime/WeChat.app` 执行 `nm -u | grep sqlite3_`，动态导入数为 0。
- 两种挂钩方式的原理与取舍见 [`原理-fishhook-vs-interpose.md`](原理-fishhook-vs-interpose.md)。

### 2.2 真正的抓手：CommonCrypto

WeChat 在打开加密库时会走系统 CommonCrypto：

```
CCKeyDerivationPBKDF(algorithm = kCCPBKDF2,
                     password   = <32 字节口令>,
                     salt       = <数据库文件前 16 字节>,
                     prf        = 5 (HMAC-SHA512),
                     rounds     = 256000,
                     derivedKey = <32 字节输出>)
```

日志实测（`weixin-key-dumper.log`）：

```
pbkdf2: pass_len=32 salt=<salt> rounds=256000 prf=5 dk_len=32
pbkdf2 hit: matched db salt=<salt> rounds=256000 pass_len=32
```

- **32 字节输出 = SQLCipher 的 AES-256 页密钥**（即 raw key）。
- 同一口令还会用 `rounds=2`、`salt ^ 0x3a` 再派生一次 **HMAC 密钥**（SQLCipher 4 的 fast KDF），它的输出不能解密页面，会在校验阶段被丢弃。

### 2.3 SQLCipher 4 页面布局

```
物理页 4096 字节：
[ salt 16 ][ AES-256-CBC 密文 4000 ][ IV 16 ][ HMAC-SHA512 64 ]
             ^ 偏移 16                              ^ 偏移 4016
```

- 第 1 页的明文逻辑偏移是 16：解密后前两字节是页大小（`0x10 0x00` = 4096，大端），随后是写/读格式版本（SQLCipher 4 为 `0x01 0x01`）。
- 自校验方法：用候选 key 解密第 1 页，检查 `out[0]==0x10 && out[1]==0x00 && out[2] <= 2`。
  - 已用 sqlcipher 生成的已知 key 库验证：正确 key → `head=10 00 01 01`；错误 key → 随机字节。

### 2.4 密钥的“组合形态”

SQLCipher 接受 raw key 时格式为：

```
PRAGMA key = "x'<64 位 hex 的 key><32 位 hex 的 salt>'";
```

即 `key || salt` 共 96 个 hex 字符。解密时从 `wechat_db_keys.json` 取 `key`，再加文件头 16 字节的 `salt` 拼成这个形式。

---

## 3. 准备工作区运行副本

`/Applications/WeChat.app` 已被 macOS App Management（`com.apple.macl`）保护，终端无法改写；WeChat 自动升级还会重置内容。因此改为**工作区副本**运行：复制 → 去隔离属性 → 用原 entitlements 重新 ad-hoc 签名（保留沙盒权限，去掉 hardened runtime，允许 dyld 注入）。

```bash
cd WeChatSqlcipherKeyDumper
bash scripts/build-runtime.sh
```

脚本会依次完成：

- 检查工作区副本是否正在运行（运行中拒绝重建）；
- `ditto /Applications/WeChat.app runtime/WeChat.app` 复制；
- 用 `codesign -d --entitlements :-` 导出 `config/entitlements-<version>-raw.plist`（版本取自 Info.plist，升级后文件名随之更新）；
- `xattr -cr` 去隔离属性，ad-hoc 重签并 `--verify --strict` 校验。

校验结果应满足：

- `flags=0x2(adhoc)`（不再有 `0x10000(runtime)`）
- `TeamIdentifier=not set`
- `--verify --strict` 返回 0

> 这里沿用原 App 的 entitlements，因此副本仍能访问 WeChat 沙盒容器。输出目录由
> `WX_DUMP_DIR` 指定，默认工作区内的 `WeChatSqlcipherKeyDumper/out`；如果沙箱拒绝写工作区，
> 再回退到 entitlement 放行的 `~/Downloads` 作为临时中转（见第 6 节）。

---

## 4. 构建 dumper

源码目录 `WeChatSqlcipherKeyDumper/src/weixin-key-dumper/`（可独立构建）：

- `weixin-key-dumper.c`：主体（核心逻辑见第 2 节；文件头部有完整注释）
- `fishhook.c` / `fishhook.h`：Mach-O 符号槽改写

LC_LOAD_DYLIB 注入器在 `WeChatSqlcipherKeyDumper/src/inject/`（`inject.c` + `build-inject.sh`，见 5.1 节），与 dumper 分开构建。

推荐直接用脚本（同时构建两个源文件并签名）：

```bash
cd WeChatSqlcipherKeyDumper
bash src/weixin-key-dumper/build-dylib.sh
```

等价的手工命令：

```bash
clang -dynamiclib -O2 -arch arm64 -arch x86_64 \
  -Wl,-undefined,dynamic_lookup \
  -Wl,-weak_reference_mismatches,weak \
  -o build/weixin-key-dumper.dylib \
  src/weixin-key-dumper/weixin-key-dumper.c src/weixin-key-dumper/fishhook.c

codesign -f -s - build/weixin-key-dumper.dylib
codesign --verify --strict build/weixin-key-dumper.dylib
```

要点：

- `-Wl,-undefined,dynamic_lookup`：允许引用宿主进程里的符号（`CCCrypt`、`dlsym` 等）。
- dumper 的职责：
  1. **interpose** `CCCrypt` / `CCKeyDerivationPBKDF`（主路径，WeChat 各镜像都动态导入 CommonCrypto）；
  2. **fishhook** `sqlite3_key` / `_v2`、`sqlite3_prepare_v2/v3`、`sqlite3_prepare16_v2/v3`、`sqlite3_exec`（动态链接 SQLite 的宿主；WeChat 静态 codec 下不触发），并扫描 SQL 文本中的 `x'<96 hex>'`；
  3. 收集候选 key（99 字符 `x'...'`、裸 96 hex、32 字节 raw key）；
  4. 递归扫描容器内 `.db` 的 16 字节 salt；
  5. 用候选 key 试解密每个库的第 1 页，只输出**校验通过**的 `{salt: key}`；
  6. 把容器内**全部** `.db`（含 `-wal`/`-shm`，保持 `xwechat_files/<账号>/` 下的相对路径）复制到 `$WX_DUMP_DIR/xwechat_files/`；
  7. 结果同时写容器内 `$HOME/tmp/` 与 `$WX_DUMP_DIR/`；`WX_DUMP_DIR` 未设置时默认 `~/Downloads`（沙箱回退）。

可选自检：interpose 段应有 2 个二元组，fishhook 入口应作为导出符号存在。

```bash
otool -l build/weixin-key-dumper.dylib | grep -A4 -i __interpose   # 2 个 tuple：CCCrypt / PBKDF2
nm -gU build/weixin-key-dumper.dylib | grep wx_rebind_symbols
nm -u  build/weixin-key-dumper.dylib | grep -E 'CCCrypt|PBKDF2|dlsym'
```

> `nm -u` 里不会再出现 `sqlite3_key`：fishhook 按符号名字符串匹配，不依赖未定义符号。
> 若想验证 fishhook 层本身，运行 `bash src/weixin-key-dumper/test-dylib.sh`（不启动 WeChat，产物全部留在 `build/`）。

---

## 5. 注入运行（一次启动完成两件事）

一键完成按需构建/重建、启动、等待、回收、校验与解密：

```bash
cd WeChatSqlcipherKeyDumper
bash scripts/run-all.sh
```

`run-all.sh` 会先比较源文件与 `build/weixin-key-dumper.dylib` 的新旧、WeChat 版本与 `runtime/WeChat.app` 是否一致，只在需要时调用 `scripts/build-runtime.sh`；抓取完成后按 mtime 判断是否需要调用 `scripts/decrypt-dbs.sh`（`SKIP_BUILD=1` / `SKIP_DECRYPT=1` / `REBUILD_RUNTIME=1` 可覆盖）。

以下为等价的分步命令。关闭 WeChat（避免单实例模式下注入副本不打开数据库），然后启动副本：

```bash
cd WeChatSqlcipherKeyDumper
WX_DUMP_DIR=$PWD/out \
DYLD_INSERT_LIBRARIES=$PWD/build/weixin-key-dumper.dylib \
  ./runtime/WeChat.app/Contents/MacOS/WeChat > build/run.out 2>&1 &
```

> dumper 启动时会在沙箱内对 `WX_DUMP_DIR`（默认工作区 `out/`）做一次写探测；被拒绝时
> （ad-hoc 副本上临时例外 entitlement 不生效）自动回退到 `~/Downloads`，并在日志里记一条
> `warning: ... fell back to ...`。WeChat 停止后把结果复制回 `out/`：
>
> ```bash
> mkdir -p out
> cp ~/Downloads/wechat_db_keys.json ~/Downloads/weixin-key-dumper.log out/
> cp -R ~/Downloads/xwechat_files out/
> rm -rf ~/Downloads/xwechat_files ~/Downloads/wechat_db_keys.json ~/Downloads/weixin-key-dumper.log
> ```

> 实测：若已有正常 WeChat 实例在运行，注入副本可能不会打开任何加密库
> （日志里没有 `pbkdf2 hit`），因此建议先完全退出 WeChat 再执行本步骤。

日志里检查关键行：

```bash
tail -20 out/weixin-key-dumper.log        # 回退时：tail -20 ~/Downloads/weixin-key-dumper.log
# db scan: 20 salt(s) found
# db copy: db_storage/message/message_0.db (... bytes incl. wal/shm)
# db mirror: 20 db(s), 20962968 bytes total -> .../WeChatSqlcipherKeyDumper/out/xwechat_files
```

本次结果：扫描到 20 个库，其中 19 个加密库全部通过页解密校验并拿到 key；
剩余 1 个 `key_info.db` 本身是明文 SQLite（`SQLite format 3\0`），无需密钥。

### 5.1 备用注入方式：LC_LOAD_DYLIB（已实测）

除了环境变量，还可以把 dylib 写进主可执行文件的加载命令，让 dyld 在启动时自动加载。
`WeChatSqlcipherKeyDumper/src/inject/inject.c` 只往 Mach-O **头部空隙**追加一条 `LC_LOAD_DYLIB`，不移动任何段/section
偏移；支持 FAT/FAT64 与 thin `MH_MAGIC_64`，每个 slice 各插一条。

```bash
cd WeChatSqlcipherKeyDumper

# 0) 构建注入器（等价于 clang -O2 -o build/inject src/inject/inject.c）
bash src/inject/build-inject.sh

# 1) 备份可执行文件，并把 dylib 放进 bundle（避免依赖绝对路径）
cp runtime/WeChat.app/Contents/MacOS/WeChat build/WeChat-4.2.0-original
mkdir -p runtime/WeChat.app/Contents/Frameworks
cp build/weixin-key-dumper.dylib runtime/WeChat.app/Contents/Frameworks/
codesign -f -s - runtime/WeChat.app/Contents/Frameworks/weixin-key-dumper.dylib

# 2) 插入 LC_LOAD_DYLIB 并替换主可执行文件
./build/inject build/WeChat-4.2.0-original build/WeChat-4.2.0-patched \
  "@executable_path/../Frameworks/weixin-key-dumper.dylib"
cp build/WeChat-4.2.0-patched runtime/WeChat.app/Contents/MacOS/WeChat

# 3) 重新签名并校验（entitlements 文件名随当前 WeChat 版本）
codesign -f -s - --entitlements config/entitlements-4.2.0-raw.plist runtime/WeChat.app
codesign --verify --strict runtime/WeChat.app
otool -l runtime/WeChat.app/Contents/MacOS/WeChat | grep -B2 -A4 weixin-key-dumper
```

之后**不需要任何环境变量**，直接执行（或双击）就会加载 dumper：

```bash
./runtime/WeChat.app/Contents/MacOS/WeChat > build/run_lc.out 2>&1 &
```

4.2.0 实测记录（2026-11-04）：

- 两个 slice 都成功插入，`LC_LOAD_DYLIB` 的 `cmdsize` 为 80 字节：
  `sizeofcmds` x86_64 5128→5208、arm64 4800→4880（头部可用空隙约 49 KB）
- 启动命令**未设置** `DYLD_INSERT_LIBRARIES`、也未设置 `WX_DUMP_DIR`，日志仍出现
  `loaded into pid=...`，并完成 `db mirror: 20 db(s), 20962968 bytes total`
- 该次启动 WeChat 未打开加密库（`pbkdf2 hit` 为 0），说明密钥抓取仍取决于 WeChat 是否实际
  打开数据库，与注入方式无关
- 验证后已恢复副本：`Contents/MacOS/WeChat` 还原为 `build/WeChat-4.2.0-original`、删除嵌入的
  dylib 并重新签名；`build/WeChat-4.2.0-patched` 保留作可用产物

与 `DYLD_INSERT_LIBRARIES` 对比：

| | `DYLD_INSERT_LIBRARIES` | `LC_LOAD_DYLIB` |
| --- | --- | --- |
| 修改二进制 | 否 | 是（只写头部空隙） |
| 启动方式 | 必须直接执行可执行文件（Finder/Dock 不传环境变量） | 任意方式，双击即可 |
| 环境变量依赖 | 需要 | 无 |
| 重签要求 | 需要（去掉 hardened runtime） | 需要（改完签名必然失效） |
| dylib 丢失后果 | 只是不注入 | 硬加载失败会导致 App 起不来（可改 `LC_LOAD_WEAK_DYLIB` 兜底） |
| WeChat 升级影响 | 重建副本即可 | 需重新复制、注入、签名 |
| 适合场景 | 临时调试、可脚本化启动 | 想按普通 App 方式启动、不依赖环境 |

注意事项：

- 修改二进制后必须重签，否则 AMFI 会拒绝启动；签名时保留原 entitlements。
- 建议用 `@executable_path/...` 相对路径；绝对路径在副本移动后失效。
- 只 patch 主可执行文件，`WeChatAppEx` 等 helper 不会加载 dumper；抓 DB key 只需主进程。
- 不要改 `/Applications/WeChat.app`（App Management 保护，`com.apple.macl`），只在
  `runtime/` 副本操作。
- 每次启动都会自动加载并镜像全部库；日常使用完建议恢复未打补丁的副本（上面已还原），
  避免把数据反复写到 out/。

---

## 6. 取出数据库（绕开 TCC）

宿主 shell 读容器会被 TCC 拒绝：

```
xxd: .../message_0.db: Operation not permitted
ls: .../db_storage/message/: Operation not permitted
```

而注入进程在 WeChat 沙箱内，把**所有** `.db` 复制到 `$WX_DUMP_DIR/xwechat_files/`，保持原相对路径。
`WX_DUMP_DIR` 默认指向工作区 `WeChatSqlcipherKeyDumper/out`；dumper 启动时探测其可写性，
被沙箱拒绝时自动回退到 `~/Downloads`（副本唯一被 entitlement 放行的容器外可写位置）。

```
out/xwechat_files/.account                          # 从 /db_storage/ 前的路径段推导
out/xwechat_files/db_storage/message/message_0.db    # 其余库同理，均含 -wal / -shm
out/xwechat_files/db_storage/contact/contact.db
out/xwechat_files/db_storage/contact/contact_fts.db
out/xwechat_files/db_storage/session/session.db
out/xwechat_files/login/wxid_xxx/key_info.db        # 明文库
...
```

后续只在 `out/xwechat_files/` 的副本上操作，不动原库。

> 想彻底不经过 `out/` 镜像，需要给读取容器的终端授予「完全磁盘访问权限」；
> 即使直接读容器，解密也只应针对复制出来的库，原始加密文件保持不动。

> `message_1..5` 只有在 WeChat 实际写入时才创建；本次共发现 20 个 `.db`，其中
> `weclaw.db`、`solitaire.db` 是 4096 字节的空加密库。

---

## 7. 使用密钥（WeChatSqlcipherKeyDumper 之外）

WeChatSqlcipherKeyDumper 负责产出 `out/wechat_db_keys.json` 与 `out/xwechat_files/`，并提供 `scripts/decrypt-dbs.sh` 把镜像批量导出为明文：

```bash
bash scripts/decrypt-dbs.sh
```

脚本只处理 `out/xwechat_files/` 下已经存在的 `.db`（不访问 WeChat 容器），按文件头 salt 匹配 key，输出到各库同目录：`<NAME>.db` -> `<NAME>_decrypted.db`（如 `db_storage/message/message_0_decrypted.db`），权限 600；原始加密库保持只读。明文库（如 `login/.../key_info.db`）用 `sqlite3 .backup` 合并 WAL 后直出，空加密库也会导出为 0 表明文文件。

> `*_fts.db` 的 FTS 虚拟表使用微信自定义分词器（`MMFtsTokenizer`），用普通 SQLite 查询这些虚拟表会报
> `SQL logic error`；`sqlcipher_export` 导出的是完整页面，普通表不受影响。

也可以继续用任意支持 SQLCipher 4 的工具直接消费：

- `out/wechat_db_keys.json` 是 `{ "<16 字节 salt 的 hex>": "<32 字节 raw key 的 hex>", ..., "_account": "wxid_...", "_db_map": { "<salt>": ["db_storage/..."] } }`；
  `_account` 记录账号 wxid，`_db_map` 标明每个 salt 对应的库相对路径（注入 dumper 产出；lldb 扫描两者为空字符串/空对象），按 salt 取 key 时忽略它们即可；
- 读取每个库文件前 16 字节得到 `salt`，从 JSON 取出对应 `key`；
- 拼成 `PRAGMA key = "x'<key><salt>'"`，并设置 `cipher_compatibility = 4`。

单个库导出为明文 SQLite 的标准脚本：

```sql
PRAGMA key = "x'<64 hex key><32 hex salt>'";
PRAGMA cipher_compatibility = 4;
ATTACH DATABASE '<out>.tmp' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
```

示例（`sqlcipher` CLI 需自行安装；先复制库到可写目录，避免改动镜像）：

```bash
cd WeChatSqlcipherKeyDumper
db=out/xwechat_files/db_storage/contact/contact.db
salt=$(xxd -p -l 16 "$db")
key=$(python3 -c 'import json,sys; print(json.load(open("out/wechat_db_keys.json"))[sys.argv[1]])' "$salt")
cp "$db" out/contact.db
sqlcipher out/contact.db <<SQL
PRAGMA key = "x'$key$salt'";
PRAGMA cipher_compatibility = 4;
ATTACH DATABASE 'out/contact.dec.db' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
SQL
```

注意：明文库（`SQLite format 3\0`，如 `key_info.db`）无需 key；WeChat 预建的 4096 字节空加密库只要密钥正确即为成功；
每个 key 只对**对应 salt** 的库有效。

一次实测（能力 A）的输出：**20 个 `.db` 全部导出成功**（0 失败、0 缺密钥），合计约 5.2 MB：

| 类别 | 数量 | 说明 |
| --- | --- | --- |
| 普通 SQLCipher 库 | 17 | `message_0`、`contact`、`session`、`emoticon`、`sns`、`general` 等 |
| 空加密库 | 2 | `weclaw.db`、`solitaire.db`（4096 字节，0 表） |
| 明文库 | 1 | `login/.../key_info.db` |

校验（以上述示例输出为例）：

```bash
sqlite3 out/contact.dec.db "PRAGMA integrity_check;"
sqlite3 out/contact.dec.db \
  "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
```

`message_0.db` 中可见 `Msg_*` 分表、`Name2Id` 等 WCDB 结构，说明数据真实可用。

> 3 个 FTS 库（`contact_fts`、`favorite_fts`、`message_fts`）的 `quick_check`
> 会报 `SQL logic error`：WeChat 的自定义 FTS 模块/分词器不在系统 SQLite 中，
> **加密源库本身也是同样报错**。已用基表行数逐库比对（30/5/2 行），导出数据一致。

---

## 8. 收尾

```bash
# 停掉注入实例（kill 主进程，helper 会随之退出）
pgrep -f 'runtime/WeChat.app/Contents/MacOS/WeChat$' | xargs kill

# 结果直接写在 out/；沙箱回退时确认 Downloads 已清空
ls ~/Downloads | grep -i wx || true
```

`WeChatSqlcipherKeyDumper/.gitignore` 已排除敏感数据与生成物，避免误提交：

```
build/
runtime/
out/
*.dylib
```

`/Applications/WeChat.app` 全程未改动；原 App 来源统一为它。

---

## 9. `wechat_db_keys.json` 能反复使用吗？

**能，但有明确前提。**

| 场景 | 旧 key 是否可用 | 说明 |
| --- | --- | --- |
| 同一数据库文件、salt 未变 | ✅ 可反复使用 | key 只与“32 字节口令 + 文件 salt”绑定；解密任意副本、含 `-wal` 数据都行 |
| 备份/复制过的旧库 | ✅ | 只要文件头 16 字节 salt 相同 |
| WeChat 升级但保留数据库 | ✅（通常） | salt 存在文件里，升级一般不重建库；用 salt 是否命中即可判断 |
| WeChat 重装 / 清数据 / 重新登录 / 修改数据库口令 | ❌ | 会重新生成 salt，需重新注入抓取一次 |
| 新的 `message_1.db` 等之后才创建的库 | ❌ | 新文件有新 salt，需要再跑一次抓取（一次启动即可） |
| 换账号 | ❌ | 每个账号的文件 salt/口令都不同 |

快速判断覆盖情况：

```bash
cd WeChatSqlcipherKeyDumper
python3 - <<'PY'
import json, os
keys = json.load(open("out/wechat_db_keys.json"))
for root, _, files in os.walk("out/xwechat_files"):
    for fn in sorted(files):
        if not fn.endswith(".db"):
            continue
        p = os.path.join(root, fn)
        salt = open(p, "rb").read(16).hex()
        print(os.path.relpath(p, "out/xwechat_files"), "有 key" if salt in keys else "需要重新抓取")
PY
```

### 密钥是怎么生成的

1. WeChat 内部持有一段 **32 字节的数据库口令**（由登录态/本地材料派生，抓包点在 PBKDF2 的 `password` 参数）。
2. 打开每个库时，取该文件**前 16 字节 salt**，执行
   `PBKDF2-HMAC-SHA512(password, salt, 256000 轮, dkLen=32)`，得到 **32 字节 AES-256 页密钥**。
3. 再用 `salt ^ 0x3a`、2 轮 PBKDF2 派生 HMAC 密钥，用于每页 HMAC 校验。
4. 每页数据以 AES-256-CBC 加密，IV 存在页尾（HMAC 之前）。
5. 因此：
   - 同一口令 + 不同 salt ⇒ **不同**页密钥（每个库一把）；
   - 我们导出的 `{salt: key}` 每项只对对应 salt 的库有效；
   - 把 `key` 与文件 salt 拼成 `x'<key><salt>'` 就是 SQLCipher 的 raw-key 形式，跳过 PBKDF2 直接解密。

> `wechat_db_keys.json` 等同于明文数据库的钥匙，请勿提交、上传或分享；文档与日志中均不包含 key 本身。

---

## 10. 踩坑与排查记录

| 现象                                             | 原因                                   | 处理                                                 |
| ---------------------------------------------- | ------------------------------------ | -------------------------------------------------- |
| interpose / fishhook 的 `sqlite3_key` 从不触发      | codec 静态链接，镜像内直接调用，没有符号槽            | 改挂 CommonCrypto；fishhook 只对动态导入 SQLite 的宿主有效     |
| 抓到 32 字节“key”但解密失败                             | 那是 PBKDF2 输入口令，不是页密钥                 | 捕获 `CCKeyDerivationPBKDF` 的 32 字节输出                |
| 日志显示 `rounds=2` 的 key 解不开页                     | 那是 HMAC fast-KDF 输出                  | 页解密校验时自动丢弃                                         |
| 宿主机 `ls/xxd` 容器报 EPERM                         | TCC 限制                               | 由注入进程复制到 `$WX_DUMP_DIR`（out 或回退的 `~/Downloads`） |
| `/Applications/WeChat.app` 内文件 `touch` 报 EPERM | App Management（`com.apple.macl`）     | 只在 `WeChatSqlcipherKeyDumper/runtime/` 副本操作                           |
| WeChat 自动升级后 dylib 消失                               | 升级重写 bundle                          | 重新 `ditto` + 重新签名；不要改 `/Applications/WeChat.app`   |
| 二次启动日志无 `pbkdf2 hit`                           | 已有 WeChat 实例占用（单实例模式）                      | 完全退出 WeChat 后再注入运行                                       |
| `weclaw.db`/`solitaire.db` 导出后 0 表             | WeChat 预建的 4096 字节空加密库，密钥正确               | 视为成功（空库）                                           |
| FTS 库 `quick_check` 报 `SQL logic error`        | WeChat 自定义 FTS 模块/分词器不在系统 SQLite 中，源库同样报错 | 用基表行数比对验证                                          |
| zsh 下 `PIPESTATUS` 无效                          | zsh 用 `$pipestatus`（1-indexed）       | 需要判断退出码时不要接管道                                      |
| `kill $pids` 报 illegal pid                     | zsh 默认不对变量做分词                        | 用 `pgrep ... | xargs kill`                         |

---

## 11. 文件清单

| 路径 | 作用 |
| --- | --- |
| `WeChatSqlcipherKeyDumper/src/weixin-key-dumper/weixin-key-dumper.c` | 注入用 dylib 主体（interpose + fishhook 接线、页解密校验、库复制） |
| `WeChatSqlcipherKeyDumper/src/weixin-key-dumper/fishhook.c` / `fishhook.h` | Mach-O 符号槽改写 |
| `WeChatSqlcipherKeyDumper/build/weixin-key-dumper.dylib` | 构建产物（ad-hoc 签名） |
| `WeChatSqlcipherKeyDumper/src/inject/inject.c` / `WeChatSqlcipherKeyDumper/build/inject` | LC_LOAD_DYLIB 注入器源码与产物 |
| `WeChatSqlcipherKeyDumper/src/wechat-key-dumper/` | 独立 fishhook dumper（可单独构建） |
| `WeChatSqlcipherKeyDumper/build/wechat-key-dumper.dylib` | 该 dumper 的构建产物（`src/wechat-key-dumper/build-dylib.sh` 构建并签名） |
| `WeChatSqlcipherKeyDumper/scripts/run-all.sh` | 一键入口：按需构建/重建、启动、等待密钥与镜像、回收沙箱回退产物、校验摘要、按需解密 |
| `WeChatSqlcipherKeyDumper/scripts/decrypt-dbs.sh` | 批量解密 `out/xwechat_files` 的库，输出到各库同目录的 `<NAME>_decrypted.db`（明文库直出） |
| `WeChatSqlcipherKeyDumper/src/weixin-key-dumper/build-dylib.sh` | 能力 A 的构建脚本 |
| `WeChatSqlcipherKeyDumper/src/inject/build-inject.sh` | 注入器构建脚本 |
| `WeChatSqlcipherKeyDumper/src/weixin-key-dumper/run-dyld.sh` | DYLD 注入启动工作区副本 |
| `WeChatSqlcipherKeyDumper/src/weixin-key-dumper/test-dylib.sh` | fishhook 端到端验证（test-host + 假 SQLite 库） |
| `WeChatSqlcipherKeyDumper/src/lldb-scan/scan-keys.py` / `scan.sh` | 无注入的 lldb 扫内存能力 |
| `WeChatSqlcipherKeyDumper/build/WeChat-4.2.0-original` | 4.2.0 原始主可执行文件备份 |
| `WeChatSqlcipherKeyDumper/build/WeChat-4.2.0-patched` | 已插入 LC_LOAD_DYLIB 的主可执行文件（实测可用） |
| `WeChatSqlcipherKeyDumper/out/` | 最终产出：`wechat_db_keys.json`、`xwechat_files/`、`weixin-key-dumper.log` |
| `WeChatSqlcipherKeyDumper/runtime/WeChat.app` | 工作区运行副本（原 entitlements 重签，升级后需重建） |
| `WeChatSqlcipherKeyDumper/scripts/build-runtime.sh` | 准备工作区运行副本：复制、导出 entitlements、ad-hoc 重签 |
| `WeChatSqlcipherKeyDumper/config/entitlements-<version>-raw.plist` | 由 `scripts/build-runtime.sh` 从原 App 导出（升级后随版本更新） |
| `WeChatSqlcipherKeyDumper/docs/原理-fishhook-vs-interpose.md` | 两种挂钩方式的原理、对比与限制 |
| `WeChatSqlcipherKeyDumper/.gitignore` | 排除构建产物、运行副本与密钥/数据库输出 |

---

## 12. 合规边界

- 仅处理**本机、本人账号**的数据；
- 只解密数据库**副本**，原始加密文件字节不变；
- 不处理他人数据、不发布解密结果或密钥；
- 所有生成物与中间文件均位于 `Wechat/` 工作区内；`~/Downloads` 仅在沙箱拒绝写
  `WeChatSqlcipherKeyDumper/out` 时充当一次性中转（复制回 `out/` 后立即删除）。
