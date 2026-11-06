# WeChatSqlcipherKeyDumper

macOS WeChat SQLCipher Key Dumper

**本工具仅供个人学习、技术研究与本人数据备份使用，严禁任何商业用途。**

## 目录结构

```
WeChatSqlcipherKeyDumper/
├── README.md
├── scripts/                       # 顶层编排脚本
│   ├── run-all.sh                 # 一键入口：按需构建/重建 -> 启动 -> 等待 -> 回收 -> 校验 -> 解密
│   ├── decrypt-dbs.sh             # 批量解密 out/xwechat_files 的库，输出到各库同目录
│   └── build-runtime.sh           # 复制 WeChat 副本、导出 entitlements 并重签
├── src/
│   ├── weixin-key-dumper/         # 能力 A：interpose + fishhook 主 dumper（可独立构建）
│   │   ├── weixin-key-dumper.c    # 抓取、页解密校验、库镜像、两层挂钩接线
│   │   ├── fishhook.c / .h        # Mach-O 符号槽改写
│   │   ├── build-dylib.sh         # 构建 + 签名 weixin-key-dumper.dylib
│   │   ├── run-dyld.sh            # 退出 WeChat 后，DYLD 注入启动工作区副本
│   │   ├── test-dylib.sh          # 构建假 SQLite 库并跑 fishhook 验证
│   │   └── test-fixtures/         # 验证夹具
│   │       ├── test-host.c        # fishhook 端到端验证宿主
│   │       └── test-sqlite.c      # 验证用假 SQLite 动态库（被 test-host 导入）
│   ├── inject/                    # LC_LOAD_DYLIB 头部空隙注入器（把 weixin-key-dumper 的 dylib 写进主可执行文件）
│   │   ├── inject.c
│   │   └── build-inject.sh        # 构建 build/inject
│   ├── lldb-scan/                 # 能力 C：不注入，lldb 扫内存（可独立使用）
│   │   ├── scan-keys.py           # lldb 命令脚本
│   │   └── scan.sh                # attach 运行中的 WeChat 并写出 out/wechat_db_keys.json
│   └── wechat-key-dumper/         # 能力 B：独立 fishhook dumper（可单独构建）
│       ├── wechat-key-dumper.c
│       └── build-dylib.sh         # 构建并签名 build/wechat-key-dumper.dylib
├── docs/
│   ├── 实现-获取WeChat本地数据库-WCDB-SQLCipher-密钥.md   # 完整流程（含 LC_LOAD_DYLIB）
│   └── 原理-fishhook-vs-interpose.md
├── config/                        # 从原 App 导出的 entitlements（<version>-raw.plist）
├── build/                         # 构建产物、测试 fixture 与日志
├── runtime/WeChat.app             # 工作区运行副本（原 entitlements 重签）
└── out/                           # 最终产出：wechat_db_keys.json、xwechat_files/、日志
```

## 快速开始

一键跑完（按需构建 dylib / 重建 runtime、启动、等待登录/开库、回收沙箱回退产物、校验、解密）：

```bash
cd WeChatSqlcipherKeyDumper
bash scripts/run-all.sh
```

可调环境变量：`WAIT_SECONDS`（默认 900）、`QUIET_SECONDS`（默认 15）、`SKIP_BUILD=1`、`SKIP_DECRYPT=1`、`REBUILD_RUNTIME=1`、`WX_DUMP_DIR`。脚本会比较源文件与 dylib 新旧、WeChat 与 runtime 副本版本，按需构建/重建；抓取结束后按 mtime 决定是否解密。若本次只捕到部分 key，会合并上次 JSON 中同 salt 的 key，避免覆盖完整结果。沙箱拒绝写 `out/` 时自动回退 `~/Downloads` 并在结束后回收、清理。

解密镜像（run-all 完成后自动执行；也可单独运行；只处理已落到 `out/xwechat_files/` 的库）：

```bash
bash scripts/decrypt-dbs.sh
# 例：out/xwechat_files/db_storage/bizchat/bizchat.db
#  -> out/xwechat_files/db_storage/bizchat/bizchat_decrypted.db
```

`*_fts_decrypted.db` 的 FTS 虚拟表使用微信自定义分词器（`MMFtsTokenizer`），用普通 SQLite 查询这些虚拟表会报 `SQL logic error`；导出本身成功，普通表可正常读取。

分步执行：

```bash
cd WeChatSqlcipherKeyDumper

# 1) 构建 dumper（产物在 build/weixin-key-dumper.dylib）
bash src/weixin-key-dumper/build-dylib.sh

# 2) 准备工作区运行副本（首次或 WeChat 升级后；详见 docs 第 3 节）
bash scripts/build-runtime.sh

# 3) 完全退出 WeChat 后启动注入副本；结果直接写入 out/
bash src/weixin-key-dumper/run-dyld.sh

# 4) WeChat 打开/登录后查看结果（沙箱拒绝写 out/ 时会在 ~/Downloads）
ls out/                          # wechat_db_keys.json、xwechat_files/、weixin-key-dumper.log
```

dumper 启动时会在沙箱内对输出目录做一次写探测：`out/` 不可写时自动回退到 `~/Downloads`
（日志记一条 `warning: ... fell back to ...`）。此时把 Downloads 里的三个结果复制到 `out/`，
复制后立即删除 Downloads 中的副本。

不想注入时，也可以直接扫运行中 WeChat 的内存（需要关闭 SIP）：

```bash
bash src/lldb-scan/scan.sh        # 产出 out/wechat_db_keys.json
```

验证 fishhook 层（不启动 WeChat，全部产物留在 `build/`）：

```bash
bash src/weixin-key-dumper/test-dylib.sh
```

`LC_LOAD_DYLIB` 方式（可选，双击启动也能加载；需先构建 dylib）：

```bash
bash src/weixin-key-dumper/build-dylib.sh
bash src/inject/build-inject.sh                  # 产出 build/inject
```

能力 B 是内置的独立 fishhook dumper（无外部依赖），可单独构建：

```bash
bash src/wechat-key-dumper/build-dylib.sh        # 产出并签名 build/wechat-key-dumper.dylib
```

它使用自己的环境变量（`EXPORT_WECHAT_EMOJI_KEY_OUT` 等），不参与 `wechat_db_keys.json` 管线。

## 能力与输出

### 抓取方式


| 方式                              | 关闭 SIP | 修改二进制    | 需要 lldb | 入口                                         |
| ------------------------------- | ------ | -------- | ------- | ------------------------------------------ |
| lldb 扫内存                        | 是      | 否        | 是       | `src/lldb-scan/scan.sh`                    |
| `DYLD_INSERT_LIBRARIES` + dylib | 否      | 否        | 否       | `src/weixin-key-dumper/run-dyld.sh`        |
| `LC_LOAD_DYLIB` 头部注入            | 否      | 是（仅头部空隙） | 否       | `src/inject/build-inject.sh`（原理见文档第 5.1 节） |
| 独立 fishhook dumper              | 否      | 否        | 否       | `src/wechat-key-dumper/`（单独构建，见上）          |


dylib 内部并行使用两层挂钩：

- **`__DATA,__interpose`**：`CCCrypt`、`CCKeyDerivationPBKDF`。WeChat 各镜像都动态导入 CommonCrypto，这是实际生效的抓取路径。
- **fishhook**：`sqlite3_key` / `_v2`、`sqlite3_prepare_v2/v3`、`sqlite3_prepare16_v2/v3`、`sqlite3_exec`。用于动态链接 SQLite 的宿主；WeChat 主程序静态链接 codec 且不导入任何 `sqlite3_*` 符号，所以在 WeChat 内不会触发，仅作通用场景支持。

### 输出文件


| 文件                          | 内容                                                                                 |
| --------------------------- | ---------------------------------------------------------------------------------- |
| `out/wechat_db_keys.json`          | `{"<salt>": "<32 字节 key 的 hex>", ..., "_account": "wxid_...", "_db_map": {"<salt>": ["db_storage/..."]}}`，key 仅包含通过页解密校验的项；`_account` 为账号 wxid，`_db_map` 标明每个 salt 对应的库路径（lldb 扫描两者为空） |
| `out/xwechat_files/`        | 容器内全部 `.db` 及 `-wal`/`-shm`，保持账号目录下的相对路径（`db_storage/`、`login/` 等）；`.account` 记录账号 |
| `out/weixin-key-dumper.log` | 生命周期、挂钩命中与镜像统计，不写 key 本身                                                           |
| `out/xwechat_files/**/<NAME>_decrypted.db` | `scripts/decrypt-dbs.sh` 就地导出的明文 SQLite（与加密库同目录，权限 600）；原加密库保持只读，解密只写新文件          |


`wechat_db_keys.json` 等同于明文库钥匙：不要提交、上传或分享；`.gitignore` 已排除 `out/` 与构建产物。

## 文档

- 完整流程、SQLCipher 页面布局、密钥生成方式、LC_LOAD_DYLIB 实测：`docs/实现-获取WeChat本地数据库-WCDB-SQLCipher-密钥.md`
- fishhook / `__DATA,__interpose` 原理与对比：`docs/原理-fishhook-vs-interpose.md`

## 合规边界与免责声明

**本工具仅供个人学习、技术研究与本人数据备份使用，严禁任何商业用途。**

使用本工具即表示你已理解并同意以下全部条款：

- 仅处理本机、本人账号的数据；只解密数据副本，不改动原始数据；
- 不处理他人数据、不发布解密结果或密钥；
- 使用者须自行确认对目标设备、账号与数据拥有合法权限，并遵守所在地法律、WeChat 用户协议及相关软件许可；不得用于未授权访问、破解他人数据或任何违法用途；
- 不得重新分发 WeChat 客户端或其修改副本，也不得将本工具或产出用于对外提供解密、取证、数据提取等收费或托管服务；
- 敏感数据须妥善保管并仅用于本人数据备份，不得上传公共平台、云盘或提供给第三方，任务完成后及时删除；
- 本工具与腾讯及 WeChat 官方无任何关联，未获其授权或背书；相关商标归其权利人所有；
- 随本工具附带的第三方代码（如 fishhook）遵循其原始许可证；
- 本工具按“现状”（AS IS）提供，不附带任何明示或暗示的担保，包括但不限于适销性、特定用途适用性与不侵权担保；
- 作者不对使用本工具造成的任何直接或间接损失、数据损坏、账号封禁、法律责任等承担责任，一切后果由使用者自行承担。

如你不同意上述条款，请立即停止使用并删除本工具及全部产出。