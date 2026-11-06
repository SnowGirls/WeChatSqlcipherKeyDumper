# fishhook 与 `__DATA,__interpose`：两种挂钩方式的原理与边界

> 目标：在 macOS 上拦截第三方进程对 `sqlite3_key`、`CCKeyDerivationPBKDF`、`CCCrypt` 等函数的调用。
> 本文解释两种常用手段各自改写了什么、为什么有时“挂了但没触发”，以及 WeChatSqlcipherKeyDumper 为什么两层同时使用。

---

## 1. 一句话结论

| 手段 | 本质 | 生效对象 |
| --- | --- | --- |
| `__DATA,__interpose` | 告诉 **dyld**：“绑定到 A 的地方都改绑 B” | 所有镜像的**动态符号绑定** |
| fishhook | 自己解析 Mach-O，**直接改写已解析的调用槽** | 有符号槽的**已加载镜像** |

两者都只能影响“经过动态符号槽”的调用。**同镜像内直接调用**（静态链接、内部函数、编译器内联后的调用）既不过 dyld 绑定，也没有槽可改，因此两种方式都无效。

---

## 2. 背景：一次外部函数调用在 Mach-O 里长什么样

编译 `sqlite3_key(db, key, n)` 时，编译器并不知道目标地址，于是生成一次“经由槽位的间接调用”：

```
__TEXT,__text:         adrp x8, __got@PAGE
                       ldr  x8, [x8, __got@PAGEOFF]   ; 从槽里取函数地址
                       blr  x8                        ; 调过去

__DATA_CONST,__got:    .quad <sqlite3_key 的地址>       ; 非惰性槽
__DATA,__la_symbol_ptr: .quad <惰性绑定桩>              ; 惰性槽
```

- 槽位在文件里是占位值；**dyld 在启动时**（或首次调用时）把真实地址写进去。
- 调用方之后只认槽里的地址，不会再查符号表。
- 因此“挂钩”有两条路：
  1. 在 dyld 写槽时让它写我们的地址 → `__DATA,__interpose`；
  2. 在 dyld 写完之后，自己把槽改掉 → fishhook。

macOS 11+ 的可执行文件普遍使用 `LC_DYLD_CHAINED_FIXUPS`：槽位在文件里是链式编码（重基/绑定 + next 偏移），dyld 启动时遍历链并解码成真实地址。启动完成后，槽里就是普通指针，可以被再次改写。

---

## 3. `__DATA,__interpose` 的工作方式

在 dylib 里放一个二元组数组：

```c
typedef struct { const void *replacement; const void *replacee; } interpose_t;

__attribute__((used, section("__DATA,__interpose")))
static const interpose_t tuple = { (const void *)&my_open, (const void *)&open };
```

dyld 加载这个 dylib 时读取该段，建立“替换关系表”。此后**任何其他镜像**把某个符号绑定到 `replacee` 时，dyld 写入的地址变成 `replacement`。

特点：

- 不解析 Mach-O、不计算偏移、不直接改内存，**由 dyld 完成绑定**；对 chained fixups、惰性/非惰性槽都一致生效。
- 只对**动态导入**的符号有效。若目标在自己镜像内部定义并直接调用（静态链接），不会产生绑定，interpose 看不到。
- dyld 不会把 interpose 应用到“包含 interpose 段的镜像自身”，因此替换函数里再调用同名函数不会自我递归。
- 必须在目标进程**第一次绑定之前**加载：`DYLD_INSERT_LIBRARIES` 或 `LC_LOAD_DYLIB` 都可以；运行中途 `dlopen` 只能影响之后的新绑定。

WeChatSqlcipherKeyDumper 的入口：

```c
WX_INTERPOSE(wx_interpose_cccrypt, wx_CCCrypt, CCCrypt);
WX_INTERPOSE(wx_interpose_pbkdf2,  wx_pbkdf2,  CCKeyDerivationPBKDF);
```

---

## 4. fishhook 的工作方式

fishhook 不使用 dyld 的替换表，而是自己做 Mach-O 解析和内存改写：

1. 遍历已加载镜像（并注册 `_dyld_register_func_for_add_image` 处理后续加载）；
2. 读 `LC_SEGMENT_64`，只看 `__DATA` / `__DATA_CONST` 中类型为
   `S_LAZY_SYMBOL_POINTERS`（`__la_symbol_ptr`）或
   `S_NON_LAZY_SYMBOL_POINTERS`（`__got`）的 section；
3. `section->reserved1` 是该 section 在间接符号表中的起始下标；
4. 经 `LC_SYMTAB` 取 `nlist` 和字符串表，得到槽位对应的符号名；
5. 命中目标名后，保存旧值（供转发），用
   `vm_protect(..., VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)` 把该页变成可写，再把槽写成替换函数地址。

`__DATA_CONST` 在运行时是只读的，`VM_PROT_COPY` 会触发写时复制，只让本进程看到修改，不改变磁盘文件。

限制：

- 必须有槽。静态链接、同镜像直接调用、被内联的调用都没有槽。
- 只能在**镜像加载之后**改写。构造函数执行时槽已由 dyld 解析完毕，因此对已加载镜像是可行的（本项目 `src/weixin-key-dumper/test-dylib.sh` 在带 `LC_DYLD_CHAINED_FIXUPS` 的宿主上验证通过）。
- 若某个槽仍是未解析的惰性槽，或 loader 之后重新遍历链式修复信息，直接覆盖原始指针可能破坏元数据；生产路径应优先用 interpose，fishhook 作为补充。
- 只处理 `__DATA`/`__DATA_CONST`，不处理 `__AUTH`/`__AUTH_CONST` 的指针认证槽。

WeChatSqlcipherKeyDumper 的 fishhook 入口（`src/weixin-key-dumper/fishhook.c` + `src/weixin-key-dumper/weixin-key-dumper.c`）：

```c
{"sqlite3_key",        wx_fish_sqlite3_key,        &orig_sqlite3_key},
{"sqlite3_key_v2",     wx_fish_sqlite3_key_v2,     &orig_sqlite3_key_v2},
{"sqlite3_prepare_v2", wx_fish_prepare_v2,         &orig_sqlite3_prepare_v2},
{"sqlite3_prepare_v3", wx_fish_prepare_v3,         &orig_sqlite3_prepare_v3},
{"sqlite3_prepare16_v2", ...}, {"sqlite3_prepare16_v3", ...},
{"sqlite3_exec",       wx_fish_exec,               &orig_sqlite3_exec},
```

替换函数捕获参数后，优先经保存的原指针转发；原指针为空时用 `dlsym(RTLD_DEFAULT, ...)` 兜底。

---

## 5. 对比

| 维度 | `__DATA,__interpose` | fishhook |
| --- | --- | --- |
| 生效机制 | dyld 绑定期改目标 | 加载后改已解析的槽 |
| 需要解析 Mach-O | 否 | 是 |
| 需要改内存保护 | 否 | 是（`VM_PROT_COPY`） |
| 惰性/非惰性槽 | 都由 dyld 处理 | 需自行区分，依赖槽已解析 |
| chained fixups | 完全兼容 | 对已解析槽可行；未解析槽/链元数据有风险 |
| 静态链接/镜像内直接调用 | 无效 | 无效 |
| 加载时机 | 必须在首次绑定前 | 可在启动后任意时刻，但只能影响已加载镜像的槽 |
| 可否只对特定镜像生效 | 对所有镜像生效 | 可按镜像/槽选择 |
| 实现复杂度 | 极低（一个 section） | 高（Mach-O、符号表、内存保护） |
| 典型用途 | 系统调用拦截、跨镜像统一替换 | 第三方 App 内 hook、需要拿到原函数指针 |

---

## 6. WeChatSqlcipherKeyDumper 中的分工

### 6.1 为什么 CommonCrypto 走 interpose

WeChat 打开加密库时，`CCKeyDerivationPBKDF` 与 `CCCrypt` 都是**动态导入**的 CommonCrypto 符号，interpose 稳定生效：

```
CCKeyDerivationPBKDF(kCCPBKDF2, 32 字节口令, salt=文件头 16 字节,
                     rounds=256000, prf=5, dkLen=32)
        └─ 输出 32 字节 = SQLCipher AES-256 页密钥
```

`wx_pbkdf2` 先转发原函数，再把 32 字节输出加入候选；`wx_CCCrypt` 另外捕获每页加密使用的 32 字节 AES key。候选 key 必须通过“解密数据库第 1 页并检查页头”才会写入 `wechat_db_keys.json`。

### 6.2 为什么 SQLite 走 fishhook

`sqlite3_key` / `_v2` / `prepare*` / `exec` 由 fishhook 负责，捕获三类输入：

- `sqlite3_key(_v2)` 的 key 参数：`x'<96 hex>'`、裸 96 hex、32 字节 raw key；
- `prepare*` / `exec` 的 SQL 文本：扫描其中的 `x'<96 hex>'`，覆盖 `PRAGMA key = "x'...'"` 这类不经过 `sqlite3_key` 的写法；
- 捕获结果进入与 interpose 相同的 `add_key` / `add_raw_key` / 页解密校验管线。

**不再对 `sqlite3_key` 使用 interpose**，避免同一符号被两层同时改写：interpose 在绑定期把槽指向替换函数，fishhook 又在构造期改写同一槽，原函数指针的语义会变得难以预测。

### 6.3 在 WeChat 里实际发生了什么

对运行副本的扫描结果：

```
WeChat 主程序 / wechat.dylib / WeChatAppEx / 各 framework：
  动态导入的 sqlite3_key / prepare / exec 数量 = 0
  LC_DYLD_CHAINED_FIXUPS 存在
```

WeChat 的 SQLCipher codec 静态链接在自身镜像里，`sqlite3_key` 在定义镜像内部直接调用：
没有符号槽，interpose 和 fishhook 都看不到。**fishhook 的 SQLite 挂钩在 WeChat 内不会触发**，它的价值是：

- 对动态导入 SQLite 的宿主提供通用的密钥抓取路径；
- 对动态链接系统 `libsqlite3`/SQLCipher 的其他宿主有效（已用 `src/weixin-key-dumper/test-fixtures/test-sqlite.c` + `test-host.c` 验证）；
- 若未来 WeChat 把 codec 改为动态库，无需改代码即可生效。

WeChat 内真正可靠的路径仍是 `CCKeyDerivationPBKDF` 输出 + 页解密校验 + 内存扫描兜底。

### 6.4 数据流

```
CCKeyDerivationPBKDF ──32B 输出──┐
CCCrypt ──────────────32B key───┤
sqlite3_key/_v2 ──────key 参数──┼──> 候选集合 ──> 第 1 页 AES-CBC 解密校验 ──> wechat_db_keys.json
prepare*/exec ────────SQL 文本──┤                 （salt 必须命中已扫描的 .db）
进程内存扫描 ─────────x'96hex'──┘
```

---

## 7. 如何验证

### 7.1 静态检查

```bash
cd WeChatSqlcipherKeyDumper

# interpose 段应恰好有 2 个二元组（CCCrypt、PBKDF2）
otool -l build/weixin-key-dumper.dylib | grep -A4 -i __interpose

# fishhook 入口是导出符号；sqlite3_* 不再出现在未定义符号里
nm -gU build/weixin-key-dumper.dylib | grep wx_rebind_symbols
nm -u  build/weixin-key-dumper.dylib | grep -E 'CCCrypt|PBKDF2|sqlite3'
```

### 7.2 运行动态检查

```bash
bash src/weixin-key-dumper/test-dylib.sh
```

预期日志（`build/test-dylib/tmp/weixin-key-dumper.log`）：

```
fishhook: rc=0 key=0x... key_v2=0x... prepare_v2=0x... ...
fishhook sqlite3_key: nKey=32
fishhook sqlite3_key_v2: db=main nKey=99
fishhook sql: scanning 115 bytes
json written: 1 entries (...)
```

`src/weixin-key-dumper/test-fixtures/test-host.c` 通过 `build/libtest-sqlite.dylib` **导入**这些符号（而不是在自身定义），所以调用会经过符号槽；这正是 fishhook 能改写的场景。若把 `sqlite3_key` 直接定义在 test-host 内部，调用会变成镜像内直接调用，fishhook 不会触发——这正是 WeChat 的静态链接情形。

### 7.3 看 dyld 的 interpose 行为

```bash
DYLD_PRINT_INTERPOSING=1 DYLD_INSERT_LIBRARIES=$PWD/build/weixin-key-dumper.dylib \
  ./runtime/WeChat.app/Contents/MacOS/WeChat 2>&1 | grep -i interpos
```

只会看到 CommonCrypto 的替换；没有任何 `sqlite3_key` 的 interpose 记录，与静态链接的结论一致。

---

## 8. 常见失败原因

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 替换函数完全不触发 | 目标符号是静态链接/镜像内直接调用 | 改挂更外层的动态依赖（如 CommonCrypto） |
| interpose 只在 dlsym 时触发 | 目标镜像没有导入该符号 | 同上；或确认目标确实动态链接 |
| fishhook 找不到原函数 | 槽未解析、符号名不匹配、镜像未加载 | 用 `dlsym(RTLD_DEFAULT)` 兜底；确认 `nm -u` 有该符号 |
| 改写槽后崩溃 | 覆盖了未解析的惰性槽/链式元数据，或页不可写 | 优先 interpose；确认 `vm_protect` 成功；只改已解析槽 |
| 注入后进程直接退出 | hardened runtime / library validation 阻止加载 | 重签去除 hardened runtime，保留必要 entitlements |
| `DYLD_INSERT_LIBRARIES` 不生效 | SIP 限制或 App 带 `CS_RESTRICT` | 用工作区重签副本；必要时改用 `LC_LOAD_DYLIB` |

---

## 9. 参考

- fishhook（Facebook，BSD/Public Domain）：<https://github.com/facebook/fishhook>
- Apple `dyld` 源码中的 interpose 处理：`dyld/DyldProcessConfig.cpp`、`dyld/DyldRuntimeState.cpp`
- Mach-O 格式：`<mach-o/loader.h>`、`<mach-o/nlist.h>`、`<mach-o/dyld.h>`
