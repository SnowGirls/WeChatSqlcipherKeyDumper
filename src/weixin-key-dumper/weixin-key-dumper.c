// weixin-key-dumper.dylib - launch-time SQLCipher raw-key capture for WeChat (Route B).
//
// Two hook layers run side by side:
//
//   1. __DATA,__interpose (dyld): CCCrypt and CCKeyDerivationPBKDF.  Every image
//      imports CommonCrypto dynamically, and dyld redirects those binds before
//      any WeChat code runs.  This is the reliable capture path.
//   2. fishhook (see fishhook.c): sqlite3_key/_v2 and the prepare*/exec family.
//      It rewrites call slots in images that import SQLite dynamically, which
//      covers hosts other than WeChat.  WeChat's SQLCipher codec is statically
//      linked and the main binary imports no sqlite3 symbol, so these hooks do
//      not fire inside WeChat itself; they remain a fallback for dynamically
//      linked clients.
//
// Every candidate 32-byte key is verified in-process by decrypting page 1 of a
// known DB (AES-256-CBC, SQLCipher 4 layout: salt16 | ciphertext | iv16 | hmac64)
// and checking the recovered page header.  Only verified keys are emitted, so the
// JSON never carries network-session keys.
//
// Output:   $HOME/tmp/wechat_db_keys.json   {"<salt>": "<key>", ..., "_account": "wxid_...", "_db_map": {"<salt>": ["db_storage/..."]}}
//           $HOME/tmp/weixin-key-dumper.log  counts and lifecycle only, never key material
//           $WX_DUMP_DIR/xwechat_files/     encrypted copies of every .db (+ wal/shm),
//                                    so a downstream tool can read the copies
//                                    despite TCC blocking direct container access
//
// Under WeChat's app sandbox $HOME is the container Data directory, so the file
// lands in ~/Library/Containers/com.tencent.xinWeChat/Data/tmp/.  The same bytes
// are also written to $WX_DUMP_DIR (a directory the sandbox may write through the
// app's entitlements; defaults to the real user's ~/Downloads).  At startup the
// dumper probes $WX_DUMP_DIR from inside the sandbox and falls back to
// ~/Downloads when the write is denied.  Pass WX_DUMP_DIR at launch to ask for a
// drop dir, e.g.
//   WX_DUMP_DIR=$PWD/out DYLD_INSERT_LIBRARIES=... ./runtime/WeChat.app/...
// run-dyld.sh points WX_DUMP_DIR at WeChatSqlcipherKeyDumper/out/ by default.

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "fishhook.h"

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

#define MAX_KEYS    1024
#define MAX_DBSALTS 512
#define CHUNK_BYTES (1u << 20)
#define OVERLAP     98

#define PAGE_BYTES  4096
#define PAGE_SALT   16
#define PAGE_IV     16
#define PAGE_HMAC   64
#define PAGE_CIPHER (PAGE_BYTES - PAGE_SALT - PAGE_IV - PAGE_HMAC)

static char g_salt[MAX_KEYS][33];
static char g_key[MAX_KEYS][65];
static int  g_nkeys = 0;

static char g_dbsalt[MAX_DBSALTS][33];
static char g_dbpath[MAX_DBSALTS][PATH_MAX];
static int  g_ndbsalt = 0;

static unsigned char g_rawkey[MAX_KEYS][32];
static int g_nrawkey = 0;
static signed char g_pair[MAX_KEYS][MAX_DBSALTS];   // 0 unknown, 1 verified, 2 rejected

static int g_dirty = 1;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static char g_home[PATH_MAX];
static char g_json[PATH_MAX];
static char g_json_tmp[PATH_MAX];
static char g_log[PATH_MAX];

static char g_json_dl[PATH_MAX];
static char g_json_dl_tmp[PATH_MAX];
static char g_log_dl[PATH_MAX];
static char g_realhome[PATH_MAX];
static char g_dumpdir[PATH_MAX];
static char g_dump_warn[PATH_MAX];

static void mkdir_p(const char *path);
static void wlog(const char *fmt, ...);

static unsigned char g_buf[CHUNK_BYTES + OVERLAP];

static int dir_writable(const char *dir) {
    char probe[PATH_MAX];
    snprintf(probe, sizeof probe, "%s/.wxprobe.%d", dir, (int)getpid());
    FILE *f = fopen(probe, "w");
    if (!f) return 0;
    fputs("probe", f);
    fclose(f);
    unlink(probe);
    return 1;
}

static void init_paths(void) {
    const char *h = getenv("HOME");
    if (!h || !*h) h = "/";
    snprintf(g_home, sizeof g_home, "%s", h);
    snprintf(g_json, sizeof g_json, "%s/tmp/wechat_db_keys.json", g_home);
    snprintf(g_json_tmp, sizeof g_json_tmp, "%s/tmp/wechat_db_keys.json.tmp.%d", g_home, (int)getpid());
    snprintf(g_log, sizeof g_log, "%s/tmp/weixin-key-dumper.log", g_home);

    // getpwuid resolves the real home even under the app sandbox; $HOME is the container.
    struct passwd *pw = getpwuid(getuid());
    const char *rh = (pw && pw->pw_dir && *pw->pw_dir) ? pw->pw_dir : g_home;
    snprintf(g_realhome, sizeof g_realhome, "%s", rh);

    char downloads[PATH_MAX];
    snprintf(downloads, sizeof downloads, "%s/Downloads", rh);

    const char *dd = getenv("WX_DUMP_DIR");
    if (dd && *dd) {
        snprintf(g_dumpdir, sizeof g_dumpdir, "%s", dd);
        mkdir_p(g_dumpdir);
    } else {
        snprintf(g_dumpdir, sizeof g_dumpdir, "%s", downloads);
    }

    // The sandbox, not file mode bits, decides what this process may write, so
    // probe from inside and fall back to ~/Downloads (granted by the app's
    // downloads entitlement).  Keys still land under $HOME/tmp either way.
    if (!dir_writable(g_dumpdir)) {
        snprintf(g_dump_warn, sizeof g_dump_warn, "%s", g_dumpdir);
        mkdir_p(downloads);
        if (strcmp(g_dumpdir, downloads) != 0 && dir_writable(downloads))
            snprintf(g_dumpdir, sizeof g_dumpdir, "%s", downloads);
    }

    snprintf(g_json_dl, sizeof g_json_dl, "%s/wechat_db_keys.json", g_dumpdir);
    snprintf(g_json_dl_tmp, sizeof g_json_dl_tmp, "%s/wechat_db_keys.json.tmp.%d", g_dumpdir, (int)getpid());
    snprintf(g_log_dl, sizeof g_log_dl, "%s/weixin-key-dumper.log", g_dumpdir);

    if (g_dump_warn[0]) {
        if (strcmp(g_dump_warn, g_dumpdir) != 0)
            wlog("warning: %s not writable, fell back to %s", g_dump_warn, g_dumpdir);
        else
            wlog("warning: %s not writable; results only under $HOME/tmp", g_dump_warn);
    }
}

static void log_append(const char *path, const char *line) {
    FILE *f = fopen(path, "a");
    if (!f) return;
    fputs(line, f);
    fflush(f);
    fclose(f);
}

static void wlog(const char *fmt, ...) {
    char ts[32];
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);

    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);

    char line[1120];
    snprintf(line, sizeof line, "%s %s\n", ts, body);
    log_append(g_log, line);
    if (g_log_dl[0]) log_append(g_log_dl, line);
}

static int salt_known_locked(const char *salt) {
    for (int i = 0; i < g_nkeys; i++)
        if (strcmp(g_salt[i], salt) == 0) return 1;
    return 0;
}

static int dbsalt_known_locked(const char *salt) {
    for (int i = 0; i < g_ndbsalt; i++)
        if (strcmp(g_dbsalt[i], salt) == 0) return 1;
    return 0;
}

static void add_key(const char *key64, const char *salt32) {
    pthread_mutex_lock(&g_lock);
    if (!salt_known_locked(salt32) && g_nkeys < MAX_KEYS) {
        memcpy(g_key[g_nkeys], key64, 64);
        g_key[g_nkeys][64] = 0;
        memcpy(g_salt[g_nkeys], salt32, 32);
        g_salt[g_nkeys][32] = 0;
        g_nkeys++;
        g_dirty = 1;
    }
    pthread_mutex_unlock(&g_lock);
}

static void add_raw_key(const unsigned char *k32) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nrawkey; i++)
        if (memcmp(g_rawkey[i], k32, 32) == 0) {
            pthread_mutex_unlock(&g_lock);
            return;
        }
    if (g_nrawkey < MAX_KEYS) {
        memcpy(g_rawkey[g_nrawkey], k32, 32);
        g_nrawkey++;
        g_dirty = 1;
    }
    pthread_mutex_unlock(&g_lock);
}

static void add_dbsalt(const char *salt32, const char *path) {
    pthread_mutex_lock(&g_lock);
    if (!dbsalt_known_locked(salt32) && g_ndbsalt < MAX_DBSALTS) {
        memcpy(g_dbsalt[g_ndbsalt], salt32, 32);
        g_dbsalt[g_ndbsalt][32] = 0;
        snprintf(g_dbpath[g_ndbsalt], PATH_MAX, "%s", path);
        g_ndbsalt++;
    }
    pthread_mutex_unlock(&g_lock);
}

static int is_hex(const unsigned char *p, int n) {
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

// h points at the 96 hex characters that follow the leading x'
static void handle_hex96(const unsigned char *h) {
    char key[65];
    char salt[33];
    memcpy(key, h, 64);
    key[64] = 0;
    for (int i = 0; i < 32; i++) {
        unsigned char c = h[64 + i];
        if (c >= 'A' && c <= 'F') c = (unsigned char)(c - 'A' + 'a');
        salt[i] = (char)c;
    }
    salt[32] = 0;
    add_key(key, salt);
}

static void scan_bytes(const unsigned char *p, size_t n) {
    if (n < 99) return;
    const unsigned char *end = p + n - 99;
    const unsigned char *q = p;
    while (q <= end) {
        const unsigned char *m = memchr(q, 'x', (size_t)(end - q) + 1);
        if (!m) break;
        if (m[1] == '\'' && m[98] == '\'' && is_hex(m + 2, 96))
            handle_hex96(m + 2);
        q = m + 1;
    }
}

static void scan_region(mach_vm_address_t base, mach_vm_size_t size) {
    mach_vm_size_t off = 0;
    size_t carry = 0;
    while (off < size) {
        mach_vm_size_t want = size - off;
        if (want > CHUNK_BYTES) want = CHUNK_BYTES;
        mach_vm_size_t got = 0;
        kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), base + off, want,
                                                  (mach_vm_address_t)(uintptr_t)(g_buf + carry),
                                                  &got);
        if (kr == KERN_SUCCESS && got > 0) {
            size_t total = carry + (size_t)got;
            scan_bytes(g_buf, total);
            size_t keep = total < OVERLAP ? total : OVERLAP;
            memmove(g_buf, g_buf + total - keep, keep);
            carry = keep;
        } else {
            carry = 0;
        }
        off += want;
    }
}

static uint64_t g_scanned_bytes;

static void scan_once(void) {
    mach_vm_address_t addr = 0;
    g_scanned_bytes = 0;
    for (;;) {
        mach_vm_size_t rsize = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &rsize, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), object);
        if (kr != KERN_SUCCESS || rsize == 0) break;
        if (info.protection & VM_PROT_READ) {
            if (info.protection & VM_PROT_WRITE) {
                if (rsize <= 4ULL * 1024 * 1024 * 1024) {
                    scan_region(addr, rsize);
                    g_scanned_bytes += rsize;
                }
            } else if (rsize <= 256ULL * 1024 * 1024) {
                scan_region(addr, rsize);
                g_scanned_bytes += rsize;
            }
        }
        mach_vm_address_t next = addr + rsize;
        if (next <= addr) break;
        addr = next;
    }
}

static int has_suffix_ci(const char *s, const char *suf) {
    size_t ls = strlen(s), lf = strlen(suf);
    if (ls < lf) return 0;
    return strcasecmp(s + ls - lf, suf) == 0;
}

static void walk_dbs(const char *dir, int depth) {
    if (depth > 6) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (n < 0 || (size_t)n >= sizeof path) continue;
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            walk_dbs(path, depth + 1);
        } else if (S_ISREG(st.st_mode) && has_suffix_ci(e->d_name, ".db")) {
            unsigned char hdr[16];
            FILE *f = fopen(path, "rb");
            if (!f) continue;
            size_t got = fread(hdr, 1, sizeof hdr, f);
            fclose(f);
            if (got == sizeof hdr) {
                char salt[33];
                for (int i = 0; i < 16; i++)
                    snprintf(salt + i * 2, 3, "%02x", hdr[i]);
                salt[32] = 0;
                add_dbsalt(salt, path);
            }
        }
    }
    closedir(d);
}

static void collect_db_salts(void) {
    char root[PATH_MAX];
    snprintf(root, sizeof root, "%s/Documents/xwechat_files", g_home);
    walk_dbs(root, 0);
    wlog("db scan: %d salt(s) found", g_ndbsalt);
}

// The host shell is blocked by TCC from reading the container, but this process
// runs inside WeChat's sandbox, so it can copy the encrypted DBs (and their
// WAL/SHM sidecars) into $WX_DUMP_DIR (default ~/Downloads because that is the
// only sandbox-writable drop-off with the stock entitlements; pass WX_DUMP_DIR
// to target the project out directory when the sandbox permits it).
// Every .db discovered under xwechat_files/<account>/ is mirrored, preserving
// the relative path (e.g. db_storage/message/message_0.db).

static void mkdir_p(const char *path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static long long copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    char part[PATH_MAX];
    snprintf(part, sizeof part, "%s.part", dst);
    FILE *out = fopen(part, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }
    static unsigned char cbuf[1 << 20];
    size_t n;
    long long total = 0;
    while ((n = fread(cbuf, 1, sizeof cbuf, in)) > 0) {
        if (fwrite(cbuf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            unlink(part);
            return -1;
        }
        total += (long long)n;
    }
    fclose(in);
    if (fclose(out) != 0) {
        unlink(part);
        return -1;
    }
    if (rename(part, dst) != 0) {
        unlink(part);
        return -1;
    }
    return total;
}

static void write_account_file(const char *root, const char *dbpath) {
    const char *file = strstr(dbpath, "/xwechat_files/");
    const char *storage = strstr(dbpath, "/db_storage/");
    if (!file || !storage || storage <= file) return;
    file += strlen("/xwechat_files/");
    size_t n = (size_t)(storage - file);
    if (n == 0 || n >= 256) return;
    char acc[256];
    memcpy(acc, file, n);
    acc[n] = 0;
    char f[PATH_MAX];
    snprintf(f, sizeof f, "%s/.account", root);
    FILE *fp = fopen(f, "w");
    if (!fp) return;
    fputs(acc, fp);
    fputc('\n', fp);
    fclose(fp);
    wlog("db mirror: account=%s", acc);
}

static void mirror_all_dbs(void) {
    char root[PATH_MAX];
    snprintf(root, sizeof root, "%s/xwechat_files", g_dumpdir);
    mkdir_p(root);
    int copied = 0;
    long long grand = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_ndbsalt; i++) {
        const char *p = strstr(g_dbpath[i], "/xwechat_files/");
        if (!p) continue;
        p += strlen("/xwechat_files/");
        const char *slash = strchr(p, '/');   // end of account directory
        if (!slash || !slash[1]) continue;
        const char *rel = slash + 1;          // db_storage/<dir>/<name>.db

        char dst[PATH_MAX];
        int n = snprintf(dst, sizeof dst, "%s/%s", root, rel);
        if (n < 0 || (size_t)n >= sizeof dst) continue;
        char parent[PATH_MAX];
        snprintf(parent, sizeof parent, "%s", dst);
        char *last = strrchr(parent, '/');
        if (last) {
            *last = 0;
            mkdir_p(parent);
        }
        static const char *const sufs[] = {"", "-wal", "-shm"};
        long long total = 0;
        for (int s = 0; s < 3; s++) {
            char src[PATH_MAX], d[PATH_MAX];
            snprintf(src, sizeof src, "%s%s", g_dbpath[i], sufs[s]);
            snprintf(d, sizeof d, "%s%s", dst, sufs[s]);
            if (access(src, R_OK) != 0) continue;
            long long nb = copy_file(src, d);
            if (nb < 0)
                wlog("db copy: %s%s failed", rel, sufs[s]);
            else
                total += nb;
        }
        wlog("db copy: %s (%lld bytes incl. wal/shm)", rel, total);
        write_account_file(root, g_dbpath[i]);
        copied++;
        grand += total;
    }
    pthread_mutex_unlock(&g_lock);
    wlog("db mirror: %d db(s), %lld bytes total -> %s", copied, grand, root);
}

// SQLCipher 4 page 1: salt(16) | AES-256-CBC ciphertext | iv(16) | hmac-sha512(64).
// The recovered plaintext starts at logical offset 16, i.e. the two page-size
// bytes (0x10 0x00 for 4096) followed by the write/read format versions.
static int verify_pair(const unsigned char *key32, int idx) {
    if (idx < 0 || idx >= g_ndbsalt) return 0;
    unsigned char page[PAGE_BYTES];
    FILE *f = fopen(g_dbpath[idx], "rb");
    if (!f) return 0;
    size_t got = fread(page, 1, sizeof page, f);
    fclose(f);
    if (got != sizeof page) return 0;

    unsigned char out[PAGE_CIPHER];
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0,
                                 key32, 32,
                                 page + PAGE_BYTES - PAGE_HMAC - PAGE_IV,
                                 page + PAGE_SALT, PAGE_CIPHER,
                                 out, sizeof out, &moved);
    if (st != kCCSuccess || moved != PAGE_CIPHER) return 0;
    return (out[0] == 0x10 && out[1] == 0x00 && out[2] <= 2) ? 1 : 0;
}

static int salt_in_list(const char list[][33], int n, const char *salt) {
    for (int i = 0; i < n; i++)
        if (strcmp(list[i], salt) == 0) return 1;
    return 0;
}

// dbpath = .../xwechat_files/<account>/db_storage/... -> db_storage/...
static int db_rel_path(const char *dbpath, char *out, size_t outn) {
    const char *p = strstr(dbpath, "/xwechat_files/");
    if (!p) return 0;
    p += strlen("/xwechat_files/");
    const char *slash = strchr(p, '/');
    if (!slash || !slash[1]) return 0;
    int n = snprintf(out, outn, "%s", slash + 1);
    return n > 0 && (size_t)n < outn;
}

// dbpath = .../xwechat_files/<account>/... -> <account>
static int db_account(const char *dbpath, char *out, size_t outn) {
    const char *p = strstr(dbpath, "/xwechat_files/");
    if (!p) return 0;
    p += strlen("/xwechat_files/");
    const char *slash = strchr(p, '/');
    if (!slash) return 0;
    size_t n = (size_t)(slash - p);
    if (n == 0 || n >= outn) return 0;
    memcpy(out, p, n);
    out[n] = 0;
    return 1;
}

static int write_json_file(const char *tmp_path, const char *final_path) {
    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;
    int filtered = (g_ndbsalt > 0);
    int emitted = 0;
    int verified = 0;
    char emitted_salts[MAX_KEYS][33];
    int n_es = 0;
    fputs("{\n", f);
    for (int i = 0; i < g_nkeys; i++) {
        if (filtered && !dbsalt_known_locked(g_salt[i])) continue;
        if (salt_in_list(emitted_salts, n_es, g_salt[i])) continue;
        fprintf(f, "%s  \"%s\": \"%s\"", emitted ? ",\n" : "", g_salt[i], g_key[i]);
        emitted++;
        if (n_es < MAX_KEYS) snprintf(emitted_salts[n_es++], 33, "%s", g_salt[i]);
    }
    // Raw 32-byte candidates carry no salt; only emit pairs whose key decrypts
    // that database's first page.
    if (g_ndbsalt > 0) {
        for (int s = 0; s < g_ndbsalt; s++) {
            if (salt_known_locked(g_dbsalt[s])) continue;
            if (salt_in_list(emitted_salts, n_es, g_dbsalt[s])) continue;
            for (int r = 0; r < g_nrawkey; r++) {
                signed char *cell = &g_pair[r][s];
                if (*cell == 0) *cell = verify_pair(g_rawkey[r], s) ? 1 : 2;
                if (*cell != 1) continue;
                char keyhex[65];
                for (int j = 0; j < 32; j++)
                    snprintf(keyhex + j * 2, 3, "%02x", g_rawkey[r][j]);
                keyhex[64] = 0;
                fprintf(f, "%s  \"%s\": \"%s\"", emitted ? ",\n" : "", g_dbsalt[s], keyhex);
                emitted++;
                verified++;
                if (n_es < MAX_KEYS) snprintf(emitted_salts[n_es++], 33, "%s", g_dbsalt[s]);
                break;
            }
        }
    }
    if (n_es > 0) {
        // Prefer the real account dir: all_users holds shared/login DBs, so the
        // first scanned path is not necessarily the user's wxid.
        char account[256] = "";
        for (int s = 0; s < g_ndbsalt && !account[0]; s++) {
            char acc[256];
            if (db_account(g_dbpath[s], acc, sizeof acc) && strncasecmp(acc, "wxid_", 5) == 0)
                snprintf(account, sizeof account, "%s", acc);
        }
        for (int s = 0; s < g_ndbsalt && !account[0]; s++) {
            char acc[256];
            if (!db_account(g_dbpath[s], acc, sizeof acc)) continue;
            if (strcmp(acc, "all_users") != 0)
                snprintf(account, sizeof account, "%s", acc);
        }
        if (!account[0] && g_ndbsalt > 0)
            db_account(g_dbpath[0], account, sizeof account);
        fprintf(f, ",\n  \"_account\": \"%s\"", account);
        int map_entries = 0;
        fputs(",\n  \"_db_map\": {", f);
        for (int e = 0; e < n_es; e++) {
            int started = 0;
            for (int s = 0; s < g_ndbsalt; s++) {
                if (strcmp(g_dbsalt[s], emitted_salts[e]) != 0) continue;
                char rel[PATH_MAX];
                if (!db_rel_path(g_dbpath[s], rel, sizeof rel)) continue;
                int dup = 0;
                for (int j = 0; j < s && !dup; j++) {
                    char prev[PATH_MAX];
                    if (strcmp(g_dbsalt[j], emitted_salts[e]) != 0) continue;
                    if (db_rel_path(g_dbpath[j], prev, sizeof prev) && strcmp(prev, rel) == 0)
                        dup = 1;
                }
                if (dup) continue;
                if (!started) {
                    fprintf(f, "%s\n    \"%s\": [", map_entries ? "," : "", emitted_salts[e]);
                    started = 1;
                    map_entries++;
                } else {
                    fputs(", ", f);
                }
                fprintf(f, "\"%s\"", rel);
            }
            if (started) fputs("]", f);
        }
        fputs("\n  }", f);
    }
    fputs("\n}\n", f);
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    if (rename(tmp_path, final_path) != 0) return -1;
    static int last_verified = -1;
    if (verified != last_verified) {
        wlog("verify: %d pair(s) via page-1 decrypt (raw=%d db salts=%d)",
             verified, g_nrawkey, g_ndbsalt);
        last_verified = verified;
    }
    return emitted;
}

static void write_json(void) {
    pthread_mutex_lock(&g_lock);
    int emitted = write_json_file(g_json_tmp, g_json);
    if (emitted < 0)
        wlog("warning: could not write %s", g_json);
    if (g_json_dl[0]) {
        int mirror = write_json_file(g_json_dl_tmp, g_json_dl);
        if (mirror < 0)
            wlog("warning: could not write %s", g_json_dl);
    }
    g_dirty = 0;
    pthread_mutex_unlock(&g_lock);
    wlog("json written: %d entries (keys=%d raw=%d db salts=%d)",
         emitted < 0 ? 0 : emitted, g_nkeys, g_nrawkey, g_ndbsalt);
}

static void capture_key_bytes(const void *p, int n) {
    if (!p || n <= 0) return;
    const unsigned char *s = (const unsigned char *)p;
    if (n == 99 && s[0] == 'x' && s[1] == '\'' && s[98] == '\'' && is_hex(s + 2, 96))
        handle_hex96(s + 2);
    else if (n == 96 && is_hex(s, 96))
        handle_hex96(s);
    else if (n == 32)
        add_raw_key(s);
}

static void *mirror_main(void *arg) {
    (void)arg;
    mirror_all_dbs();
    return NULL;
}

static void *scanner_main(void *arg) {
    (void)arg;
    collect_db_salts();
    wlog("scanner start: pid=%d", (int)getpid());
    write_json();   // keys captured so far must land even if mirroring is slow
    pthread_t mt;
    if (pthread_create(&mt, NULL, mirror_main, NULL) == 0)
        pthread_detach(mt);
    else
        wlog("error: mirror thread could not start");
    for (int i = 0; i < 2880; i++) {
        scan_once();
        if (g_dirty) write_json();
        sleep(i < 150 ? 2 : 30);
    }
    write_json();
    wlog("scanner stopped after scan budget: %d key(s)", g_nkeys);
    return NULL;
}

// ---- interposed entry points (CommonCrypto) ---------------------------------

__attribute__((used)) static CCCryptorStatus wx_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
                                                    const void *key, size_t keyLength, const void *iv,
                                                    const void *dataIn, size_t dataInLength,
                                                    void *dataOut, size_t dataOutAvailable,
                                                    size_t *dataOutMoved) {
    if (alg == kCCAlgorithmAES && keyLength == 32 && key) {
        static int logged = 0;
        if (logged < 40) {
            wlog("cccrypt: op=%d alg=%u keylen=%zu datalen=%zu", (int)op, (unsigned)alg,
                 keyLength, dataInLength);
            logged++;
        }
        add_raw_key((const unsigned char *)key);
    }
    return CCCrypt(op, alg, options, key, keyLength, iv, dataIn, dataInLength,
                   dataOut, dataOutAvailable, dataOutMoved);
}

__attribute__((used)) static int wx_pbkdf2(CCPBKDFAlgorithm algorithm, const char *password,
                                              size_t passwordLen, const uint8_t *salt,
                                              size_t saltLen, CCPseudoRandomAlgorithm prf,
                                              uint32_t rounds, uint8_t *derivedKey,
                                              size_t derivedKeyLen) {
    if (algorithm == kCCPBKDF2 && salt && saltLen == 16) {
        static int logged = 0;
        if (logged < 20) {
            char sh[33];
            for (int i = 0; i < 16; i++) snprintf(sh + i * 2, 3, "%02x", salt[i]);
            sh[32] = 0;
            wlog("pbkdf2: pass_len=%zu salt=%s rounds=%u prf=%d dk_len=%zu",
                 passwordLen, sh, rounds, (int)prf, derivedKeyLen);
            logged++;
        }
        char match[33];
        int hit = 0;
        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < g_ndbsalt && !hit; i++) {
            unsigned char kdf[16], mac[16];
            for (int j = 0; j < 16; j++) {
                kdf[j] = salt[j];
                mac[j] = salt[j] ^ 0x3a;
            }
            char kdf_hex[33], mac_hex[33];
            for (int j = 0; j < 16; j++) {
                snprintf(kdf_hex + j * 2, 3, "%02x", kdf[j]);
                snprintf(mac_hex + j * 2, 3, "%02x", mac[j]);
            }
            kdf_hex[32] = mac_hex[32] = 0;
            if ((rounds > 2 && strcmp(kdf_hex, g_dbsalt[i]) == 0) ||
                (rounds <= 2 && strcmp(mac_hex, g_dbsalt[i]) == 0) ||
                strcmp(kdf_hex, g_dbsalt[i]) == 0) {
                snprintf(match, sizeof match, "%s", g_dbsalt[i]);
                hit = 1;
            }
        }
        pthread_mutex_unlock(&g_lock);
        if (hit)
            wlog("pbkdf2 hit: matched db salt=%s rounds=%u pass_len=%zu", match, rounds, passwordLen);
    }
    int rc = CCKeyDerivationPBKDF(algorithm, password, passwordLen, salt, saltLen, prf,
                                  rounds, derivedKey, derivedKeyLen);
    // The 32-byte 256000-round output is SQLCipher's AES-256 page key; the HMAC
    // fast-kdf output fails page-1 verification and is dropped there.
    if (rc == 0 && algorithm == kCCPBKDF2 && saltLen == 16 && derivedKey && derivedKeyLen == 32)
        add_raw_key(derivedKey);
    return rc;
}

// ---- fishhook entry points (SQLite) -----------------------------------------
//
// These only see calls that go through an imported symbol slot.  They capture
// the same formats the interpose path does: x'<96 hex>', bare 96-hex, and raw
// 32-byte keys.  SQL text is scanned for x'<96 hex>' so a PRAGMA key statement
// is captured even when it never reaches sqlite3_key.

typedef int (*wx_key_fn)(sqlite3 *, const void *, int);
typedef int (*wx_key_v2_fn)(sqlite3 *, const char *, const void *, int);
typedef int (*wx_prepare_v2_fn)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
typedef int (*wx_prepare_v3_fn)(sqlite3 *, const char *, int, unsigned int, sqlite3_stmt **,
                               const char **);
typedef int (*wx_prepare16_v2_fn)(sqlite3 *, const void *, int, sqlite3_stmt **, const void **);
typedef int (*wx_prepare16_v3_fn)(sqlite3 *, const void *, int, unsigned int, sqlite3_stmt **,
                                  const void **);
typedef int (*wx_exec_fn)(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *,
                          char **);

static wx_key_fn orig_sqlite3_key;
static wx_key_v2_fn orig_sqlite3_key_v2;
static wx_prepare_v2_fn orig_sqlite3_prepare_v2;
static wx_prepare_v3_fn orig_sqlite3_prepare_v3;
static wx_prepare16_v2_fn orig_sqlite3_prepare16_v2;
static wx_prepare16_v3_fn orig_sqlite3_prepare16_v3;
static wx_exec_fn orig_sqlite3_exec;

#define WX_SQLITE_MISUSE 21

static void capture_sql_text(const char *sql, int nByte) {
    if (!sql) return;
    size_t n = (nByte < 0) ? strlen(sql) : (size_t)nByte;
    if (n < 99) return;
    static int logged = 0;
    if (logged < 8) {
        wlog("fishhook sql: scanning %zu bytes", n);
        logged++;
    }
    scan_bytes((const unsigned char *)sql, n);
}

static int wx_fish_sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
    if (nKey > 0) wlog("fishhook sqlite3_key: nKey=%d", nKey);
    capture_key_bytes(pKey, nKey);
    wx_key_fn fn = orig_sqlite3_key;
    if (!fn) fn = (wx_key_fn)dlsym(RTLD_DEFAULT, "sqlite3_key");
    return fn ? fn(db, pKey, nKey) : 0;
}

static int wx_fish_sqlite3_key_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
    wlog("fishhook sqlite3_key_v2: db=%s nKey=%d", zDb ? zDb : "(null)", nKey);
    capture_key_bytes(pKey, nKey);
    wx_key_v2_fn fn = orig_sqlite3_key_v2;
    if (!fn) fn = (wx_key_v2_fn)dlsym(RTLD_DEFAULT, "sqlite3_key_v2");
    return fn ? fn(db, zDb, pKey, nKey) : 0;
}

static int wx_fish_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt,
                              const char **pzTail) {
    capture_sql_text(zSql, nByte);
    wx_prepare_v2_fn fn = orig_sqlite3_prepare_v2;
    if (!fn) fn = (wx_prepare_v2_fn)dlsym(RTLD_DEFAULT, "sqlite3_prepare_v2");
    return fn ? fn(db, zSql, nByte, ppStmt, pzTail) : WX_SQLITE_MISUSE;
}

static int wx_fish_prepare_v3(sqlite3 *db, const char *zSql, int nByte, unsigned int prepFlags,
                              sqlite3_stmt **ppStmt, const char **pzTail) {
    capture_sql_text(zSql, nByte);
    wx_prepare_v3_fn fn = orig_sqlite3_prepare_v3;
    if (!fn) fn = (wx_prepare_v3_fn)dlsym(RTLD_DEFAULT, "sqlite3_prepare_v3");
    return fn ? fn(db, zSql, nByte, prepFlags, ppStmt, pzTail) : WX_SQLITE_MISUSE;
}

static int wx_fish_prepare16_v2(sqlite3 *db, const void *zSql, int nByte, sqlite3_stmt **ppStmt,
                                const void **pzTail) {
    capture_sql_text((const char *)zSql, nByte);
    wx_prepare16_v2_fn fn = orig_sqlite3_prepare16_v2;
    if (!fn) fn = (wx_prepare16_v2_fn)dlsym(RTLD_DEFAULT, "sqlite3_prepare16_v2");
    return fn ? fn(db, zSql, nByte, ppStmt, pzTail) : WX_SQLITE_MISUSE;
}

static int wx_fish_prepare16_v3(sqlite3 *db, const void *zSql, int nByte, unsigned int prepFlags,
                                sqlite3_stmt **ppStmt, const void **pzTail) {
    capture_sql_text((const char *)zSql, nByte);
    wx_prepare16_v3_fn fn = orig_sqlite3_prepare16_v3;
    if (!fn) fn = (wx_prepare16_v3_fn)dlsym(RTLD_DEFAULT, "sqlite3_prepare16_v3");
    return fn ? fn(db, zSql, nByte, prepFlags, ppStmt, pzTail) : WX_SQLITE_MISUSE;
}

static int wx_fish_exec(sqlite3 *db, const char *sql,
                        int (*callback)(void *, int, char **, char **), void *arg, char **errmsg) {
    capture_sql_text(sql, -1);
    wx_exec_fn fn = orig_sqlite3_exec;
    if (!fn) fn = (wx_exec_fn)dlsym(RTLD_DEFAULT, "sqlite3_exec");
    return fn ? fn(db, sql, callback, arg, errmsg) : WX_SQLITE_MISUSE;
}

static void install_fishhook(void) {
    struct wx_rebinding binds[] = {
        {"sqlite3_key", (void *)wx_fish_sqlite3_key, (void **)&orig_sqlite3_key},
        {"sqlite3_key_v2", (void *)wx_fish_sqlite3_key_v2, (void **)&orig_sqlite3_key_v2},
        {"sqlite3_prepare_v2", (void *)wx_fish_prepare_v2, (void **)&orig_sqlite3_prepare_v2},
        {"sqlite3_prepare_v3", (void *)wx_fish_prepare_v3, (void **)&orig_sqlite3_prepare_v3},
        {"sqlite3_prepare16_v2", (void *)wx_fish_prepare16_v2, (void **)&orig_sqlite3_prepare16_v2},
        {"sqlite3_prepare16_v3", (void *)wx_fish_prepare16_v3, (void **)&orig_sqlite3_prepare16_v3},
        {"sqlite3_exec", (void *)wx_fish_exec, (void **)&orig_sqlite3_exec},
    };
    int rc = wx_rebind_symbols(binds, sizeof binds / sizeof binds[0]);

    // An image that binds lazily may not have a resolved slot yet; keep a dlsym
    // fallback so forwarding works once we are actually called.
    if (!orig_sqlite3_key) orig_sqlite3_key = (wx_key_fn)dlsym(RTLD_DEFAULT, "sqlite3_key");
    if (!orig_sqlite3_key_v2) orig_sqlite3_key_v2 = (wx_key_v2_fn)dlsym(RTLD_DEFAULT, "sqlite3_key_v2");
    if (!orig_sqlite3_prepare_v2)
        orig_sqlite3_prepare_v2 = (wx_prepare_v2_fn)dlsym(RTLD_DEFAULT, "sqlite3_prepare_v2");
    if (!orig_sqlite3_prepare_v3)
        orig_sqlite3_prepare_v3 = (wx_prepare_v3_fn)dlsym(RTLD_DEFAULT, "sqlite3_prepare_v3");
    if (!orig_sqlite3_prepare16_v2)
        orig_sqlite3_prepare16_v2 = (wx_prepare16_v2_fn)dlsym(RTLD_DEFAULT, "sqlite3_prepare16_v2");
    if (!orig_sqlite3_prepare16_v3)
        orig_sqlite3_prepare16_v3 = (wx_prepare16_v3_fn)dlsym(RTLD_DEFAULT, "sqlite3_prepare16_v3");
    if (!orig_sqlite3_exec) orig_sqlite3_exec = (wx_exec_fn)dlsym(RTLD_DEFAULT, "sqlite3_exec");

    wlog("fishhook: rc=%d key=%p key_v2=%p prepare_v2=%p prepare_v3=%p prepare16_v2=%p "
         "prepare16_v3=%p exec=%p",
         rc, (void *)orig_sqlite3_key, (void *)orig_sqlite3_key_v2, (void *)orig_sqlite3_prepare_v2,
         (void *)orig_sqlite3_prepare_v3, (void *)orig_sqlite3_prepare16_v2,
         (void *)orig_sqlite3_prepare16_v3, (void *)orig_sqlite3_exec);
}

typedef struct {
    const void *replacement;
    const void *replacee;
} wx_interpose_t;

#define WX_INTERPOSE(name, repl, orig)                                             \
    __attribute__((used, section("__DATA,__interpose")))                           \
    static const wx_interpose_t name = {                                           \
        (const void *)(uintptr_t)&repl, (const void *)(uintptr_t)&orig              \
    }

WX_INTERPOSE(wx_interpose_cccrypt, wx_CCCrypt,         CCCrypt);
WX_INTERPOSE(wx_interpose_pbkdf2,  wx_pbkdf2,          CCKeyDerivationPBKDF);

static void dump_images(void) {
    uint32_t n = _dyld_image_count();
    wlog("images: %u", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        wlog("img[%u] %s", i, nm ? nm : "?");
    }
}

__attribute__((constructor))
static void wx_init(void) {
    init_paths();
    mkdir_p(g_dumpdir);
    dump_images();
    wlog("addr CCCrypt=%p pbkdf2=%p", (void *)CCCrypt, (void *)CCKeyDerivationPBKDF);
    char tmpdir[PATH_MAX];
    snprintf(tmpdir, sizeof tmpdir, "%s/tmp", g_home);
    mkdir(tmpdir, 0755);
    write_json();
    install_fishhook();
    wlog("loaded into pid=%d, home=%s, dumpdir=%s, interpose=CCCrypt+PBKDF2, "
         "fishhook=sqlite3_key/prepare/exec",
         (int)getpid(), g_home, g_dumpdir);
    pthread_t th;
    if (pthread_create(&th, NULL, scanner_main, NULL) == 0)
        pthread_detach(th);
    else
        wlog("error: scanner thread could not start");
}
