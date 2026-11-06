// test-host.c - end-to-end validation harness for the fishhook layer.
//
// Imports sqlite3_key / _v2 / prepare* / exec from build/libtest-sqlite.dylib
// (test-sqlite.c), so calls go through symbol slots that fishhook rewrites.
// It also plants a WCDB-shaped 99-byte key string on the heap so the memory
// scanner has something to find, and expects HOME to hold
// Documents/xwechat_files/*/db_storage/*.db whose first 16 bytes match
// PLANTED_SALT, because collect_db_salts runs in the constructor.
//
// Run from WeChatSqlcipherKeyDumper/:
//   src/weixin-key-dumper/test-dylib.sh

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

extern int sqlite3_key(sqlite3 *, const void *, int);
extern int sqlite3_key_v2(sqlite3 *, const char *, const void *, int);
extern int sqlite3_prepare_v2(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
extern int sqlite3_prepare_v3(sqlite3 *, const char *, int, unsigned int, sqlite3_stmt **,
                              const char **);
extern int sqlite3_exec(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *,
                        char **);

#define PLANTED_KEY  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define PLANTED_SALT "00112233445566778899aabbccddeeff"

int main(void) {
    char planted[128];
    snprintf(planted, sizeof(planted), "x'%s%s'", PLANTED_KEY, PLANTED_SALT);
    fprintf(stderr, "[test-host] planted %zu bytes: %s\n", strlen(planted), planted);

    char *heap = strdup(planted);

    unsigned char rawkey[32];
    for (int i = 0; i < 32; i++) {
        unsigned int v = 0;
        sscanf(&PLANTED_KEY[i * 2], "%2x", &v);
        rawkey[i] = (unsigned char)v;
    }

    sqlite3_key(NULL, rawkey, 32);
    sqlite3_key_v2(NULL, "main", heap, 99);

    char sql[256];
    snprintf(sql, sizeof(sql), "PRAGMA key = \"x'%s%s'\";", PLANTED_KEY, PLANTED_SALT);
    sqlite3_stmt *stmt = NULL;
    const char *tail = NULL;
    sqlite3_prepare_v2(NULL, sql, -1, &stmt, &tail);
    sqlite3_prepare_v3(NULL, sql, -1, 0, &stmt, &tail);
    sqlite3_exec(NULL, sql, NULL, NULL, NULL);

    fprintf(stderr, "[test-host] sleeping so the scanner thread can run\n");
    for (int i = 0; i < 8; i++) {
        sleep(1);
    }
    fprintf(stderr, "[test-host] done, heap=%p\n", (void *)heap);
    return 0;
}
