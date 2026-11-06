// test-sqlite.c - fake SQLite entry points for the fishhook harness.
//
// Built as build/libtest-sqlite.dylib so test-host.c imports (instead of
// defines) sqlite3_key and friends.  Imports are what fishhook rewrites; a
// definition inside the main executable would be called directly and never
// pass through a symbol slot.

#include <stdio.h>

typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;

#define SQLITE_OK 0

int sqlite3_key(sqlite3 *db, const void *pKey, int nKey) {
    (void)db;
    (void)pKey;
    fprintf(stderr, "[test-sqlite] real sqlite3_key reached, nKey=%d\n", nKey);
    return SQLITE_OK;
}

int sqlite3_key_v2(sqlite3 *db, const char *zDb, const void *pKey, int nKey) {
    (void)db;
    (void)pKey;
    fprintf(stderr, "[test-sqlite] real sqlite3_key_v2 reached, zDb=%s nKey=%d\n",
            zDb ? zDb : "(null)", nKey);
    return SQLITE_OK;
}

int sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt,
                       const char **pzTail) {
    (void)db;
    (void)zSql;
    (void)nByte;
    if (ppStmt) *ppStmt = 0;
    if (pzTail) *pzTail = 0;
    fprintf(stderr, "[test-sqlite] real sqlite3_prepare_v2 reached\n");
    return SQLITE_OK;
}

int sqlite3_prepare_v3(sqlite3 *db, const char *zSql, int nByte, unsigned int prepFlags,
                       sqlite3_stmt **ppStmt, const char **pzTail) {
    (void)db;
    (void)zSql;
    (void)nByte;
    (void)prepFlags;
    if (ppStmt) *ppStmt = 0;
    if (pzTail) *pzTail = 0;
    fprintf(stderr, "[test-sqlite] real sqlite3_prepare_v3 reached\n");
    return SQLITE_OK;
}

int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **),
                 void *arg, char **errmsg) {
    (void)db;
    (void)sql;
    (void)callback;
    (void)arg;
    if (errmsg) *errmsg = 0;
    fprintf(stderr, "[test-sqlite] real sqlite3_exec reached\n");
    return SQLITE_OK;
}
