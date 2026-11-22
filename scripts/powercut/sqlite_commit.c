/* The program of test/sqlite.zig, against the real kernel (docs/power-cut.md).
 *
 *   sqlite_commit write OFF|FULL|EXTRA <database>
 *       creates a table and a first row, then commits a second row, and
 *       prints "acknowledged" when that commit has returned.
 *   sqlite_commit check <database>
 *       prints one of: cannot_open, cannot_read, integrity, row_lost, kept.
 *
 * Built with SQLite's amalgamation and its own Unix VFS (ext4.sh says how).
 */
#include <stdio.h>
#include <string.h>
#include "sqlite3.h"

static char first[64];
static int rows;

static int row(void *ctx, int columns, char **values, char **names) {
    (void)ctx;
    (void)names;
    if (rows == 0 && columns > 0 && values[0]) {
        strncpy(first, values[0], sizeof first - 1);
        first[sizeof first - 1] = 0;
    }
    rows += 1;
    return 0;
}

static int query(sqlite3 *db, const char *sql) {
    first[0] = 0;
    rows = 0;
    return sqlite3_exec(db, sql, row, 0, 0);
}

static int say(const char *what, int rc) {
    puts(what);
    return rc;
}

int main(int argc, char **argv) {
    sqlite3 *db = 0;
    if (argc == 4 && strcmp(argv[1], "write") == 0) {
        char pragma[64];
        snprintf(pragma, sizeof pragma, "PRAGMA synchronous=%s", argv[2]);
        if (sqlite3_open(argv[3], &db) != 0) return say("open failed", 2);
        if (sqlite3_exec(db, pragma, 0, 0, 0) != 0) return say("pragma failed", 2);
        if (sqlite3_exec(db, "CREATE TABLE kv(k INTEGER PRIMARY KEY, v TEXT)", 0, 0, 0) != 0) return say("create failed", 2);
        if (sqlite3_exec(db, "INSERT INTO kv VALUES(1, 'one')", 0, 0, 0) != 0) return say("insert failed", 2);
        if (sqlite3_exec(db, "INSERT INTO kv VALUES(2, 'two')", 0, 0, 0) != 0) return say("insert failed", 2);
        puts("acknowledged");
        fflush(stdout);
        sqlite3_close(db);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "check") == 0) {
        if (sqlite3_open(argv[2], &db) != 0) return say("cannot_open", 0);
        if (query(db, "PRAGMA integrity_check") != 0) return say("cannot_read", 0);
        if (strcmp(first, "ok") != 0) return say("integrity", 0);
        if (query(db, "SELECT v FROM kv WHERE k = 2") != 0) return say("cannot_read", 0);
        if (!(rows == 1 && strcmp(first, "two") == 0)) return say("row_lost", 0);
        return say("kept", 0);
    }
    fprintf(stderr, "usage: sqlite_commit write OFF|FULL|EXTRA <database> | check <database>\n");
    return 2;
}
