/*
 * A legacy C library linked into a Zig program, for the C shim tests
 * (src/sec/tests/cshim_test.zig). Each function has a buggy form (`fixed`
 * 0) that puts the caller's text into a sink, and a fixed form that passes
 * it as data.
 */
#include <string.h>
#include <sys/types.h>

/*
 * Stand-ins for <pthread.h> and <sqlite3.h>, so the test builds the same
 * on every target: the simulation runs one task at a time, so the test
 * needs the API, not the threads or the database.
 */
typedef struct { int held; } test_mutex;
#define pthread_mutex_t test_mutex
#define PTHREAD_MUTEX_INITIALIZER { 0 }
static int pthread_mutex_lock(pthread_mutex_t *m) { m->held = 1; return 0; }
static int pthread_mutex_unlock(pthread_mutex_t *m) { m->held = 0; return 0; }

#define SQLITE_VERSION "test"
typedef struct sqlite3 { int prepared; } sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
static int sqlite3_prepare_v2(sqlite3 *db, const char *sql, int n, sqlite3_stmt **stmt, const char **tail) {
    (void)sql; (void)n; (void)tail;
    db->prepared += 1;
    *stmt = 0;
    return 0;
}
static int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *arg, char **errmsg) {
    (void)sql; (void)callback; (void)arg; (void)errmsg;
    db->prepared += 1;
    return 0;
}

/* And for <spawn.h>, which MinGW does not have. */
#define POSIX_SPAWN_RESETIDS 1
typedef int posix_spawn_file_actions_t;
typedef int posix_spawnattr_t;

#include "tardis_sec.h"

static sqlite3 users_db;

/* Greets `name` into `out`. Bug: the greeting is built first and then used
 * as the format, so the name is part of it. */
int legacy_greet(char *out, size_t cap, const char *name, int fixed) {
    char format[96];
    if (fixed) return snprintf(out, cap, "hello %s", name);
    snprintf(format, sizeof format, "hello %s", name);
    return snprintf(out, cap, format);
}

/* Looks `name` up. Bug: the name is pasted into the SQL text; fixed, it is
 * a bound parameter. */
int legacy_lookup(const char *name, int fixed) {
    char sql[128];
    sqlite3_stmt *stmt;
    if (fixed) return sqlite3_prepare_v2(&users_db, "SELECT id FROM users WHERE name = ?1", -1, &stmt, 0);
    snprintf(sql, sizeof sql, "SELECT id FROM users WHERE name = '%s'", name);
    return sqlite3_prepare_v2(&users_db, sql, -1, &stmt, 0);
}

/* Tells the administrator about `name`. Bug: the name goes on the shell
 * command line; fixed, the command is constant (the name would go through a
 * file or a pipe). */
int legacy_notify(const char *name, int fixed) {
    char command[128];
    if (fixed) return system("notify-admin --from-queue");
    snprintf(command, sizeof command, "notify-admin %s", name);
    return system(command);
}

/* Converts the upload `name`. Bug: the name is an argument of the
 * converter; fixed, the converter reads its job from the queue. */
int legacy_convert(const char *name, int fixed) {
    char *const queued[] = { "convert", "--from-queue", 0 };
    char *const direct[] = { "convert", (char *)name, 0 };
    return execvp("convert", fixed ? queued : direct);
}

/* Archives the upload `name`, with `execl` or (`spawn` nonzero)
 * `posix_spawnp`. Bug: the name is an argument; fixed, the archiver reads
 * its job from the queue. Returns whether the call failed as it must. */
int legacy_archive(const char *name, int fixed, int spawn) {
    char *const direct[] = { "archive", (char *)name, 0 };
    char *const queued[] = { "archive", "--from-queue", 0 };
    pid_t pid;
    if (spawn) return posix_spawnp(&pid, "archive", 0, 0, fixed ? queued : direct, 0) == ENOSYS;
    if (fixed) return execl("/usr/bin/archive", "archive", "--from-queue", (char *)0) == -1;
    return execlp("archive", "archive", name, (char *)0) == -1;
}

/* Reports on `name` through a pipe. Bug: the name is on the command line;
 * fixed, the command is constant. Returns whether a pipe was opened. */
int legacy_report(const char *name, int fixed) {
    char command[128];
    FILE *f;
    if (fixed) f = popen("report --stdin", "w");
    else {
        snprintf(command, sizeof command, "report %s", name);
        f = popen(command, "r");
    }
    return f != NULL;
}

/* Accepts `tag` when it equals `expected` (n bytes), in constant time.
 * `doubled` 0: one check, which one skipped compare turns into an accept.
 * Nonzero: the check is made twice, so one glitch still rejects. */
int legacy_verify(const unsigned char *tag, const unsigned char *expected, size_t n, int doubled) {
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < n; i++) diff |= (unsigned char)(tag[i] ^ expected[i]);
    if (!TARDIS_SEC_CRITICAL(diff == 0)) return 0;
    if (doubled && !TARDIS_SEC_CRITICAL(diff == 0)) return 0;
    return 1;
}

/* Unlocks when armed and the signature is good or an override is set:
 * decision 11, recorded for MC/DC. */
int legacy_unlock(int armed, int sig_ok, int override) {
    return tardis_sec_mcdc(11, 3, TARDIS_SEC_VECTOR3(armed, sig_ok, override), armed && (sig_ok || override));
}

static pthread_mutex_t accounts = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t audit_log = PTHREAD_MUTEX_INITIALIZER;

void legacy_transfer(void) {
    pthread_mutex_lock(&accounts);
    pthread_mutex_lock(&audit_log);
    pthread_mutex_unlock(&audit_log);
    pthread_mutex_unlock(&accounts);
}

/* Bug: the audit job takes the two locks in the other order. */
void legacy_audit(int fixed) {
    if (fixed) {
        pthread_mutex_lock(&accounts);
        pthread_mutex_lock(&audit_log);
        pthread_mutex_unlock(&audit_log);
        pthread_mutex_unlock(&accounts);
        return;
    }
    pthread_mutex_lock(&audit_log);
    pthread_mutex_lock(&accounts);
    pthread_mutex_unlock(&accounts);
    pthread_mutex_unlock(&audit_log);
}
