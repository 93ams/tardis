/*
 * tardis_sec C shims (plan2.md §5.2).
 *
 * Include this header after the system headers in C code that runs under a
 * TARDIS simulation with the security layer (and export its functions from
 * the Zig test with `comptime { tardis_sec.exportC(); }`). It wraps:
 *
 *   printf, fprintf, sprintf, snprintf  the format string is a sink (CWE-134)
 *   system, popen                       the command is a sink (CWE-78);
 *                                       the simulation runs no processes, so
 *                                       they fail (-1, NULL) as without a shell
 *   execv, execvp, execve,              the path and each argument are sinks
 *   execl, execlp, execle               (CWE-78); they fail with -1
 *   posix_spawn, posix_spawnp           the same, when <spawn.h> came first;
 *                                       they fail with ENOSYS
 *
 * Each of these starts a process, which a sandbox without
 * `allow_process_spawn` forbids (CWE-272).
 *   sqlite3_prepare_v2, sqlite3_exec    the SQL text is a sink (CWE-89),
 *                                       when <sqlite3.h> came first
 *   pthread_mutex_lock, _unlock         lock order by mutex (CWE-833), when
 *                                       <pthread.h> came first
 *
 * TARDIS_SEC_CRITICAL(cond) marks a security-critical condition (a MAC or
 * signature check): under `instruction_skip_glitch_ppm` the simulation may
 * invert it, as a fault attack that skips one compare does. Code that must
 * fail closed checks twice.
 *
 * tardis_sec_mcdc(id, n, vector, outcome) records one evaluation of a
 * decision for MC/DC, in the same table as Zig's `mcdc.decision`; the
 * TARDIS_SEC_VECTOR macros build the vector from the conditions:
 *
 *     int armed = ..., sig = ..., ovr = ...;
 *     if (tardis_sec_mcdc(7, 3, TARDIS_SEC_VECTOR3(armed, sig, ovr),
 *                         armed && (sig || ovr))) { ... }
 *
 * TARDIS_SEC_BOUNDS(index, len) is `index < len` for an index the
 * attacker chooses. In C built with -fsanitize-coverage=trace-pc,trace-loads
 * the loads after it are watched: one whose address follows the value an
 * earlier one returned is the Spectre-v1 shape (CWE-1037). An index
 * hardened with tardis_sec_index_nospec() is not watched.
 *
 * A sink holding 8 or more bytes in a row that the program received from the
 * network, and did not pass to `markSanitized`, is a finding and fails the
 * run. The wrapped call then goes on as it would have. Without an active
 * simulation every check does nothing.
 *
 * Define TARDIS_SEC_NO_SHIMS to get the functions without the renaming.
 */
#ifndef TARDIS_SEC_H
#define TARDIS_SEC_H

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Each returns the CWE of a finding, or 0. */
int tardis_sec_check_format(const char *format);
int tardis_sec_check_command(const char *command);
/* The path, then argv up to its NULL (32 entries in all are checked). */
int tardis_sec_check_exec(const char *path, char *const argv[]);
/* len < 0: up to the NUL. */
int tardis_sec_check_sql(const char *sql, int len);
/* `cond` as 0 or 1, possibly inverted by an injected glitch. */
int tardis_sec_critical_check(int cond);
#define TARDIS_SEC_CRITICAL(cond) tardis_sec_critical_check((cond) != 0)
/* Records the vector (condition i is bit i) of decision `id` (0..255)
 * with its outcome, and returns the outcome. */
int tardis_sec_mcdc(unsigned id, unsigned conditions, unsigned vector, int outcome);
#define TARDIS_SEC_VECTOR2(a, b) (((a) ? 1u : 0u) | ((b) ? 2u : 0u))
#define TARDIS_SEC_VECTOR3(a, b, c) (TARDIS_SEC_VECTOR2(a, b) | ((c) ? 4u : 0u))
#define TARDIS_SEC_VECTOR4(a, b, c, d) (TARDIS_SEC_VECTOR3(a, b, c) | ((d) ? 8u : 0u))
/* `index < len` as 0 or 1; when 1, the following loads are watched. */
int tardis_sec_bounds_check(size_t index, size_t len);
#define TARDIS_SEC_BOUNDS(index, len) tardis_sec_bounds_check((size_t)(index), (size_t)(len))
/* `index` when it is below `len`, else 0, computed with a mask and no
 * branch on the comparison (as Linux's array_index_nospec; check the code
 * your compiler generates for it). */
static inline size_t tardis_sec_index_nospec(size_t index, size_t len) {
    size_t mask = (size_t)0 - (size_t)(index < len);
    return index & mask;
}
/* Before a mutex is taken (it may wait), and after it is released. */
void tardis_sec_mutex_acquire(const void *mutex);
void tardis_sec_mutex_release(const void *mutex);

static inline int tardis_sec_vsnprintf(char *buf, size_t n, const char *format, va_list ap) {
    tardis_sec_check_format(format);
    return vsnprintf(buf, n, format, ap);
}

static inline int tardis_sec_snprintf(char *buf, size_t n, const char *format, ...) {
    va_list ap;
    int r;
    tardis_sec_check_format(format);
    va_start(ap, format);
    r = vsnprintf(buf, n, format, ap);
    va_end(ap);
    return r;
}

static inline int tardis_sec_sprintf(char *buf, const char *format, ...) {
    va_list ap;
    int r;
    tardis_sec_check_format(format);
    va_start(ap, format);
    r = vsprintf(buf, format, ap);
    va_end(ap);
    return r;
}

static inline int tardis_sec_fprintf(FILE *f, const char *format, ...) {
    va_list ap;
    int r;
    tardis_sec_check_format(format);
    va_start(ap, format);
    r = vfprintf(f, format, ap);
    va_end(ap);
    return r;
}

static inline int tardis_sec_printf(const char *format, ...) {
    va_list ap;
    int r;
    tardis_sec_check_format(format);
    va_start(ap, format);
    r = vprintf(format, ap);
    va_end(ap);
    return r;
}

static inline int tardis_sec_system(const char *command) {
    tardis_sec_check_command(command);
    return -1;
}

static inline FILE *tardis_sec_popen(const char *command, const char *mode) {
    (void)mode;
    tardis_sec_check_command(command);
    return NULL;
}

static inline int tardis_sec_execv(const char *path, char *const argv[]) {
    tardis_sec_check_exec(path, argv);
    return -1;
}

static inline int tardis_sec_execvp(const char *file, char *const argv[]) {
    tardis_sec_check_exec(file, argv);
    return -1;
}

static inline int tardis_sec_execve(const char *path, char *const argv[], char *const envp[]) {
    (void)envp;
    tardis_sec_check_exec(path, argv);
    return -1;
}

/* execl, execlp, execle: the arguments up to the NULL (an `execle`
 * environment after it is not read). */
static inline int tardis_sec_execl(const char *path, const char *arg, ...) {
    char *argv[32];
    size_t n = 0;
    va_list ap;
    va_start(ap, arg);
    while (arg != NULL && n < 31) {
        argv[n++] = (char *)arg;
        arg = va_arg(ap, const char *);
    }
    va_end(ap);
    argv[n] = NULL;
    tardis_sec_check_exec(path, argv);
    return -1;
}

#ifdef POSIX_SPAWN_RESETIDS
static inline int tardis_sec_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions, const posix_spawnattr_t *attr, char *const argv[], char *const envp[]) {
    (void)pid; (void)actions; (void)attr; (void)envp;
    tardis_sec_check_exec(path, argv);
    return ENOSYS;
}
#endif

#ifdef SQLITE_VERSION
static inline int tardis_sec_sqlite3_prepare_v2(sqlite3 *db, const char *sql, int n, sqlite3_stmt **stmt, const char **tail) {
    tardis_sec_check_sql(sql, n);
    return sqlite3_prepare_v2(db, sql, n, stmt, tail);
}

static inline int tardis_sec_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *arg, char **errmsg) {
    tardis_sec_check_sql(sql, -1);
    return sqlite3_exec(db, sql, callback, arg, errmsg);
}
#endif

#ifdef PTHREAD_MUTEX_INITIALIZER
static inline int tardis_sec_pthread_mutex_lock(pthread_mutex_t *m) {
    int r;
    tardis_sec_mutex_acquire(m);
    r = pthread_mutex_lock(m);
    if (r != 0) tardis_sec_mutex_release(m);
    return r;
}

static inline int tardis_sec_pthread_mutex_unlock(pthread_mutex_t *m) {
    int r = pthread_mutex_unlock(m);
    if (r == 0) tardis_sec_mutex_release(m);
    return r;
}
#endif

#ifndef TARDIS_SEC_NO_SHIMS
#undef printf
#undef fprintf
#undef sprintf
#undef snprintf
#undef vsnprintf
#undef system
#undef popen
#undef execv
#undef execvp
#undef execve
#undef execl
#undef execlp
#undef execle
#define printf tardis_sec_printf
#define fprintf tardis_sec_fprintf
#define sprintf tardis_sec_sprintf
#define snprintf tardis_sec_snprintf
#define vsnprintf tardis_sec_vsnprintf
#define system tardis_sec_system
#define popen tardis_sec_popen
#define execv tardis_sec_execv
#define execvp tardis_sec_execvp
#define execve tardis_sec_execve
#define execl tardis_sec_execl
#define execlp tardis_sec_execl
#define execle tardis_sec_execl
#ifdef POSIX_SPAWN_RESETIDS
#undef posix_spawn
#undef posix_spawnp
#define posix_spawn tardis_sec_posix_spawn
#define posix_spawnp tardis_sec_posix_spawn
#endif
#ifdef SQLITE_VERSION
#undef sqlite3_prepare_v2
#undef sqlite3_exec
#define sqlite3_prepare_v2 tardis_sec_sqlite3_prepare_v2
#define sqlite3_exec tardis_sec_sqlite3_exec
#endif
#ifdef PTHREAD_MUTEX_INITIALIZER
#undef pthread_mutex_lock
#undef pthread_mutex_unlock
#define pthread_mutex_lock tardis_sec_pthread_mutex_lock
#define pthread_mutex_unlock tardis_sec_pthread_mutex_unlock
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif
