/*
 * SPDX-FileCopyrightText: Gianluca
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * qute_browser_spoof.c — LD_PRELOAD shim for 1Password BrowserSupport.
 *
 * Problem: 1Password-BrowserSupport verifies the calling process by walking
 * the /proc ancestry chain and reading /proc/<pid>/exe for each ancestor,
 * comparing the result against a whitelist of trusted browser binaries.
 *
 * Solution: intercept readlink(2), readlinkat(2) and openat(2) so that any
 * /proc/<ancestor>/exe query returns "/usr/bin/firefox" instead of the real
 * sidecar executable.
 *
 * BrowserSupport uses two forms:
 *   1. readlink("/proc/<ppid>/exe", buf, size)           — direct form
 *   2. openat(AT_FDCWD, "/proc/<ppid>", O_PATH|O_DIR)   — gets an fd, then:
 *      readlinkat(fd, "exe", buf, size)                  — relative form
 * Both forms are intercepted here.
 *
 * The binary is setgid (group "onepassword") in the system installation so
 * LD_PRELOAD is ignored for it.  NativeProtocolBackend creates a non-setgid
 * shadow copy in ~/.local/share/qute-1pass/ and loads this shim into that copy.
 * The shadow copy can still connect to /run/user/<uid>/1Password-BrowserSupport.sock
 * because that socket is owned 0600 by the user and does not require the group.
 *
 * Build:
 *   gcc -O2 -shared -fPIC -o qute_browser_spoof.so qute_browser_spoof.c -ldl -lpthread
 *
 * DISCLAIMER: use likely violates 1Password ToS.  Gated behind
 * onepassword.experimental_bridge=true (default: false).
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* Trusted browser binary to impersonate.  Must exist on the filesystem so that
 * any subsequent stat() on the returned path succeeds. */
#define SPOOF_EXE "/usr/bin/firefox"

/* How many ancestor levels we walk when checking ancestry. */
#define MAX_ANCESTORS 4

/* ---------------------------------------------------------------------------
 * fd → pid mapping (tracks openat("/proc/<pid>", O_PATH|O_DIRECTORY) calls)
 * ---------------------------------------------------------------------------*/

#define FD_TABLE_SIZE 64

typedef struct {
    int  fd;
    int  pid; /* 0 = free slot */
} FdEntry;

static FdEntry  fd_table[FD_TABLE_SIZE];
static pthread_mutex_t fd_table_lock = PTHREAD_MUTEX_INITIALIZER;

static void fd_table_set(int fd, int pid)
{
    pthread_mutex_lock(&fd_table_lock);
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fd_table[i].pid == 0 || fd_table[i].fd == fd) {
            fd_table[i].fd  = fd;
            fd_table[i].pid = pid;
            break;
        }
    }
    pthread_mutex_unlock(&fd_table_lock);
}

static int fd_table_get(int fd)
{
    pthread_mutex_lock(&fd_table_lock);
    int pid = 0;
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fd_table[i].fd == fd && fd_table[i].pid != 0) {
            pid = fd_table[i].pid;
            break;
        }
    }
    pthread_mutex_unlock(&fd_table_lock);
    return pid;
}

static void fd_table_clear(int fd)
{
    pthread_mutex_lock(&fd_table_lock);
    for (int i = 0; i < FD_TABLE_SIZE; i++) {
        if (fd_table[i].fd == fd) {
            fd_table[i].pid = 0;
            break;
        }
    }
    pthread_mutex_unlock(&fd_table_lock);
}

/* ---------------------------------------------------------------------------
 * Ancestor check
 * ---------------------------------------------------------------------------*/

static int is_ancestor(pid_t pid)
{
    pid_t cur = getppid();
    for (int i = 0; i < MAX_ANCESTORS; i++) {
        if (cur == pid)
            return 1;
        if (cur <= 1)
            break;
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", (int)cur);
        FILE *f = fopen(status_path, "r");
        if (!f)
            break;
        pid_t next = -1;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "PPid:\t%d", &next) == 1)
                break;
        }
        fclose(f);
        if (next <= 1)
            break;
        cur = next;
    }
    return 0;
}

/* Parse /proc/<pid>/exe → return pid (0 on failure). */
static pid_t pid_from_proc_exe(const char *path)
{
    if (!path || strncmp(path, "/proc/", 6) != 0)
        return 0;
    const char *p = path + 6;
    pid_t pid = 0;
    while (*p >= '0' && *p <= '9')
        pid = pid * 10 + (*p++ - '0');
    return (strcmp(p, "/exe") == 0 && pid > 0) ? pid : 0;
}

/* Parse /proc/<pid> → return pid (0 on failure). */
static pid_t pid_from_proc_dir(const char *path)
{
    if (!path || strncmp(path, "/proc/", 6) != 0)
        return 0;
    const char *p = path + 6;
    pid_t pid = 0;
    while (*p >= '0' && *p <= '9')
        pid = pid * 10 + (*p++ - '0');
    return ((*p == '\0' || *p == '/') && pid > 0) ? pid : 0;
}

static ssize_t spoof_buf(char *buf, size_t bufsiz)
{
    size_t len = strlen(SPOOF_EXE);
    if (bufsiz == 0) { errno = EINVAL; return -1; }
    size_t copy = len < bufsiz ? len : bufsiz;
    memcpy(buf, SPOOF_EXE, copy);
    return (ssize_t)copy;
}

/* ---------------------------------------------------------------------------
 * openat override — track /proc/<pid> directory opens
 * ---------------------------------------------------------------------------*/

typedef int (*openat_fn)(int, const char *, int, ...);

int openat(int dirfd, const char *pathname, int flags, ...)
{
    static openat_fn real_openat = NULL;
    if (!real_openat)
        real_openat = (openat_fn)dlsym(RTLD_NEXT, "openat");

    /* Forward the call first to get the real fd. */
    int fd;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        fd = real_openat(dirfd, pathname, flags, mode);
    } else {
        fd = real_openat(dirfd, pathname, flags);
    }

    if (fd >= 0 && dirfd == AT_FDCWD && (flags & O_DIRECTORY)) {
        pid_t pid = pid_from_proc_dir(pathname);
        if (pid > 0 && is_ancestor(pid))
            fd_table_set(fd, (int)pid);
    }

    return fd;
}

/* ---------------------------------------------------------------------------
 * close override — clean up fd tracking
 * ---------------------------------------------------------------------------*/

typedef int (*close_fn)(int);

int close(int fd)
{
    static close_fn real_close = NULL;
    if (!real_close)
        real_close = (close_fn)dlsym(RTLD_NEXT, "close");
    fd_table_clear(fd);
    return real_close(fd);
}

/* ---------------------------------------------------------------------------
 * readlink override
 * ---------------------------------------------------------------------------*/

typedef ssize_t (*readlink_fn)(const char *, char *, size_t);

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
    static readlink_fn real_readlink = NULL;
    if (!real_readlink)
        real_readlink = (readlink_fn)dlsym(RTLD_NEXT, "readlink");

    pid_t pid = pid_from_proc_exe(pathname);
    if (pid > 0 && is_ancestor(pid))
        return spoof_buf(buf, bufsiz);

    return real_readlink(pathname, buf, bufsiz);
}

/* ---------------------------------------------------------------------------
 * readlinkat override
 * ---------------------------------------------------------------------------*/

typedef ssize_t (*readlinkat_fn)(int, const char *, char *, size_t);

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{
    static readlinkat_fn real_readlinkat = NULL;
    if (!real_readlinkat)
        real_readlinkat = (readlinkat_fn)dlsym(RTLD_NEXT, "readlinkat");

    /* Absolute path form: readlinkat(AT_FDCWD, "/proc/<pid>/exe", ...) */
    if (dirfd == AT_FDCWD) {
        pid_t pid = pid_from_proc_exe(pathname);
        if (pid > 0 && is_ancestor(pid))
            return spoof_buf(buf, bufsiz);
    }

    /* Relative form: readlinkat(fd_on_proc_pid_dir, "exe", ...) */
    if (strcmp(pathname, "exe") == 0 && dirfd != AT_FDCWD) {
        int pid = fd_table_get(dirfd);
        if (pid > 0)
            return spoof_buf(buf, bufsiz);
    }

    return real_readlinkat(dirfd, pathname, buf, bufsiz);
}
