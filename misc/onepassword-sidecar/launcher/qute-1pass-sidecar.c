/*
 * SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * qute-1pass-sidecar.c — Bridge launcher for 1Password BrowserSupport.
 *
 * Design
 * ------
 * 1Password-BrowserSupport verifies the calling process by reading
 * /proc/<ppid>/exe and checking the basename against a whitelist that
 * includes /etc/1password/custom_allowed_browsers (root-owned).
 *
 * This binary must be the DIRECT PARENT of BrowserSupport so that its
 * basename ("qute-1pass-sidecar") is what 1Password sees.  It therefore
 * forks BrowserSupport as a child and stays alive as a bidirectional
 * stdin/stdout proxy, bridging the Python sidecar (its own parent) with
 * BrowserSupport (its child).
 *
 *   Python sidecar ──stdin/stdout──▶ [qute-1pass-sidecar] ──stdin/stdout──▶ BrowserSupport
 *                                      (this binary, stays alive as ppid)
 *
 * Setup (one-time, requires root):
 *   make install
 *   echo "qute-1pass-sidecar" | sudo tee -a /etc/1password/custom_allowed_browsers
 *
 * Usage: the NativeProtocolBackend invokes this binary; it reads
 *   QUTE_1PASS_BS_PATH   — path to 1Password-BrowserSupport (default: /opt/1Password/…)
 *   QUTE_1PASS_MANIFEST  — path to the NM manifest JSON
 *   QUTE_1PASS_EXT_ID    — extension ID string
 *
 * DISCLAIMER: use likely violates 1Password ToS.
 * Gate: onepassword.experimental_bridge=true (default: false).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define BS_PATH_DEFAULT "/opt/1Password/1Password-BrowserSupport"
#define BUF_SIZE 65536

static volatile pid_t g_child_pid = 0;

static void on_sigchld(int sig)
{
    (void)sig;
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (pid == g_child_pid) {
            g_child_pid = 0;
        }
    }
}

int main(void)
{
    const char *bs_path  = getenv("QUTE_1PASS_BS_PATH");
    const char *manifest = getenv("QUTE_1PASS_MANIFEST");
    const char *ext_id   = getenv("QUTE_1PASS_EXT_ID");

    if (!bs_path  || bs_path[0]  == '\0') bs_path  = BS_PATH_DEFAULT;
    if (!manifest || manifest[0] == '\0') {
        fputs("qute-1pass-sidecar: QUTE_1PASS_MANIFEST not set\n", stderr);
        return 1;
    }
    if (!ext_id   || ext_id[0]   == '\0') {
        fputs("qute-1pass-sidecar: QUTE_1PASS_EXT_ID not set\n", stderr);
        return 1;
    }

    /* Pipes: parent_to_child (our stdin → child stdin),
     *        child_to_parent (child stdout → our stdout) */
    int p2c[2], c2p[2];
    if (pipe(p2c) < 0 || pipe(c2p) < 0) { perror("pipe"); return 1; }

    signal(SIGCHLD, on_sigchld);

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }

    if (child == 0) {
        /* ---- child: exec BrowserSupport ---- */
        dup2(p2c[0], STDIN_FILENO);
        dup2(c2p[1], STDOUT_FILENO);
        close(p2c[0]); close(p2c[1]);
        close(c2p[0]); close(c2p[1]);
        /* Unset LD_PRELOAD so the setgid binary's loader ignores it. */
        unsetenv("LD_PRELOAD");
        char *argv[] = { (char *)bs_path, (char *)manifest, (char *)ext_id, NULL };
        execv(bs_path, argv);
        perror("execv");
        _exit(1);
    }

    /* ---- parent: bidirectional bridge ---- */
    g_child_pid = child;
    close(p2c[0]);  /* child end */
    close(c2p[1]);  /* child end */

    int our_stdin  = STDIN_FILENO;
    int our_stdout = STDOUT_FILENO;
    int to_child   = p2c[1];
    int from_child = c2p[0];

    /* Make our stdin non-blocking for poll. */
    fcntl(our_stdin,   F_SETFL, O_NONBLOCK);
    fcntl(from_child,  F_SETFL, O_NONBLOCK);

    char buf[BUF_SIZE];
    struct pollfd fds[2];

    while (g_child_pid != 0) {
        fds[0].fd      = our_stdin;
        fds[0].events  = POLLIN;
        fds[1].fd      = from_child;
        fds[1].events  = POLLIN;

        int n = poll(fds, 2, 1000);
        if (n < 0 && errno != EINTR) break;

        /* our stdin → child stdin */
        if (fds[0].revents & POLLIN) {
            ssize_t r = read(our_stdin, buf, sizeof(buf));
            if (r <= 0) break;  /* parent closed — signal child */
            const char *p = buf;
            while (r > 0) {
                ssize_t w = write(to_child, p, (size_t)r);
                if (w <= 0) goto done;
                p += w; r -= w;
            }
        }
        if (fds[0].revents & (POLLHUP | POLLERR)) break;

        /* child stdout → our stdout */
        if (fds[1].revents & POLLIN) {
            ssize_t r = read(from_child, buf, sizeof(buf));
            if (r <= 0) break;
            const char *p = buf;
            while (r > 0) {
                ssize_t w = write(our_stdout, p, (size_t)r);
                if (w <= 0) goto done;
                p += w; r -= w;
            }
        }
        if (fds[1].revents & (POLLHUP | POLLERR)) break;
    }

done:
    if (g_child_pid != 0) {
        kill(g_child_pid, SIGTERM);
        waitpid(g_child_pid, NULL, 0);
    }
    close(to_child);
    close(from_child);
    return 0;
}
