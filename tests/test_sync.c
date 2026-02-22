/*
 * test_sync.c — tests for the local peer-sync layer (sync.c)
 *
 * sync_pull uses fork() so that two independent processes can each have their
 * own CWD (and therefore their own messages.db) and their own server state.
 */

#include "test_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#  include <unistd.h>
#  include <sys/wait.h>
#endif
#include <sys/stat.h>

#include "sync.h"
#include "proto.h"

/* ---- minimal test framework ---- */

static int  g_pass = 0, g_fail = 0, g_cur_failed = 0;
static char g_orig_cwd[512];

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "    FAIL  %s:%d  (%s)\n", __FILE__, __LINE__, #expr); \
        g_cur_failed = 1; \
    } \
} while (0)

static void run_test(const char *name, void (*fn)(void))
{
    g_cur_failed = 0;
    fn();
    if (g_cur_failed) { fprintf(stderr, "FAIL  %s\n", name); g_fail++; }
    else              { printf("pass  %s\n",  name); g_pass++; }
}

/* ---- helpers ---- */

/* Return 1 if ./registry.db in the current directory contains an entry
   for the given port (any host). sync.c writes "host:port" lines. */
static int registry_has_entry(int port)
{
    FILE *f = fopen("registry.db", "r");
    if (!f) return 0;
    char line[128];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char h[64]; int p;
        if (sscanf(line, "%63[^:]:%d", h, &p) == 2 && p == port) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int count_db_lines(void)
{
    FILE *f = fopen("messages.db", "r");
    if (!f) return 0;
    int n = 0;
    char buf[8192];
    while (fgets(buf, sizeof(buf), f)) n++;
    fclose(f);
    return n;
}

/* ---- tests ---- */

/* sync_start_server must bind to a valid loopback port. */
static void test_server_starts(void)
{
    char tmpdir[] = "/tmp/dcomms_stest_XXXXXX";
    if (!mkdtemp(tmpdir)) { CHECK(0); return; }
    chdir(tmpdir);

    int port = sync_start_server();
    CHECK(port > 0 && port <= 65535);

    sync_unregister();
    chdir(g_orig_cwd);
    rmdir(tmpdir);
}

/* sync_register must add the current pid:port to the registry file, and
   sync_unregister must remove it. */
static void test_register_and_unregister(void)
{
    char tmpdir[] = "/tmp/dcomms_stest_XXXXXX";
    if (!mkdtemp(tmpdir)) { CHECK(0); return; }
    chdir(tmpdir);

    int port = sync_start_server();
    CHECK(port > 0);

    sync_register(port);
    CHECK(registry_has_entry(port));

    sync_unregister();
    CHECK(!registry_has_entry(port));

    unlink("registry.db");
    chdir(g_orig_cwd);
    rmdir(tmpdir);
}

#ifndef _WIN32
/*
 * Fork-based pull test:
 *
 *   Parent  — writes messages.db in tmpdir_a, starts TCP server, registers.
 *   Child   — starts in empty tmpdir_b, calls sync_with_peers(), verifies that
 *              it received the parent's DB lines.
 *
 * A pipe is used so the child waits until the parent's server is ready.
 */
static void test_sync_pull(void)
{
    char tmpdir_a[] = "/tmp/dcomms_sa_XXXXXX";
    char tmpdir_b[] = "/tmp/dcomms_sb_XXXXXX";
    if (!mkdtemp(tmpdir_a) || !mkdtemp(tmpdir_b)) { CHECK(0); return; }

    int pipefd[2];
    if (pipe(pipefd) != 0) { CHECK(0); return; }

    pid_t child = fork();
    if (child < 0) { CHECK(0); return; }

    if (child == 0) {
        /* ---- child ---- */
        close(pipefd[1]);

        /* Receive parent's listening port. */
        int port = 0;
        if (read(pipefd[0], &port, sizeof(port)) != sizeof(port)) _exit(10);
        close(pipefd[0]);

        if (chdir(tmpdir_b) != 0) _exit(11);

        /* Bootstrap: tell sync layer where the parent's server is. */
        sync_add_peer("127.0.0.1", port);

        /* Pull from registered peers (the parent). */
        int added = sync_with_peers();

        /* Verify something arrived. */
        int lines = count_db_lines();

        unlink("registry.db");
        _exit((added > 0 && lines > 0) ? 0 : 1);
    }

    /* ---- parent ---- */
    close(pipefd[0]);
    chdir(tmpdir_a);

    /* Write a few lines to messages.db via the protocol layer. */
    proto_chat chat;
    char user_key[64], secret_id[64];
    proto_initialize(&chat, user_key, secret_id);
    proto_send(&chat, "sync_test_message");
    proto_chat_cleanup(&chat);

    /* Start server so the child can connect. */
    int port = sync_start_server();

    /* Send port to child. */
    write(pipefd[1], &port, sizeof(port));
    close(pipefd[1]);

    /* Wait for child. */
    int status;
    waitpid(child, &status, 0);

    /* Tear down. */
    sync_unregister();

    char path[256];
    snprintf(path, sizeof(path), "%s/messages.db", tmpdir_a);
    unlink(path);
    rmdir(tmpdir_a);
    snprintf(path, sizeof(path), "%s/messages.db", tmpdir_b);
    unlink(path);
    rmdir(tmpdir_b);

    chdir(g_orig_cwd);

    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
#endif /* !_WIN32 */

/* ---- main ---- */

int main(void)
{
    if (!getcwd(g_orig_cwd, sizeof(g_orig_cwd))) {
        fprintf(stderr, "getcwd failed\n");
        return 1;
    }

    printf("=== sync tests ===\n");

    run_test("server_starts",           test_server_starts);
    run_test("register_and_unregister", test_register_and_unregister);
#ifndef _WIN32
    run_test("sync_pull",               test_sync_pull);
#else
    printf("skip  sync_pull (not supported on Windows)\n");
#endif

    printf("---\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
