/*
 * test_proto.c — integration tests for the protocol layer (proto.c)
 *
 * messages.db is opened relative to CWD, so every test that touches the DB
 * creates a fresh temporary directory and chdir()s into it, then cleans up.
 */

#include "test_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#  include <unistd.h>
#endif
#include <sys/stat.h>

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

/* Returns 1 iff str is exactly n lowercase hex chars. */
static int is_hex(const char *str, int n)
{
    if ((int)strlen(str) != n) return 0;
    for (int i = 0; i < n; i++) {
        char c = str[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
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

/* Create a temp dir, chdir into it. Returns 0 on success, -1 on failure. */
static int setup(char *tmpdir /* caller supplies char[64] */)
{
    strcpy(tmpdir, DCOMMS_TEST_TMPDIR);
    if (!mkdtemp(tmpdir)) return -1;
    return chdir(tmpdir);
}

/* Remove messages.db and return to the original CWD. */
static void teardown(const char *tmpdir)
{
    unlink("messages.db");
    chdir(g_orig_cwd);
    rmdir(tmpdir);
}

/* ---- tests ---- */

/* proto_initialize must produce valid hex credentials and set state fields. */
static void test_credentials_format(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat chat;
    char user_key[64], secret_id[64];
    int r = proto_initialize(&chat, user_key, secret_id);

    CHECK(r == 0);
    CHECK(is_hex(user_key,   32));
    CHECK(is_hex(secret_id,  32));
    CHECK(is_hex(chat.entity_id, 16));
    CHECK(chat.is_initiator == 1);
    CHECK(chat.state == 1);

    proto_chat_cleanup(&chat);
    teardown(tmpdir);
}

/* proto_initialize must write exactly one line to messages.db (the FID). */
static void test_init_writes_fid(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat chat;
    char user_key[64], secret_id[64];
    proto_initialize(&chat, user_key, secret_id);

    CHECK(count_db_lines() == 1);

    proto_chat_cleanup(&chat);
    teardown(tmpdir);
}

/* Each proto_send must append exactly one line to messages.db. */
static void test_send_appends_db_line(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat chat;
    char user_key[64], secret_id[64];
    proto_initialize(&chat, user_key, secret_id);
    int before = count_db_lines();

    proto_send(&chat, "hello");
    CHECK(count_db_lines() == before + 1);

    proto_send(&chat, "world");
    CHECK(count_db_lines() == before + 2);

    proto_chat_cleanup(&chat);
    teardown(tmpdir);
}

/* proto_list must return the text and correct sender flag. */
static void test_list_returns_sent_message(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat chat;
    char user_key[64], secret_id[64];
    proto_initialize(&chat, user_key, secret_id);
    proto_send(&chat, "hello world");

    const proto_messages *msgs = proto_list(&chat);
    CHECK(msgs->count == 1);
    CHECK(msgs->texts[0] != NULL);
    CHECK(strcmp(msgs->texts[0], "hello world") == 0);
    CHECK(msgs->sender[0] == 0); /* initiator side */

    proto_chat_cleanup(&chat);
    teardown(tmpdir);
}

/* A zero-initialised proto_chat (state=0) must reject sends. */
static void test_uninit_send_fails(void)
{
    proto_chat chat;
    memset(&chat, 0, sizeof(chat)); /* state = 0 */
    CHECK(proto_send(&chat, "hello") == -1);
}

/* proto_join leaves state=2 (need_list), so the immediate send must fail. */
static void test_responder_send_before_list_fails(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat init_chat;
    char user_key[64], secret_id[64];
    proto_initialize(&init_chat, user_key, secret_id);
    proto_chat_cleanup(&init_chat);

    proto_chat resp;
    proto_join(&resp, user_key, secret_id);
    CHECK(resp.state == 2);
    CHECK(proto_send(&resp, "too early") == -1);

    proto_chat_cleanup(&resp);
    teardown(tmpdir);
}

/* After proto_list the responder walks the chain, reaches state=1, and
   can call proto_send successfully. */
static void test_responder_can_send_after_list(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat init_chat;
    char user_key[64], secret_id[64];
    proto_initialize(&init_chat, user_key, secret_id);
    proto_chat_cleanup(&init_chat);

    proto_chat resp;
    proto_join(&resp, user_key, secret_id);
    proto_list(&resp);

    CHECK(resp.state == 1);
    CHECK(proto_send(&resp, "reply") == 0);

    proto_chat_cleanup(&resp);
    teardown(tmpdir);
}

/* Full two-party exchange: initiator sends → responder reads + replies →
   initiator reads both messages. */
static void test_full_exchange(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat a;
    char user_key[64], secret_id[64];
    proto_initialize(&a, user_key, secret_id);
    proto_send(&a, "ping");

    proto_chat b;
    proto_join(&b, user_key, secret_id);

    const proto_messages *b_msgs = proto_list(&b);
    CHECK(b_msgs->count == 1);
    CHECK(strcmp(b_msgs->texts[0], "ping") == 0);
    CHECK(b_msgs->sender[0] == 0); /* initiator side */

    CHECK(proto_send(&b, "pong") == 0);

    const proto_messages *a_msgs = proto_list(&a);
    CHECK(a_msgs->count == 2);
    /* Order within different groups follows chain order. */
    CHECK(strcmp(a_msgs->texts[0], "ping") == 0);
    CHECK(strcmp(a_msgs->texts[1], "pong") == 0);
    CHECK(a_msgs->sender[0] == 0);
    CHECK(a_msgs->sender[1] == 1); /* responder side */

    /* Initiator can now send a second turn. */
    CHECK(a.state == 1);
    CHECK(proto_send(&a, "done") == 0);

    proto_chat_cleanup(&a);
    proto_chat_cleanup(&b);
    teardown(tmpdir);
}

/* Three-turn exchange verifying sides alternate correctly. */
static void test_three_turn_exchange(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat a;
    char user_key[64], secret_id[64];
    proto_initialize(&a, user_key, secret_id);
    proto_send(&a, "A1");

    proto_chat b;
    proto_join(&b, user_key, secret_id);
    proto_list(&b);
    proto_send(&b, "B1");

    proto_list(&a);
    proto_send(&a, "A2");

    const proto_messages *msgs = proto_list(&b);
    CHECK(msgs->count == 3);
    CHECK(msgs->sender[0] == 0); /* A1 */
    CHECK(msgs->sender[1] == 1); /* B1 */
    CHECK(msgs->sender[2] == 0); /* A2 */

    proto_chat_cleanup(&a);
    proto_chat_cleanup(&b);
    teardown(tmpdir);
}

/* Multiple messages from the same client all carry the same entity_id. */
static void test_entity_id_consistency(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat a;
    char user_key[64], secret_id[64];
    proto_initialize(&a, user_key, secret_id);
    proto_send(&a, "msg1");
    proto_send(&a, "msg2");
    proto_send(&a, "msg3");

    const proto_messages *msgs = proto_list(&a);
    CHECK(msgs->count == 3);

    /* All entity IDs are valid 16-char hex strings. */
    for (int i = 0; i < msgs->count; i++)
        CHECK(is_hex(msgs->entity_ids[i], 16));

    /* All from the same client instance → same entity_id. */
    CHECK(strcmp(msgs->entity_ids[0], msgs->entity_ids[1]) == 0);
    CHECK(strcmp(msgs->entity_ids[1], msgs->entity_ids[2]) == 0);

    /* entity_id in messages matches the struct field. */
    CHECK(strcmp(msgs->entity_ids[0], a.entity_id) == 0);

    proto_chat_cleanup(&a);
    teardown(tmpdir);
}

/* Two responders joined with the same credentials both write into the same
   group, and their messages appear with distinct entity_ids. */
static void test_two_responders_same_group(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat a;
    char user_key[64], secret_id[64];
    proto_initialize(&a, user_key, secret_id);

    proto_chat b1, b2;
    proto_join(&b1, user_key, secret_id);
    proto_join(&b2, user_key, secret_id);

    proto_list(&b1);
    proto_list(&b2);

    CHECK(b1.state == 1);
    CHECK(b2.state == 1);

    /* b1 sends first — writes FID for group 1 and one message. */
    CHECK(proto_send(&b1, "from_b1") == 0);

    /* b2 re-syncs (has_sent_fid=0), finds b1's FID, writes into the same group. */
    CHECK(proto_send(&b2, "from_b2") == 0);

    /* Initiator lists — sees both messages in one responder group. */
    const proto_messages *msgs = proto_list(&a);
    CHECK(msgs->count == 2);
    CHECK(msgs->sender[0] == 1);
    CHECK(msgs->sender[1] == 1);

    /* Different entity_ids for b1 and b2. */
    CHECK(strcmp(msgs->entity_ids[0], msgs->entity_ids[1]) != 0);

    int found_b1 = 0, found_b2 = 0;
    for (int i = 0; i < msgs->count; i++) {
        if (strcmp(msgs->texts[i], "from_b1") == 0) found_b1 = 1;
        if (strcmp(msgs->texts[i], "from_b2") == 0) found_b2 = 1;
    }
    CHECK(found_b1 && found_b2);

    proto_chat_cleanup(&a);
    proto_chat_cleanup(&b1);
    proto_chat_cleanup(&b2);
    teardown(tmpdir);
}

/* Multiple messages in one group: all must appear (order is by encrypted hex). */
static void test_multiple_messages_all_present(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat a;
    char user_key[64], secret_id[64];
    proto_initialize(&a, user_key, secret_id);
    proto_send(&a, "alpha");
    proto_send(&a, "beta");
    proto_send(&a, "gamma");

    const proto_messages *msgs = proto_list(&a);
    CHECK(msgs->count == 3);

    for (int i = 0; i < msgs->count; i++)
        CHECK(msgs->sender[i] == 0);

    int fa = 0, fb = 0, fg = 0;
    for (int i = 0; i < msgs->count; i++) {
        if (strcmp(msgs->texts[i], "alpha") == 0) fa = 1;
        if (strcmp(msgs->texts[i], "beta")  == 0) fb = 1;
        if (strcmp(msgs->texts[i], "gamma") == 0) fg = 1;
    }
    CHECK(fa && fb && fg);

    proto_chat_cleanup(&a);
    teardown(tmpdir);
}

/* After proto_send the cache is invalidated, and the next proto_list must
   reflect the new message. */
static void test_cache_invalidated_after_send(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat a;
    char user_key[64], secret_id[64];
    proto_initialize(&a, user_key, secret_id);

    proto_send(&a, "first");
    CHECK(proto_list(&a)->count == 1);

    proto_send(&a, "second");
    CHECK(proto_list(&a)->count == 2);

    proto_chat_cleanup(&a);
    teardown(tmpdir);
}

/* proto_save_chat / proto_load_chat must persist state across struct instances. */
static void test_save_and_load_chat(void)
{
    char tmpdir[64];
    if (setup(tmpdir) != 0) { CHECK(0); return; }

    proto_chat a;
    char user_key[64], secret_id[64];
    proto_initialize(&a, user_key, secret_id);
    proto_send(&a, "persisted");

    int r = proto_save_chat(&a, "tc", tmpdir);
    CHECK(r == 0);
    proto_chat_cleanup(&a);

    proto_chat b;
    r = proto_load_chat(&b, "tc", tmpdir);
    CHECK(r == 0);
    CHECK(b.is_initiator == 1);
    CHECK(strcmp(b.user_key,  user_key)  == 0);
    CHECK(strcmp(b.secret_id, secret_id) == 0);

    const proto_messages *msgs = proto_list(&b);
    CHECK(msgs->count == 1);
    CHECK(strcmp(msgs->texts[0], "persisted") == 0);

    /* A loaded chat can still send. */
    CHECK(b.state == 1);

    /* Cleanup chat file. */
    char chat_path[256];
    snprintf(chat_path, sizeof(chat_path), "%s/chats/tc.chat", tmpdir);
    unlink(chat_path);
    char chats_dir[256];
    snprintf(chats_dir, sizeof(chats_dir), "%s/chats", tmpdir);
    rmdir(chats_dir);

    proto_chat_cleanup(&b);
    teardown(tmpdir);
}

/* proto_list on an uninitialised chat must return 0 messages safely. */
static void test_list_uninit_is_empty(void)
{
    proto_chat chat;
    memset(&chat, 0, sizeof(chat)); /* state = 0 */
    const proto_messages *msgs = proto_list(&chat);
    CHECK(msgs->count == 0);
}

/* ---- main ---- */

int main(void)
{
    if (!getcwd(g_orig_cwd, sizeof(g_orig_cwd))) {
        fprintf(stderr, "getcwd failed\n");
        return 1;
    }

    printf("=== proto tests ===\n");

    run_test("credentials_format",              test_credentials_format);
    run_test("init_writes_fid",                 test_init_writes_fid);
    run_test("send_appends_db_line",            test_send_appends_db_line);
    run_test("list_returns_sent_message",       test_list_returns_sent_message);
    run_test("uninit_send_fails",               test_uninit_send_fails);
    run_test("responder_send_before_list_fails",test_responder_send_before_list_fails);
    run_test("responder_can_send_after_list",   test_responder_can_send_after_list);
    run_test("full_exchange",                   test_full_exchange);
    run_test("three_turn_exchange",             test_three_turn_exchange);
    run_test("entity_id_consistency",           test_entity_id_consistency);
    run_test("two_responders_same_group",       test_two_responders_same_group);
    run_test("multiple_messages_all_present",   test_multiple_messages_all_present);
    run_test("cache_invalidated_after_send",    test_cache_invalidated_after_send);
    run_test("save_and_load_chat",              test_save_and_load_chat);
    run_test("list_uninit_is_empty",            test_list_uninit_is_empty);

    printf("---\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
