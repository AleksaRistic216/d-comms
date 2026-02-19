#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "proto.h"
#include "sha256.h"
#include "aes.h"

#define DB_FILE "messages.db"

/* ---- DB lock (intra-process thread safety) ---- */

static pthread_rwlock_t g_db_lock = PTHREAD_RWLOCK_INITIALIZER;

void proto_db_rdlock(void) { pthread_rwlock_rdlock(&g_db_lock); }
void proto_db_wrlock(void) { pthread_rwlock_wrlock(&g_db_lock); }
void proto_db_unlock(void) { pthread_rwlock_unlock(&g_db_lock); }

/* ---- helpers ---- */

static int gen_hex(char *buf, int bytes)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    for (int i = 0; i < bytes; i++) {
        unsigned char c;
        if (fread(&c, 1, 1, f) != 1) { fclose(f); return -1; }
        sprintf(buf + i * 2, "%02x", c);
    }
    buf[bytes * 2] = '\0';
    fclose(f);
    return 0;
}

static void hash_prefix(const char *raw_id, char *out)
{
    uint8_t hash[32];
    sha256((const uint8_t *)raw_id, strlen(raw_id), hash);
    for (int i = 0; i < PREFIX_BYTES; i++)
        sprintf(out + i * 2, "%02x", hash[i]);
    out[PREFIX_BYTES * 2] = '\0';
}

static void derive_keys(const char *user_key,
                        uint8_t aes_key[32], uint8_t hmac_key[32])
{
    sha256((const uint8_t *)user_key, strlen(user_key), aes_key);
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "hmac:%s", user_key);
    sha256((const uint8_t *)buf, (size_t)n, hmac_key);
}

static int hex_to_bin(const char *hex, size_t hex_len, uint8_t *bin)
{
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%02x", &b) != 1) return -1;
        bin[i] = (uint8_t)b;
    }
    return 0;
}

/* Encrypt plaintext, return hex(IV || ciphertext || HMAC-SHA256). Caller frees. */
static char *encrypt_to_hex(const uint8_t aes_key[32],
                            const uint8_t hmac_key[32],
                            const char *plain)
{
    size_t ct_len;
    uint8_t *ct = aes_cbc_encrypt(aes_key, (const uint8_t *)plain,
                                  strlen(plain), &ct_len);
    if (!ct) return NULL;

    /* HMAC over IV || ciphertext */
    uint8_t mac[32];
    hmac_sha256(hmac_key, 32, ct, ct_len, mac);

    /* Output: hex(ct) + hex(mac) */
    size_t total = ct_len + 32;
    char *hex = malloc(total * 2 + 1);
    if (!hex) { free(ct); return NULL; }
    for (size_t i = 0; i < ct_len; i++)
        sprintf(hex + i * 2, "%02x", ct[i]);
    for (size_t i = 0; i < 32; i++)
        sprintf(hex + (ct_len + i) * 2, "%02x", mac[i]);
    hex[total * 2] = '\0';

    free(ct);
    return hex;
}

/* Decrypt hex(IV || ciphertext || HMAC). Verifies MAC first. Caller frees. */
static char *decrypt_from_hex(const uint8_t aes_key[32],
                              const uint8_t hmac_key[32],
                              const char *hex)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return NULL;
    size_t bin_len = hex_len / 2;

    /* Need at least IV(16) + 1 block(16) + MAC(32) = 64 bytes */
    if (bin_len < 64) return NULL;

    uint8_t *bin = malloc(bin_len);
    if (!bin) return NULL;
    if (hex_to_bin(hex, hex_len, bin) != 0) { free(bin); return NULL; }

    /* Split: ct_data = IV||ciphertext, mac = last 32 bytes */
    size_t ct_len = bin_len - 32;
    const uint8_t *mac = bin + ct_len;

    /* Verify HMAC (constant-time compare) */
    uint8_t computed[32];
    hmac_sha256(hmac_key, 32, bin, ct_len, computed);
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= mac[i] ^ computed[i];
    if (diff != 0) { free(bin); return NULL; }

    /* Decrypt */
    size_t pt_len;
    uint8_t *pt = aes_cbc_decrypt(aes_key, bin, ct_len, &pt_len);
    free(bin);
    if (!pt) return NULL;

    char *str = malloc(pt_len + 1);
    if (!str) { free(pt); return NULL; }
    memcpy(str, pt, pt_len);
    str[pt_len] = '\0';

    free(pt);
    return str;
}

/* ---- database ---- */

static void db_append(const char *prefix, const char *hex_data)
{
    proto_db_wrlock();
    FILE *f = fopen(DB_FILE, "a");
    if (!f) { proto_db_unlock(); return; }
    flock(fileno(f), LOCK_EX);
    fprintf(f, "%s.%s\n", prefix, hex_data);
    fflush(f);
    flock(fileno(f), LOCK_UN);
    fclose(f);
    proto_db_unlock();
}

static int db_read(const char *prefix, char ***out)
{
    proto_db_rdlock();
    FILE *f = fopen(DB_FILE, "r");
    if (!f) { *out = NULL; proto_db_unlock(); return 0; }
    flock(fileno(f), LOCK_SH);

    int cap = 16, count = 0;
    char **res = malloc(sizeof(char *) * (size_t)cap);
    if (!res) { flock(fileno(f), LOCK_UN); fclose(f); proto_db_unlock(); *out = NULL; return 0; }

    char line[MAX_LINE];
    int plen = (int)strlen(prefix);

    while (fgets(line, sizeof(line), f)) {
        int len = (int)strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (strncmp(line, prefix, (size_t)plen) == 0 && line[plen] == '.') {
            if (count >= cap) {
                cap *= 2;
                char **tmp = realloc(res, sizeof(char *) * (size_t)cap);
                if (!tmp) break;
                res = tmp;
            }
            res[count++] = strdup(line + plen + 1);
        }
    }

    flock(fileno(f), LOCK_UN);
    fclose(f);
    proto_db_unlock();
    *out = res;
    return count;
}

/* ---- protocol functions ---- */

int proto_initialize(proto_chat *chat, char *out_user_key, char *out_secret_id)
{
    char secret_id[ID_BYTES * 2 + 1];
    char user_key[ID_BYTES * 2 + 1];
    char fid[ID_BYTES * 2 + 1];

    if (gen_hex(secret_id, ID_BYTES) != 0) return -1;
    if (gen_hex(user_key, ID_BYTES) != 0) return -1;
    if (gen_hex(fid, ID_BYTES) != 0) return -1;

    memset(chat, 0, sizeof(*chat));
    strncpy(chat->user_key, user_key, sizeof(chat->user_key) - 1);
    strncpy(chat->secret_id, secret_id, sizeof(chat->secret_id) - 1);

    derive_keys(user_key, chat->aes_key, chat->hmac_key);

    char hprefix[PREFIX_BYTES * 2 + 1];
    hash_prefix(secret_id, hprefix);

    strncpy(chat->send_prefix, hprefix, sizeof(chat->send_prefix) - 1);
    strncpy(chat->initial_prefix, hprefix, sizeof(chat->initial_prefix) - 1);

    strncpy(chat->raw_listen_id, fid, sizeof(chat->raw_listen_id) - 1);
    hash_prefix(fid, chat->listen_prefix);

    chat->is_initiator = 1;
    chat->has_sent_fid = 1;
    chat->state = 1;

    char *enc_fid = encrypt_to_hex(chat->aes_key, chat->hmac_key, fid);
    if (enc_fid) {
        db_append(hprefix, enc_fid);
        free(enc_fid);
    }

    strcpy(out_user_key, user_key);
    strcpy(out_secret_id, secret_id);
    return 0;
}

void proto_join(proto_chat *chat, const char *user_key, const char *secret_id)
{
    memset(chat, 0, sizeof(*chat));
    strncpy(chat->user_key, user_key, sizeof(chat->user_key) - 1);
    strncpy(chat->secret_id, secret_id, sizeof(chat->secret_id) - 1);

    derive_keys(user_key, chat->aes_key, chat->hmac_key);

    hash_prefix(secret_id, chat->listen_prefix);
    strncpy(chat->initial_prefix, chat->listen_prefix, sizeof(chat->initial_prefix) - 1);

    chat->is_initiator = 0;
    chat->send_prefix[0] = '\0';
    chat->raw_listen_id[0] = '\0';
    chat->has_sent_fid = 0;
    chat->state = 2;
}

static void do_chain_walk(proto_chat *chat)
{
    proto_messages_free(&chat->msgs);

    int cap = 16;
    chat->msgs.texts = malloc(sizeof(char *) * (size_t)cap);
    chat->msgs.sender = malloc(sizeof(int) * (size_t)cap);
    chat->msgs.count = 0;
    if (!chat->msgs.texts || !chat->msgs.sender) return;

    char cur[PREFIX_BYTES * 2 + 1];
    strncpy(cur, chat->initial_prefix, sizeof(cur) - 1);
    cur[sizeof(cur) - 1] = '\0';

    char last_prefix[PREFIX_BYTES * 2 + 1] = {0};
    char last_raw_fid[64] = {0};
    int groups = 0;

    while (1) {
        char **hex;
        int count = db_read(cur, &hex);
        if (count == 0) { free(hex); break; }

        strncpy(last_prefix, cur, sizeof(last_prefix) - 1);
        last_prefix[sizeof(last_prefix) - 1] = '\0';

        char *fid = decrypt_from_hex(chat->aes_key, chat->hmac_key, hex[0]);
        free(hex[0]);
        if (!fid) {
            for (int i = 1; i < count; i++) free(hex[i]);
            free(hex);
            break;
        }
        strncpy(last_raw_fid, fid, sizeof(last_raw_fid) - 1);
        last_raw_fid[sizeof(last_raw_fid) - 1] = '\0';

        int sender = groups % 2;
        for (int i = 1; i < count; i++) {
            char *plain = decrypt_from_hex(chat->aes_key, chat->hmac_key, hex[i]);
            free(hex[i]);
            if (plain) {
                if (chat->msgs.count >= cap) {
                    cap *= 2;
                    char **tt = realloc(chat->msgs.texts, sizeof(char *) * (size_t)cap);
                    int *ts = realloc(chat->msgs.sender, sizeof(int) * (size_t)cap);
                    if (!tt || !ts) { free(plain); continue; }
                    chat->msgs.texts = tt;
                    chat->msgs.sender = ts;
                }
                chat->msgs.texts[chat->msgs.count] = plain;
                chat->msgs.sender[chat->msgs.count] = sender;
                chat->msgs.count++;
            }
        }

        free(hex);
        groups++;
        hash_prefix(fid, cur);
        free(fid);
    }

    /* Update state based on who owns the last group */
    if (groups > 0) {
        int last_is_mine = (((groups - 1) % 2 == 0) == chat->is_initiator);
        if (last_is_mine) {
            strncpy(chat->send_prefix, last_prefix, sizeof(chat->send_prefix) - 1);
            chat->send_prefix[sizeof(chat->send_prefix) - 1] = '\0';

            strncpy(chat->raw_listen_id, last_raw_fid, sizeof(chat->raw_listen_id) - 1);
            chat->raw_listen_id[sizeof(chat->raw_listen_id) - 1] = '\0';
            hash_prefix(last_raw_fid, chat->listen_prefix);

            chat->has_sent_fid = 1;
        } else {
            hash_prefix(last_raw_fid, chat->send_prefix);
            chat->raw_listen_id[0] = '\0';
            chat->has_sent_fid = 0;
        }
        chat->state = 1;
    }

    /* Update cache metadata */
    struct stat st;
    if (stat(DB_FILE, &st) == 0) {
        chat->cache_mtime = st.st_mtime;
        chat->cache_size = st.st_size;
        chat->cache_valid = 1;
    }
}

const proto_messages *proto_list(proto_chat *chat)
{
    if (!chat->state) {
        proto_messages_free(&chat->msgs);
        return &chat->msgs;
    }

    /* Check if DB changed since last walk */
    struct stat st;
    if (chat->cache_valid &&
        stat(DB_FILE, &st) == 0 &&
        st.st_mtime == chat->cache_mtime &&
        st.st_size == chat->cache_size) {
        return &chat->msgs;
    }

    do_chain_walk(chat);
    return &chat->msgs;
}

int proto_send(proto_chat *chat, const char *msg)
{
    if (chat->state == 2) return -1;
    if (chat->state == 0 || chat->send_prefix[0] == '\0') return -1;

    if (!chat->has_sent_fid) {
        char new_fid[ID_BYTES * 2 + 1];
        if (gen_hex(new_fid, ID_BYTES) != 0) return -1;

        char *enc_fid = encrypt_to_hex(chat->aes_key, chat->hmac_key, new_fid);
        if (enc_fid) {
            db_append(chat->send_prefix, enc_fid);
            free(enc_fid);
        }

        strncpy(chat->raw_listen_id, new_fid, sizeof(chat->raw_listen_id) - 1);
        chat->raw_listen_id[sizeof(chat->raw_listen_id) - 1] = '\0';
        hash_prefix(new_fid, chat->listen_prefix);

        chat->has_sent_fid = 1;
    }

    char *enc_msg = encrypt_to_hex(chat->aes_key, chat->hmac_key, msg);
    if (enc_msg) {
        db_append(chat->send_prefix, enc_msg);
        free(enc_msg);
        chat->cache_valid = 0; /* invalidate cache after write */
        return 0;
    }
    return -1;
}

void proto_messages_free(proto_messages *msgs)
{
    if (!msgs) return;
    for (int i = 0; i < msgs->count; i++)
        free(msgs->texts[i]);
    free(msgs->texts);
    free(msgs->sender);
    msgs->texts = NULL;
    msgs->sender = NULL;
    msgs->count = 0;
}

void proto_chat_cleanup(proto_chat *chat)
{
    proto_messages_free(&chat->msgs);
    chat->cache_valid = 0;
}

/* ---- chat config persistence ---- */

int proto_save_chat(const proto_chat *chat, const char *name, const char *basedir)
{
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/chats", basedir);
    mkdir(dir, 0700);

    char path[512];
    snprintf(path, sizeof(path), "%s/chats/%s.chat", basedir, name);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }

    fprintf(f, "user_key=%s\n", chat->user_key);
    fprintf(f, "secret_id=%s\n", chat->secret_id);
    fprintf(f, "is_initiator=%d\n", chat->is_initiator);
    fclose(f);
    return 0;
}

int proto_load_chat(proto_chat *chat, const char *name, const char *basedir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/chats/%s.chat", basedir, name);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    memset(chat, 0, sizeof(*chat));

    while (fgets(line, sizeof(line), f)) {
        int len = (int)strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';

        if (strncmp(line, "user_key=", 9) == 0)
            strncpy(chat->user_key, line + 9, sizeof(chat->user_key) - 1);
        else if (strncmp(line, "secret_id=", 10) == 0)
            strncpy(chat->secret_id, line + 10, sizeof(chat->secret_id) - 1);
        else if (strncmp(line, "is_initiator=", 13) == 0)
            chat->is_initiator = atoi(line + 13);
    }
    fclose(f);

    derive_keys(chat->user_key, chat->aes_key, chat->hmac_key);
    hash_prefix(chat->secret_id, chat->initial_prefix);
    chat->state = 2;

    /* Sync state by walking the message chain */
    proto_list(chat);

    return 0;
}
