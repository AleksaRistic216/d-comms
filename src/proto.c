#include "compat.h"

#include <pthread.h>

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
    unsigned char tmp[32];
    if (bytes > (int)sizeof(tmp)) return -1;
    if (dcomms_random_bytes(tmp, (size_t)bytes) != 0) return -1;
    for (int i = 0; i < bytes; i++)
        sprintf(buf + i * 2, "%02x", tmp[i]);
    buf[bytes * 2] = '\0';
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

/*
 * Slow KDF: hash secret_id-salted strings then iterate SHA-256 KDF_ROUNDS
 * times.  An attacker must pay this cost per credential guess; legitimate
 * users pay it once per proto_initialize / proto_join / proto_load_chat.
 */
static void derive_keys(const char *user_key, const char *secret_id,
                        uint8_t aes_key[32], uint8_t hmac_key[32])
{
    char buf[256];
    int n;

    /* AES key: iterate SHA-256 starting from SHA-256("aes:<key>:<salt>") */
    n = snprintf(buf, sizeof(buf), "aes:%s:%s", user_key, secret_id);
    sha256((const uint8_t *)buf, (size_t)n, aes_key);
    for (int i = 0; i < KDF_ROUNDS; i++)
        sha256(aes_key, 32, aes_key);

    /* HMAC key: same scheme with a different domain prefix */
    n = snprintf(buf, sizeof(buf), "hmac:%s:%s", user_key, secret_id);
    sha256((const uint8_t *)buf, (size_t)n, hmac_key);
    for (int i = 0; i < KDF_ROUNDS; i++)
        sha256(hmac_key, 32, hmac_key);
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
    dcomms_flock(fileno(f), LOCK_EX);
    fprintf(f, "%s.%s\n", prefix, hex_data);
    fflush(f);
    dcomms_flock(fileno(f), LOCK_UN);
    fclose(f);
    proto_db_unlock();
}

static int db_read(const char *prefix, char ***out)
{
    proto_db_rdlock();
    FILE *f = fopen(DB_FILE, "r");
    if (!f) { *out = NULL; proto_db_unlock(); return 0; }
    dcomms_flock(fileno(f), LOCK_SH);

    int cap = 16, count = 0;
    char **res = malloc(sizeof(char *) * (size_t)cap);
    if (!res) { dcomms_flock(fileno(f), LOCK_UN); fclose(f); proto_db_unlock(); *out = NULL; return 0; }

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

    dcomms_flock(fileno(f), LOCK_UN);
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

    derive_keys(user_key, secret_id, chat->aes_key, chat->hmac_key);

    char hprefix[PREFIX_BYTES * 2 + 1];
    hash_prefix(secret_id, hprefix);

    strncpy(chat->send_prefix, hprefix, sizeof(chat->send_prefix) - 1);
    strncpy(chat->initial_prefix, hprefix, sizeof(chat->initial_prefix) - 1);

    strncpy(chat->raw_listen_id, fid, sizeof(chat->raw_listen_id) - 1);
    hash_prefix(fid, chat->listen_prefix);

    gen_hex(chat->entity_id, 8);

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

    derive_keys(user_key, secret_id, chat->aes_key, chat->hmac_key);

    hash_prefix(secret_id, chat->listen_prefix);
    strncpy(chat->initial_prefix, chat->listen_prefix, sizeof(chat->initial_prefix) - 1);

    chat->is_initiator = 0;
    chat->send_prefix[0] = '\0';
    chat->raw_listen_id[0] = '\0';
    chat->has_sent_fid = 0;
    chat->state = 2;

    gen_hex(chat->entity_id, 8);
}

/* Returns 1 if s looks like a raw FID: exactly ID_BYTES*2 lowercase hex chars,
   no newline.  Used to detect stray FIDs written by racing clients. */
static int is_fid(const char *s)
{
    if (!s) return 0;
    size_t len = strlen(s);
    if (len != (size_t)(ID_BYTES * 2)) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

static void do_chain_walk(proto_chat *chat)
{
    proto_messages_free(&chat->msgs);

    int cap = 16;
    chat->msgs.texts = malloc(sizeof(char *) * (size_t)cap);
    chat->msgs.entity_ids = malloc(sizeof(char *) * (size_t)cap);
    chat->msgs.sender = malloc(sizeof(int) * (size_t)cap);
    chat->msgs.count = 0;
    if (!chat->msgs.texts || !chat->msgs.entity_ids || !chat->msgs.sender) return;

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

        /* Decrypt all entries in this group.
           - FIDs: pick the canonical one = smallest encrypted hex string, so
             all clients agree regardless of DB file order.
           - Messages: collect with timestamp, sort for consistent display. */

        struct grp_msg {
            char *eid;
            char *text;
            char *sort_hex;  /* encrypted hex — sort key, uncontrollable by sender */
        };
        struct grp_msg *mbuf = malloc(sizeof(struct grp_msg) * (size_t)count);
        int mcount = 0;

        char *fid     = NULL;
        char *fid_hex = NULL;  /* encrypted hex string of winning FID */

        for (int i = 0; i < count; i++) {
            char *plain = decrypt_from_hex(chat->aes_key, chat->hmac_key, hex[i]);
            if (!plain) { free(hex[i]); continue; }

            if (is_fid(plain)) {
                /* Smallest encrypted hex wins → deterministic across all clients */
                if (!fid_hex || strcmp(hex[i], fid_hex) < 0) {
                    free(fid);
                    free(fid_hex);
                    fid     = plain;
                    fid_hex = hex[i];   /* takes ownership */
                } else {
                    free(plain);
                    free(hex[i]);
                }
            } else {
                /* Parse: entity_id(16) '\n' text
                   Falls back to empty eid for old-format messages. */
                const char *nl = strchr(plain, '\n');
                char *eid;
                char *text;
                if (nl && (nl - plain) == 16) {
                    eid  = strndup(plain, 16);
                    text = strdup(nl + 1);
                    free(plain);
                } else {
                    eid  = strdup("");
                    text = plain;
                }
                if (mbuf) {
                    mbuf[mcount].eid      = eid;
                    mbuf[mcount].text     = text;
                    mbuf[mcount].sort_hex = hex[i];  /* takes ownership */
                    mcount++;
                } else {
                    free(eid);
                    free(text);
                    free(hex[i]);
                }
            }
        }
        free(hex);

        if (!fid) {
            for (int i = 0; i < mcount; i++) {
                free(mbuf[i].eid);
                free(mbuf[i].text);
                free(mbuf[i].sort_hex);
            }
            free(mbuf);
            free(fid_hex);
            break;
        }
        free(fid_hex);

        strncpy(last_raw_fid, fid, sizeof(last_raw_fid) - 1);
        last_raw_fid[sizeof(last_raw_fid) - 1] = '\0';

        /* Sort by encrypted hex string — determined by the random AES IV,
           not the sender's clock, so no client can influence their position. */
        for (int i = 1; i < mcount; i++) {
            struct grp_msg tmp = mbuf[i];
            int j = i - 1;
            while (j >= 0 && strcmp(mbuf[j].sort_hex, tmp.sort_hex) > 0) {
                mbuf[j + 1] = mbuf[j];
                j--;
            }
            mbuf[j + 1] = tmp;
        }

        int sender = groups % 2;
        for (int i = 0; i < mcount; i++) {
            if (chat->msgs.count >= cap) {
                cap *= 2;
                char **tt  = realloc(chat->msgs.texts,      sizeof(char *) * (size_t)cap);
                char **tei = realloc(chat->msgs.entity_ids, sizeof(char *) * (size_t)cap);
                int  *ts   = realloc(chat->msgs.sender,     sizeof(int)    * (size_t)cap);
                if (!tt || !tei || !ts) {
                    free(mbuf[i].eid); free(mbuf[i].text); free(mbuf[i].sort_hex);
                    continue;
                }
                chat->msgs.texts      = tt;
                chat->msgs.entity_ids = tei;
                chat->msgs.sender     = ts;
            }
            chat->msgs.entity_ids[chat->msgs.count] = mbuf[i].eid;
            chat->msgs.texts[chat->msgs.count]      = mbuf[i].text;
            chat->msgs.sender[chat->msgs.count]     = sender;
            chat->msgs.count++;
            free(mbuf[i].sort_hex);
        }
        free(mbuf);

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
        /* Re-sync before writing the FID: another client may have already
           started this group.  If so, do_chain_walk will flip has_sent_fid
           to 1 and we skip writing a duplicate FID. */
        chat->cache_valid = 0;
        do_chain_walk(chat);
    }

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

    /* Format: entity_id (16 hex) + '\n' + user message */
    char tagged[MAX_MSG + 20];
    snprintf(tagged, sizeof(tagged), "%s\n%s", chat->entity_id, msg);
    char *enc_msg = encrypt_to_hex(chat->aes_key, chat->hmac_key, tagged);
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
    for (int i = 0; i < msgs->count; i++)
        free(msgs->entity_ids[i]);
    free(msgs->entity_ids);
    free(msgs->sender);
    msgs->texts = msgs->entity_ids = NULL;
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
    dcomms_mkdir(dir, 0700);

    char path[512];
    snprintf(path, sizeof(path), "%s/chats/%s.chat", basedir, name);

    int fd = dcomms_open_private(path);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }

    fprintf(f, "user_key=%s\n", chat->user_key);
    fprintf(f, "secret_id=%s\n", chat->secret_id);
    fprintf(f, "is_initiator=%d\n", chat->is_initiator);
    fprintf(f, "entity_id=%s\n", chat->entity_id);
    fclose(f);
    return 0;
}

int proto_load_chat(proto_chat *chat, const char *name, const char *basedir)
{
    memset(chat, 0, sizeof(*chat));

    char path[512];
    snprintf(path, sizeof(path), "%s/chats/%s.chat", basedir, name);
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];

    while (fgets(line, sizeof(line), f)) {
        int len = (int)strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';

        if (strncmp(line, "user_key=", 9) == 0)
            strncpy(chat->user_key, line + 9, sizeof(chat->user_key) - 1);
        else if (strncmp(line, "secret_id=", 10) == 0)
            strncpy(chat->secret_id, line + 10, sizeof(chat->secret_id) - 1);
        else if (strncmp(line, "is_initiator=", 13) == 0)
            chat->is_initiator = atoi(line + 13);
        else if (strncmp(line, "entity_id=", 10) == 0)
            strncpy(chat->entity_id, line + 10, sizeof(chat->entity_id) - 1);
    }
    fclose(f);

    derive_keys(chat->user_key, chat->secret_id, chat->aes_key, chat->hmac_key);
    hash_prefix(chat->secret_id, chat->initial_prefix);
    chat->state = 2;

    /* Sync state by walking the message chain */
    proto_list(chat);

    return 0;
}
