#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#define ID_BYTES     16
#define MAX_LINE     8192
#define MAX_MSG      4096
#define PREFIX_BYTES 16

typedef struct {
    char **texts;
    int *sender; /* 0=initiator, 1=responder */
    int count;
} proto_messages;

typedef struct {
    uint8_t aes_key[32];
    uint8_t hmac_key[32];
    char send_prefix[64];
    char listen_prefix[64];
    char initial_prefix[64];
    char raw_listen_id[64];
    char user_key[ID_BYTES * 2 + 1];
    char secret_id[ID_BYTES * 2 + 1];
    int is_initiator;
    int has_sent_fid;
    int state; /* 0=uninit, 1=can_send, 2=need_list */
    /* message cache */
    proto_messages msgs;
    time_t cache_mtime;
    off_t cache_size;
    int cache_valid;
} proto_chat;

int  proto_initialize(proto_chat *chat, char *out_user_key, char *out_secret_id);
void proto_join(proto_chat *chat, const char *user_key, const char *secret_id);
const proto_messages *proto_list(proto_chat *chat);
int  proto_send(proto_chat *chat, const char *msg);
void proto_messages_free(proto_messages *msgs);
void proto_chat_cleanup(proto_chat *chat);

int proto_save_chat(const proto_chat *chat, const char *name, const char *basedir);
int proto_load_chat(proto_chat *chat, const char *name, const char *basedir);

/* DB locking for cross-thread synchronization */
void proto_db_rdlock(void);
void proto_db_wrlock(void);
void proto_db_unlock(void);

#endif
