#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>

#include "sync.h"
#include "proto.h"

#define DB_FILE      "messages.db"
#define MAX_LINE     8192
#define SYNC_TIMEOUT 1 /* seconds */

static int g_server_fd = -1;
static pthread_t g_server_tid;
static volatile int g_server_quit;
static pid_t g_pid;

static void get_registry_path(char *buf, size_t sz)
{
    const char *home = getenv("HOME");
    if (home)
        snprintf(buf, sz, "%s/dcomms-registry.db", home);
    else
        snprintf(buf, sz, "dcomms-registry.db");
}

/* ---- hash set for O(1) line dedup ---- */

#define HS_BUCKETS 1024

typedef struct hs_node {
    char *key;
    struct hs_node *next;
} hs_node;

typedef struct {
    hs_node *buckets[HS_BUCKETS];
} hash_set;

static void hs_init(hash_set *hs)
{
    memset(hs, 0, sizeof(*hs));
}

static unsigned hs_hash(const char *s)
{
    unsigned h = 5381;
    while (*s) h = h * 33 + (unsigned char)*s++;
    return h & (HS_BUCKETS - 1);
}

static int hs_contains(const hash_set *hs, const char *key)
{
    unsigned h = hs_hash(key);
    for (hs_node *n = hs->buckets[h]; n; n = n->next)
        if (strcmp(n->key, key) == 0) return 1;
    return 0;
}

static void hs_add(hash_set *hs, const char *key)
{
    unsigned h = hs_hash(key);
    hs_node *n = malloc(sizeof(*n));
    if (!n) return;
    n->key = strdup(key);
    if (!n->key) { free(n); return; }
    n->next = hs->buckets[h];
    hs->buckets[h] = n;
}

static void hs_free(hash_set *hs)
{
    for (int i = 0; i < HS_BUCKETS; i++) {
        hs_node *n = hs->buckets[i];
        while (n) {
            hs_node *next = n->next;
            free(n->key);
            free(n);
            n = next;
        }
    }
}

/* ---- server ---- */

static void *server_thread(void *arg)
{
    (void)arg;
    while (!g_server_quit) {
        struct sockaddr_in ca;
        socklen_t ca_len = sizeof(ca);
        int cfd = accept(g_server_fd, (struct sockaddr *)&ca, &ca_len);
        if (cfd < 0) break;

        /* Set send timeout so we don't block forever on slow clients */
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        proto_db_rdlock();
        FILE *db = fopen(DB_FILE, "r");
        if (db) {
            flock(fileno(db), LOCK_SH);
            char line[MAX_LINE];
            while (fgets(line, sizeof(line), db)) {
                size_t len = strlen(line);
                size_t sent = 0;
                while (sent < len) {
                    ssize_t n = write(cfd, line + sent, len - sent);
                    if (n <= 0) break;
                    sent += (size_t)n;
                }
            }
            flock(fileno(db), LOCK_UN);
            fclose(db);
        }
        proto_db_unlock();
        close(cfd);
    }
    return NULL;
}

int sync_start_server(void)
{
    g_pid = getpid();
    g_server_quit = 0;

    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_fd < 0) return -1;

    int opt = 1;
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    socklen_t alen = sizeof(addr);
    getsockname(g_server_fd, (struct sockaddr *)&addr, &alen);

    if (listen(g_server_fd, 4) < 0) {
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    if (pthread_create(&g_server_tid, NULL, server_thread, NULL) != 0) {
        close(g_server_fd);
        g_server_fd = -1;
        return -1;
    }

    return ntohs(addr.sin_port);
}

/* ---- registry (atomic read-modify-write with LOCK_EX) ---- */

void sync_register(int port)
{
    char regpath[512];
    get_registry_path(regpath, sizeof(regpath));

    /* Open or create; use "a+" so fopen succeeds even if file doesn't exist */
    FILE *f = fopen(regpath, "a+");
    if (!f) return;
    flock(fileno(f), LOCK_EX);
    rewind(f);

    /* Read existing live entries */
    char keep[64][64];
    int count = 0;
    char line[64];
    while (fgets(line, sizeof(line), f) && count < 63) {
        int pid, p;
        if (sscanf(line, "%d:%d", &pid, &p) == 2 &&
            pid != (int)getpid() && kill(pid, 0) == 0) {
            strncpy(keep[count], line, sizeof(keep[0]) - 1);
            keep[count][sizeof(keep[0]) - 1] = '\0';
            count++;
        }
    }

    /* Truncate and rewrite atomically (still holding lock) */
    if (ftruncate(fileno(f), 0) != 0) {
        flock(fileno(f), LOCK_UN);
        fclose(f);
        return;
    }
    rewind(f);
    for (int i = 0; i < count; i++)
        fputs(keep[i], f);
    fprintf(f, "%d:%d\n", (int)getpid(), port);
    fflush(f);

    flock(fileno(f), LOCK_UN);
    fclose(f);
}

void sync_unregister(void)
{
    char regpath[512];
    get_registry_path(regpath, sizeof(regpath));

    FILE *f = fopen(regpath, "r+");
    if (!f) goto shutdown_server;
    flock(fileno(f), LOCK_EX);

    char keep[64][64];
    int count = 0;
    char line[64];
    while (fgets(line, sizeof(line), f) && count < 64) {
        int pid, p;
        if (sscanf(line, "%d:%d", &pid, &p) == 2 && pid != (int)g_pid) {
            strncpy(keep[count], line, sizeof(keep[0]) - 1);
            keep[count][sizeof(keep[0]) - 1] = '\0';
            count++;
        }
    }

    ftruncate(fileno(f), 0);
    rewind(f);
    for (int i = 0; i < count; i++)
        fputs(keep[i], f);
    fflush(f);

    flock(fileno(f), LOCK_UN);
    fclose(f);

shutdown_server:
    g_server_quit = 1;
    if (g_server_fd >= 0) {
        shutdown(g_server_fd, SHUT_RDWR);
        close(g_server_fd);
        g_server_fd = -1;
    }
    pthread_join(g_server_tid, NULL);
}

/* ---- sync client ---- */

int sync_with_peers(void)
{
    char regpath[512];
    get_registry_path(regpath, sizeof(regpath));

    FILE *rf = fopen(regpath, "r");
    if (!rf) return 0;

    /* Collect live peers */
    int ports[64];
    int peer_count = 0;
    char line[64];
    while (fgets(line, sizeof(line), rf) && peer_count < 64) {
        int pid, port;
        if (sscanf(line, "%d:%d", &pid, &port) == 2 &&
            pid != (int)getpid() && kill(pid, 0) == 0) {
            ports[peer_count++] = port;
        }
    }
    fclose(rf);

    if (peer_count == 0) return 0;

    /* Build hash set of local lines */
    hash_set hs;
    hs_init(&hs);

    proto_db_rdlock();
    FILE *lf = fopen(DB_FILE, "r");
    if (lf) {
        flock(fileno(lf), LOCK_SH);
        char lline[MAX_LINE];
        while (fgets(lline, sizeof(lline), lf)) {
            int len = (int)strlen(lline);
            if (len > 0 && lline[len - 1] == '\n') lline[--len] = '\0';
            if (len > 0) hs_add(&hs, lline);
        }
        flock(fileno(lf), LOCK_UN);
        fclose(lf);
    }
    proto_db_unlock();

    int added = 0;

    for (int p = 0; p < peer_count; p++) {
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sfd < 0) continue;

        struct timeval tv;
        tv.tv_sec = SYNC_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((uint16_t)ports[p]);

        if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(sfd);
            continue;
        }

        FILE *sf = fdopen(sfd, "r");
        if (!sf) { close(sfd); continue; }

        /* Collect new lines from this peer */
        int batch_cap = 256;
        char **batch = malloc(sizeof(char *) * (size_t)batch_cap);
        int batch_count = 0;

        char rline[MAX_LINE];
        while (batch && fgets(rline, sizeof(rline), sf)) {
            int len = (int)strlen(rline);
            if (len > 0 && rline[len - 1] == '\n') rline[--len] = '\0';
            if (len == 0) continue;

            if (!hs_contains(&hs, rline)) {
                if (batch_count >= batch_cap) {
                    batch_cap *= 2;
                    char **tmp = realloc(batch, sizeof(char *) * (size_t)batch_cap);
                    if (!tmp) break;
                    batch = tmp;
                }
                batch[batch_count++] = strdup(rline);
                hs_add(&hs, rline);
            }
        }
        fclose(sf);

        /* Batch write new lines */
        if (batch_count > 0) {
            proto_db_wrlock();
            FILE *db = fopen(DB_FILE, "a");
            if (db) {
                flock(fileno(db), LOCK_EX);
                for (int i = 0; i < batch_count; i++)
                    fprintf(db, "%s\n", batch[i]);
                fflush(db);
                flock(fileno(db), LOCK_UN);
                fclose(db);
            }
            proto_db_unlock();
        }

        for (int i = 0; i < batch_count; i++) free(batch[i]);
        free(batch);
        added += batch_count;
    }

    hs_free(&hs);
    return added;
}
