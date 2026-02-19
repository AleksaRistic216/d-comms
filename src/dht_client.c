/* System headers must come before dht.h (which omits its own prerequisites) */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "dht.h"
#include "dht_client.h"
#include "sync.h"
#include "sha256.h"

/* ---- Constants ---- */

#define MAX_ACTIVE_HASHES  64
#define QUEUE_SIZE         64
#define BOOTSTRAP_DELAY    30    /* seconds before first search */
#define SEARCH_INTERVAL    180   /* seconds between re-searches */
#define SELECT_TIMEOUT_MAX 1     /* cap select timeout to stay responsive */

/* ---- State ---- */

static pthread_t        g_dht_thread;
static volatile int     g_dht_running = 0;
static int              g_dht_fd      = -1;
static int              g_sync_port   = 0;
static char             g_basedir[256];

/* Active infohashes (only accessed from g_dht_thread) */
static unsigned char    g_active_hashes[MAX_ACTIVE_HASHES][20];
static time_t           g_last_search[MAX_ACTIVE_HASHES];
static int              g_active_count = 0;

/* Pending queue (shared, protected by g_queue_mutex) */
static char             g_pending[QUEUE_SIZE][33]; /* 32 hex + NUL */
static int              g_pending_head = 0;
static int              g_pending_tail = 0;
static pthread_mutex_t  g_queue_mutex  = PTHREAD_MUTEX_INITIALIZER;

/* ---- Infohash derivation ---- */

/* SHA256(user_key_hex_string)[0..19] — both peers compute identically. */
static void user_key_to_infohash(const char *user_key_hex, unsigned char ih[20])
{
    uint8_t hash[32];
    sha256((const uint8_t *)user_key_hex, strlen(user_key_hex), hash);
    memcpy(ih, hash, 20);
}

/* ---- jech/dht required user functions ---- */

int dht_blacklisted(const struct sockaddr *sa, int salen)
{
    (void)sa; (void)salen;
    return 0;
}

void dht_hash(void *hash_return, int hash_size,
              const void *v1, int len1,
              const void *v2, int len2,
              const void *v3, int len3)
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    if (v1 && len1 > 0) sha256_update(&ctx, (const uint8_t *)v1, (size_t)len1);
    if (v2 && len2 > 0) sha256_update(&ctx, (const uint8_t *)v2, (size_t)len2);
    if (v3 && len3 > 0) sha256_update(&ctx, (const uint8_t *)v3, (size_t)len3);
    uint8_t hash[32];
    sha256_final(&ctx, hash);
    int n = hash_size < 32 ? hash_size : 32;
    memcpy(hash_return, hash, (size_t)n);
}

int dht_random_bytes(void *buf, size_t size)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, size);
    close(fd);
    return (n == (ssize_t)size) ? 0 : -1;
}

int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *to, int tolen)
{
    return (int)sendto(sockfd, buf, (size_t)len, flags, to, (socklen_t)tolen);
}

/* ---- DHT event callback ---- */

static void dht_callback_fn(void *closure, int event,
                             const unsigned char *info_hash,
                             const void *data, size_t data_len)
{
    (void)closure; (void)info_hash;
    if (event == DHT_EVENT_VALUES) {
        /* Each entry is 6 bytes: 4-byte IPv4 address + 2-byte port (network order) */
        const unsigned char *p = (const unsigned char *)data;
        size_t i;
        for (i = 0; i + 6 <= data_len; i += 6) {
            char host[INET_ADDRSTRLEN];
            struct in_addr addr;
            memcpy(&addr, p + i, 4);
            inet_ntop(AF_INET, &addr, host, sizeof(host));
            int port = ((int)(p[i + 4]) << 8) | (int)(p[i + 5]);
            sync_add_peer(host, port);
        }
    }
}

/* ---- Node ID persistence ---- */

static void load_or_create_nodeid(unsigned char myid[20])
{
    char path[512];
    snprintf(path, sizeof(path), "%s/nodeid.db", g_basedir);

    FILE *f = fopen(path, "rb");
    if (f) {
        if (fread(myid, 1, 20, f) == 20) {
            fclose(f);
            return;
        }
        fclose(f);
    }

    /* Generate and persist a new random node ID */
    dht_random_bytes(myid, 20);
    f = fopen(path, "wb");
    if (f) {
        fwrite(myid, 1, 20, f);
        fclose(f);
    }
}

/* ---- Bootstrap ---- */

static void do_bootstrap(void)
{
    static const struct { const char *host; int port; } nodes[] = {
        { "router.bittorrent.com",  6881 },
        { "router.utorrent.com",    6881 },
        { "dht.transmissionbt.com", 6881 },
    };
    int n = (int)(sizeof(nodes) / sizeof(nodes[0]));

    for (int i = 0; i < n; i++) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        char port_str[8];
        snprintf(port_str, sizeof(port_str), "%d", nodes[i].port);
        if (getaddrinfo(nodes[i].host, port_str, &hints, &res) == 0 && res) {
            dht_ping_node((const struct sockaddr *)res->ai_addr, (int)res->ai_addrlen);
            freeaddrinfo(res);
        }
    }
}

/* ---- Drain pending queue into g_active_hashes ---- */

static void drain_queue(void)
{
    pthread_mutex_lock(&g_queue_mutex);
    while (g_pending_head != g_pending_tail) {
        char key_hex[33];
        strncpy(key_hex, g_pending[g_pending_head], 32);
        key_hex[32] = '\0';
        g_pending_head = (g_pending_head + 1) % QUEUE_SIZE;
        pthread_mutex_unlock(&g_queue_mutex);

        unsigned char ih[20];
        user_key_to_infohash(key_hex, ih);

        /* Skip if already active */
        int found = 0;
        for (int i = 0; i < g_active_count; i++) {
            if (memcmp(g_active_hashes[i], ih, 20) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && g_active_count < MAX_ACTIVE_HASHES) {
            memcpy(g_active_hashes[g_active_count], ih, 20);
            g_last_search[g_active_count] = 0; /* force search immediately */
            g_active_count++;
        }

        pthread_mutex_lock(&g_queue_mutex);
    }
    pthread_mutex_unlock(&g_queue_mutex);
}

/* ---- DHT thread ---- */

static void *dht_thread_fn(void *arg)
{
    (void)arg;

    unsigned char myid[20];
    load_or_create_nodeid(myid);

    /* Create UDP socket */
    g_dht_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_dht_fd < 0) return NULL;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port        = 0; /* any ephemeral port */
    bind(g_dht_fd, (struct sockaddr *)&sin, sizeof(sin));

    dht_init(g_dht_fd, -1, myid, NULL);
    do_bootstrap();

    time_t start_time   = time(NULL);
    int    bootstrapped = 0;
    time_t tosleep      = 1;

    unsigned char buf[4096];

    while (g_dht_running) {
        drain_queue();

        /* Allow searches once the routing table has had time to populate */
        if (!bootstrapped && (time(NULL) - start_time) >= BOOTSTRAP_DELAY)
            bootstrapped = 1;

        /* Periodic re-announce / re-search for each active hash */
        if (bootstrapped) {
            time_t now = time(NULL);
            for (int i = 0; i < g_active_count; i++) {
                if (now - g_last_search[i] >= SEARCH_INTERVAL) {
                    dht_search(g_active_hashes[i], g_sync_port, AF_INET,
                               dht_callback_fn, NULL);
                    g_last_search[i] = now;
                }
            }
        }

        /* Cap select timeout so we stay responsive to stop requests */
        time_t wait = tosleep < SELECT_TIMEOUT_MAX ? tosleep : SELECT_TIMEOUT_MAX;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_dht_fd, &rfds);
        struct timeval tv;
        tv.tv_sec  = wait;
        tv.tv_usec = 0;

        int rc = select(g_dht_fd + 1, &rfds, NULL, NULL, &tv);

        if (rc > 0 && FD_ISSET(g_dht_fd, &rfds)) {
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            ssize_t n = recvfrom(g_dht_fd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&from, &fromlen);
            if (n > 0) {
                buf[n] = '\0';
                dht_periodic(buf, (size_t)n, (struct sockaddr *)&from, (int)fromlen,
                             &tosleep, dht_callback_fn, NULL);
            }
        } else {
            dht_periodic(NULL, 0, NULL, 0, &tosleep, dht_callback_fn, NULL);
        }
    }

    dht_uninit();
    close(g_dht_fd);
    g_dht_fd = -1;
    return NULL;
}

/* ---- Public API ---- */

int dht_client_start(int sync_port, const char *basedir)
{
    if (g_dht_running) return 0;

    g_sync_port = sync_port;
    strncpy(g_basedir, basedir, sizeof(g_basedir) - 1);
    g_basedir[sizeof(g_basedir) - 1] = '\0';

    g_active_count = 0;
    g_pending_head = 0;
    g_pending_tail = 0;

    g_dht_running = 1;
    if (pthread_create(&g_dht_thread, NULL, dht_thread_fn, NULL) != 0) {
        g_dht_running = 0;
        return -1;
    }
    return 0;
}

void dht_client_add_chat(const char *user_key_hex)
{
    if (!user_key_hex || !g_dht_running) return;

    pthread_mutex_lock(&g_queue_mutex);

    /* Dedup in queue: scan existing pending entries */
    int head = g_pending_head;
    while (head != g_pending_tail) {
        if (strncmp(g_pending[head], user_key_hex, 32) == 0) {
            pthread_mutex_unlock(&g_queue_mutex);
            return;
        }
        head = (head + 1) % QUEUE_SIZE;
    }

    int next = (g_pending_tail + 1) % QUEUE_SIZE;
    if (next != g_pending_head) { /* not full */
        strncpy(g_pending[g_pending_tail], user_key_hex, 32);
        g_pending[g_pending_tail][32] = '\0';
        g_pending_tail = next;
    }

    pthread_mutex_unlock(&g_queue_mutex);
}

void dht_client_stop(void)
{
    if (!g_dht_running) return;
    g_dht_running = 0;
    pthread_join(g_dht_thread, NULL);
}
