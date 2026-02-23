#include "compat.h"

#include <pthread.h>

#include "sync.h"
#include "upnp.h"
#include "proto.h"

#define DB_FILE            "messages.db"
#define REGISTRY_FILE      "registry.db"
#define REGISTRY_SEP       "---REGISTRY---"
#define MAX_LINE           8192
#define SYNC_TIMEOUT       1  /* seconds */

/* Multicast group used for peer discovery.  All instances join this group and
   announce their host:port periodically; listeners add unknown peers to their
   local registry automatically.  TTL=1 keeps traffic link-local (LAN only).
   For internet peers beyond the LAN, use sync_add_peer() once; gossip then
   propagates them further. */
#define DISCOVERY_GROUP    "239.255.77.77"
#define DISCOVERY_PORT     55777
#define DISCOVERY_TTL      1
#define DISCOVERY_INTERVAL 5  /* seconds between announcements */

static dcomms_socket_t g_server_fd = DCOMMS_INVALID_SOCKET;
static pthread_t g_server_tid;
static volatile int g_server_quit;
static char g_my_host[64];
static int  g_my_port;
static int  g_local_port;  /* actual bound TCP port, used for hole punching */

static pthread_t g_disc_tid;
static int       g_disc_started = 0;

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

/* ---- connect helper ---- */

static int connect_to_peer_hp(const char *host, int port); /* forward decl */

/* Open a TCP connection to host:port. Returns fd on success, -1 on failure. */
static int connect_to_peer(const char *host, int port)
{
    char service[16];
    snprintf(service, sizeof(service), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res;
    if (getaddrinfo(host, service, &hints, &res) != 0)
        return -1;

    int sfd = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd < 0) continue;

        dcomms_set_socktimeo(sfd, SO_RCVTIMEO, SYNC_TIMEOUT);
        dcomms_set_socktimeo(sfd, SO_SNDTIMEO, SYNC_TIMEOUT);

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        sock_close(sfd);
        sfd = -1;
    }
    freeaddrinfo(res);

    if (sfd >= 0) return sfd;

    /* Normal connect failed — try TCP hole punching */
    return connect_to_peer_hp(host, port);
}

/* TCP hole-punch fallback: bind our socket to the local sync port (SO_REUSEPORT)
   before connecting, so the outgoing SYN punches a hole in our own NAT and,
   if both sides attempt this simultaneously, allows a simultaneous TCP open.
   Returns fd on success, -1 on failure. */
static int connect_to_peer_hp(const char *host, int port)
{
    if (g_local_port <= 0) return -1;

    char service[16];
    snprintf(service, sizeof(service), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res;
    if (getaddrinfo(host, service, &hints, &res) != 0) return -1;

    int sfd = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd < 0) continue;

        int opt = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, SOCKOPT_VAL(&opt), sizeof(opt));
#ifdef SO_REUSEPORT
        setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, SOCKOPT_VAL(&opt), sizeof(opt));
#endif

        /* Bind to our server port so our SYN's source port is predictable */
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port        = htons((uint16_t)g_local_port);
        if (bind(sfd, (struct sockaddr *)&local, sizeof(local)) < 0) {
            sock_close(sfd); sfd = -1; continue;
        }

        /* Non-blocking connect so we can wait with select */
        dcomms_set_nonblocking(sfd, 1);

        int rc = connect(sfd, rp->ai_addr, rp->ai_addrlen);
        if (rc == 0) {
            /* Immediate success (e.g. loopback) */
            dcomms_set_blocking(sfd);
            break;
        }
        if (SOCK_ERRNO != SOCK_EINPROGRESS) {
            sock_close(sfd); sfd = -1; continue;
        }

        /* Wait up to 1 s for the connection to complete */
        fd_set wfds, efds;
        FD_ZERO(&wfds); FD_ZERO(&efds);
        FD_SET(sfd, &wfds); FD_SET(sfd, &efds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        if (select(sfd + 1, NULL, &wfds, &efds, &tv) > 0
                && FD_ISSET(sfd, &wfds) && !FD_ISSET(sfd, &efds)) {
            int err = 0;
            socklen_t elen = sizeof(err);
            getsockopt(sfd, SOL_SOCKET, SO_ERROR, SOCKOPT_OUTVAL(&err), &elen);
            if (err == 0) {
                dcomms_set_blocking(sfd);
                break;
            }
        }
        sock_close(sfd); sfd = -1;
    }
    freeaddrinfo(res);
    return sfd;
}

/* ---- multicast discovery thread ---- */

/* Announces our host:port on the multicast group and adds any unknown peers
   that announce themselves.  Runs for the lifetime of the process. */
static void *discovery_thread(void *arg)
{
    (void)arg;

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd < 0) return NULL;

    /* Allow multiple instances on the same machine to share the port */
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, SOCKOPT_VAL(&opt), sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, SOCKOPT_VAL(&opt), sizeof(opt));
#endif

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port        = htons(DISCOVERY_PORT);
    if (bind(sfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        sock_close(sfd);
        return NULL;
    }

    /* Join the multicast group (receive announcements) */
    struct ip_mreq mreq;
    inet_pton(AF_INET, DISCOVERY_GROUP, &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(sfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, SOCKOPT_VAL(&mreq), sizeof(mreq));

    /* Outgoing multicast: link-local TTL, loop back to self so same-machine
       instances see each other's announcements */
    unsigned char ttl  = DISCOVERY_TTL;
    unsigned char loop = 1;
    setsockopt(sfd, IPPROTO_IP, IP_MULTICAST_TTL,  SOCKOPT_VAL(&ttl),  sizeof(ttl));
    setsockopt(sfd, IPPROTO_IP, IP_MULTICAST_LOOP, SOCKOPT_VAL(&loop), sizeof(loop));

    struct sockaddr_in mcast_addr;
    memset(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    inet_pton(AF_INET, DISCOVERY_GROUP, &mcast_addr.sin_addr);
    mcast_addr.sin_port = htons(DISCOVERY_PORT);

    char announce[128];
    snprintf(announce, sizeof(announce), "dcomms %s:%d", g_my_host, g_my_port);
    size_t ann_len = strlen(announce);

    time_t last_announce = 0;

    while (!g_server_quit) {
        /* Announce ourselves periodically */
        time_t now = time(NULL);
        if (now - last_announce >= DISCOVERY_INTERVAL) {
            sendto(sfd, announce, ann_len, 0,
                   (struct sockaddr *)&mcast_addr, sizeof(mcast_addr));
            last_announce = now;
        }

        /* Wait up to 1 s for an incoming announcement */
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sfd, &rfds);
        if (select(sfd + 1, &rfds, NULL, NULL, &tv) <= 0)
            continue;

        char buf[128];
        ssize_t n = recvfrom(sfd, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if (n <= 0) continue;
        buf[n] = '\0';

        char host[64]; int port;
        if (sscanf(buf, "dcomms %63[^:]:%d", host, &port) == 2 &&
            !(strcmp(host, g_my_host) == 0 && port == g_my_port)) {
            sync_add_peer(host, port);
        }
    }

    setsockopt(sfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, SOCKOPT_VAL(&mreq), sizeof(mreq));
    sock_close(sfd);
    return NULL;
}

/* ---- TCP sync server ---- */

static void send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = sock_send(fd, buf + sent, len - sent);
        if (n <= 0) return;
        sent += (size_t)n;
    }
}

static void *server_thread(void *arg)
{
    (void)arg;
    static const char k_sep[] = REGISTRY_SEP "\n";

    while (!g_server_quit) {
        struct sockaddr_in ca;
        socklen_t ca_len = sizeof(ca);
        int cfd = accept(g_server_fd, (struct sockaddr *)&ca, &ca_len);
        if (cfd < 0) break;

        dcomms_set_socktimeo(cfd, SO_SNDTIMEO, 2);

        /* Send messages.db */
        proto_db_rdlock();
        FILE *db = fopen(DB_FILE, "r");
        if (db) {
            dcomms_flock(fileno(db), LOCK_SH);
            char line[MAX_LINE];
            while (fgets(line, sizeof(line), db))
                send_all(cfd, line, strlen(line));
            dcomms_flock(fileno(db), LOCK_UN);
            fclose(db);
        }
        proto_db_unlock();

        /* Separator between messages and registry sections */
        send_all(cfd, k_sep, sizeof(k_sep) - 1);

        /* Gossip all known registry entries to the connecting peer */
        FILE *rf = fopen(REGISTRY_FILE, "r");
        if (rf) {
            dcomms_flock(fileno(rf), LOCK_SH);
            char line[128];
            while (fgets(line, sizeof(line), rf)) {
                char h[64]; int port;
                if (sscanf(line, "%63[^:]:%d", h, &port) == 2)
                    send_all(cfd, line, strlen(line));
            }
            dcomms_flock(fileno(rf), LOCK_UN);
            fclose(rf);
        }

        sock_close(cfd);
    }
    return NULL;
}

int sync_start_server(void)
{
    g_server_quit = 0;

    dcomms_wsa_init();

    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_fd == DCOMMS_INVALID_SOCKET) return -1;

    int opt = 1;
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEADDR, SOCKOPT_VAL(&opt), sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(g_server_fd, SOL_SOCKET, SO_REUSEPORT, SOCKOPT_VAL(&opt), sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = 0;

    if (bind(g_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        sock_close(g_server_fd);
        g_server_fd = DCOMMS_INVALID_SOCKET;
        return -1;
    }

    socklen_t alen = sizeof(addr);
    getsockname(g_server_fd, (struct sockaddr *)&addr, &alen);
    g_local_port = (int)ntohs(addr.sin_port);

    if (listen(g_server_fd, 4) < 0) {
        sock_close(g_server_fd);
        g_server_fd = DCOMMS_INVALID_SOCKET;
        return -1;
    }

    if (pthread_create(&g_server_tid, NULL, server_thread, NULL) != 0) {
        sock_close(g_server_fd);
        g_server_fd = DCOMMS_INVALID_SOCKET;
        return -1;
    }

    return ntohs(addr.sin_port);
}

/* ---- registry (host:port format, atomic read-modify-write with LOCK_EX) ---- */

void sync_register(int port)
{
    /* Try UPnP to get external IP and open a port mapping, but only when
       DCOMMS_HOST has not been set explicitly by the caller/environment. */
    const char *env_host = getenv("DCOMMS_HOST");
    if (!env_host || env_host[0] == '\0') {
        char ext_ip[64] = {0};
        if (upnp_setup(port, ext_ip, sizeof(ext_ip)) == 0)
            setenv("DCOMMS_HOST", ext_ip, 1);
        else if (upnp_http_get_external_ip(ext_ip, sizeof(ext_ip)) == 0)
            setenv("DCOMMS_HOST", ext_ip, 1);
    }

    env_host = getenv("DCOMMS_HOST");
    const char *host = (env_host && env_host[0]) ? env_host : "127.0.0.1";
    strncpy(g_my_host, host, sizeof(g_my_host) - 1);
    g_my_host[sizeof(g_my_host) - 1] = '\0';
    g_my_port = port;

    FILE *f = fopen(REGISTRY_FILE, "a+");
    if (!f) return;
    dcomms_flock(fileno(f), LOCK_EX);
    rewind(f);

    /* Keep existing entries, dropping any stale duplicate of our own address */
    char keep[64][128];
    int count = 0;
    char line[128];
    while (fgets(line, sizeof(line), f) && count < 63) {
        char h[64]; int p;
        if (sscanf(line, "%63[^:]:%d", h, &p) == 2) {
            if (strcmp(h, g_my_host) == 0 && p == g_my_port) continue;
            strncpy(keep[count], line, sizeof(keep[0]) - 1);
            keep[count][sizeof(keep[0]) - 1] = '\0';
            count++;
        }
    }

    if (ftruncate(fileno(f), 0) != 0) {
        dcomms_flock(fileno(f), LOCK_UN);
        fclose(f);
        return;
    }
    rewind(f);
    for (int i = 0; i < count; i++)
        fputs(keep[i], f);
    fprintf(f, "%s:%d\n", g_my_host, g_my_port);
    fflush(f);

    dcomms_flock(fileno(f), LOCK_UN);
    fclose(f);

    /* Start the discovery thread now that g_my_host/g_my_port are set */
    if (!g_disc_started) {
        g_disc_started = 1;
        pthread_create(&g_disc_tid, NULL, discovery_thread, NULL);
    }
}

void sync_unregister(void)
{
    upnp_cleanup(g_my_port);

    FILE *f = fopen(REGISTRY_FILE, "r+");
    if (!f) goto shutdown_server;
    dcomms_flock(fileno(f), LOCK_EX);

    char keep[64][128];
    int count = 0;
    char line[128];
    while (fgets(line, sizeof(line), f) && count < 64) {
        char h[64]; int p;
        if (sscanf(line, "%63[^:]:%d", h, &p) == 2) {
            if (strcmp(h, g_my_host) == 0 && p == g_my_port) continue;
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

    dcomms_flock(fileno(f), LOCK_UN);
    fclose(f);

shutdown_server:
    g_server_quit = 1;
    if (g_server_fd != DCOMMS_INVALID_SOCKET) {
        shutdown(g_server_fd, SHUT_RDWR);
        sock_close(g_server_fd);
        g_server_fd = DCOMMS_INVALID_SOCKET;
    }
    pthread_join(g_server_tid, NULL);
    if (g_disc_started) {
        pthread_join(g_disc_tid, NULL);
        g_disc_started = 0;
    }
    dcomms_wsa_cleanup();
}

void sync_add_peer(const char *host, int port)
{
    FILE *f = fopen(REGISTRY_FILE, "a+");
    if (!f) return;
    dcomms_flock(fileno(f), LOCK_EX);
    rewind(f);

    /* Skip if already present */
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char h[64]; int p;
        if (sscanf(line, "%63[^:]:%d", h, &p) == 2 &&
            strcmp(h, host) == 0 && p == port) {
            dcomms_flock(fileno(f), LOCK_UN);
            fclose(f);
            return;
        }
    }

    fseek(f, 0, SEEK_END);
    fprintf(f, "%s:%d\n", host, port);
    fflush(f);

    dcomms_flock(fileno(f), LOCK_UN);
    fclose(f);
}

/* ---- sync client ---- */

int sync_with_peers(void)
{
    /* Collect peers from local registry */
    struct { char host[64]; int port; } peers[64];
    int peer_count = 0;

    FILE *rf = fopen(REGISTRY_FILE, "r");
    if (rf) {
        dcomms_flock(fileno(rf), LOCK_SH);
        char line[128];
        while (fgets(line, sizeof(line), rf) && peer_count < 64) {
            char h[64]; int port;
            if (sscanf(line, "%63[^:]:%d", h, &port) == 2 &&
                !(strcmp(h, g_my_host) == 0 && port == g_my_port)) {
                strncpy(peers[peer_count].host, h, sizeof(peers[0].host) - 1);
                peers[peer_count].host[sizeof(peers[0].host) - 1] = '\0';
                peers[peer_count].port = port;
                peer_count++;
            }
        }
        dcomms_flock(fileno(rf), LOCK_UN);
        fclose(rf);
    }

    if (peer_count == 0) return 0;

    /* Build hash set of local message lines */
    hash_set msg_hs;
    hs_init(&msg_hs);

    proto_db_rdlock();
    FILE *lf = fopen(DB_FILE, "r");
    if (lf) {
        dcomms_flock(fileno(lf), LOCK_SH);
        char lline[MAX_LINE];
        while (fgets(lline, sizeof(lline), lf)) {
            int len = (int)strlen(lline);
            if (len > 0 && lline[len - 1] == '\n') lline[--len] = '\0';
            if (len > 0) hs_add(&msg_hs, lline);
        }
        dcomms_flock(fileno(lf), LOCK_UN);
        fclose(lf);
    }
    proto_db_unlock();

    /* Build hash set of local registry entries to detect duplicates */
    hash_set reg_hs;
    hs_init(&reg_hs);
    {
        FILE *rrf = fopen(REGISTRY_FILE, "r");
        if (rrf) {
            dcomms_flock(fileno(rrf), LOCK_SH);
            char line[128];
            while (fgets(line, sizeof(line), rrf)) {
                int len = (int)strlen(line);
                if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
                if (len > 0) hs_add(&reg_hs, line);
            }
            dcomms_flock(fileno(rrf), LOCK_UN);
            fclose(rrf);
        }
    }

    int added = 0;

    for (int p = 0; p < peer_count; p++) {
        int sfd = connect_to_peer(peers[p].host, peers[p].port);
        if (sfd < 0) continue;

        FILE *sf = fdopen(sfd, "r");
        if (!sf) { sock_close(sfd); continue; }

        /* Collect new message lines and registry entries from this peer */
        int msg_cap = 256;
        char **msg_batch = malloc(sizeof(char *) * (size_t)msg_cap);
        int msg_count = 0;

        int reg_cap = 64;
        char **reg_batch = malloc(sizeof(char *) * (size_t)reg_cap);
        int reg_count = 0;

        int in_registry = 0;
        char rline[MAX_LINE];

        while (msg_batch && reg_batch && fgets(rline, sizeof(rline), sf)) {
            int len = (int)strlen(rline);
            if (len > 0 && rline[len - 1] == '\n') rline[--len] = '\0';
            if (len == 0) continue;

            if (strcmp(rline, REGISTRY_SEP) == 0) {
                in_registry = 1;
                continue;
            }

            if (!in_registry) {
                /* Message line */
                if (!hs_contains(&msg_hs, rline)) {
                    if (msg_count >= msg_cap) {
                        msg_cap *= 2;
                        char **tmp = realloc(msg_batch, sizeof(char *) * (size_t)msg_cap);
                        if (!tmp) break;
                        msg_batch = tmp;
                    }
                    msg_batch[msg_count++] = strdup(rline);
                    hs_add(&msg_hs, rline);
                }
            } else {
                /* Registry entry gossiped from peer: add if unknown and not ourselves */
                char h[64]; int port;
                if (sscanf(rline, "%63[^:]:%d", h, &port) == 2 &&
                    !(strcmp(h, g_my_host) == 0 && port == g_my_port) &&
                    !hs_contains(&reg_hs, rline) &&
                    reg_count < reg_cap) {
                    reg_batch[reg_count++] = strdup(rline);
                    hs_add(&reg_hs, rline);
                }
            }
        }
        fclose(sf);

        /* Batch write new message lines */
        if (msg_count > 0) {
            proto_db_wrlock();
            FILE *db = fopen(DB_FILE, "a");
            if (db) {
                dcomms_flock(fileno(db), LOCK_EX);
                for (int i = 0; i < msg_count; i++)
                    fprintf(db, "%s\n", msg_batch[i]);
                fflush(db);
                dcomms_flock(fileno(db), LOCK_UN);
                fclose(db);
            }
            proto_db_unlock();
        }
        for (int i = 0; i < msg_count; i++) free(msg_batch[i]);
        free(msg_batch);
        added += msg_count;

        /* Append newly discovered peer registry entries */
        if (reg_count > 0) {
            FILE *rw = fopen(REGISTRY_FILE, "a");
            if (rw) {
                dcomms_flock(fileno(rw), LOCK_EX);
                for (int i = 0; i < reg_count; i++)
                    fprintf(rw, "%s\n", reg_batch[i]);
                fflush(rw);
                dcomms_flock(fileno(rw), LOCK_UN);
                fclose(rw);
            }
        }
        for (int i = 0; i < reg_count; i++) free(reg_batch[i]);
        free(reg_batch);
    }

    hs_free(&msg_hs);
    hs_free(&reg_hs);
    return added;
}
