#ifndef SYNC_H
#define SYNC_H

#ifdef __cplusplus
extern "C" {
#endif

/* Start background TCP sync server on all interfaces. Returns listening port, or -1 on error. */
int sync_start_server(void);

/* Register this client (host:port) in registry.db and start the multicast
   discovery thread.  host defaults to "127.0.0.1" or DCOMMS_HOST env var.
   Discovery group 239.255.77.77:55777 — peers on the same LAN are found
   automatically within DISCOVERY_INTERVAL seconds. */
void sync_register(int port);

/* Remove this client from the registry and close the server socket. */
void sync_unregister(void);

/* Manually add a known peer (host:port) to registry.db for bootstrap.
   No-op if the entry is already present. */
void sync_add_peer(const char *host, int port);

/* Pull messages.db from all registered peers, merge new lines. Returns count added. */
int sync_with_peers(void);

#ifdef __cplusplus
}
#endif

#endif
