#ifndef SYNC_H
#define SYNC_H

/* Start background TCP sync server. Returns listening port, or -1 on error. */
int sync_start_server(void);

/* Register this client (pid:port) in ~/dcomms-registry.db, cleaning stale entries. */
void sync_register(int port);

/* Remove this client from the registry and close the server socket. */
void sync_unregister(void);

/* Pull messages.db from all registered peers, merge new lines. Returns count added. */
int sync_with_peers(void);

#endif
