#ifndef DHT_CLIENT_H
#define DHT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Start the DHT client on the given sync_port.
   basedir is used to persist the node ID (nodeid.db).
   Returns 0 on success, -1 on error. */
int  dht_client_start(int sync_port, const char *basedir);

/* Announce and search for a chat identified by its user_key_hex (32 hex chars).
   Thread-safe; can be called from any thread at any time. */
void dht_client_add_chat(const char *user_key_hex);

/* Stop the DHT client and join the background thread. */
void dht_client_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* DHT_CLIENT_H */
