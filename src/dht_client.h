#ifndef DHT_CLIENT_H
#define DHT_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Start the DHT client on the given sync_port.
   basedir is used to persist the node ID (nodeid.db).
   Returns 0 on success, -1 on error. */
int  dht_client_start(int sync_port, const char *basedir);

/* Announce and search for a chat identified by its secret_id_hex (32 hex chars).
   secret_id is the canonical chat identifier: SHA256(secret_id_hex) is the
   first chain prefix, and its hash is used as the DHT infohash so both peers
   rendezvous on the chat's own identity rather than the encryption key.
   Thread-safe; can be called from any thread at any time. */
void dht_client_add_chat(const char *secret_id_hex);

/* Stop the DHT client and join the background thread. */
void dht_client_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* DHT_CLIENT_H */
