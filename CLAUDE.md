# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`d-comms` is a pure C99 static library (`libdcomms_core.a`) implementing an encrypted, decentralized messaging protocol with automatic peer discovery on both LAN and the public internet.

## Build

```sh
cmake -S . -B build
cmake --build build
# Produces: build/libdcomms_core.a
# jech/dht is fetched automatically via FetchContent on first configure
```

Tests are built alongside the library:

```sh
cmake --build build
ctest --test-dir build   # runs test_crypto, test_proto, test_sync
```

## Tests

All three suites pass with `ctest --test-dir build`.

| Suite | File | What it covers |
|-------|------|----------------|
| `crypto` | `tests/test_crypto.c` | SHA-256 (empty, two-block NIST B.2, incremental vs one-shot), HMAC-SHA256 (RFC 4231 TC1 & TC2), AES-256 block encrypt/decrypt (NIST FIPS 197 C.3), AES-CBC round-trips (short / exact-block / multi-block), corrupt-padding and wrong-key rejection |
| `proto` | `tests/test_proto.c` | `proto_initialize` / `proto_join` credential format, FID written on init, send appends DB lines, list returns correct text and sender flags, uninitialised-chat guards, full two-party and three-turn exchanges, entity_id consistency, two responders in same group, cache invalidation, `proto_save_chat` / `proto_load_chat` round-trip |
| `sync` | `tests/test_sync.c` | `sync_start_server` binds a valid port, `sync_register` / `sync_unregister` write and remove `host:port` in `registry.db`, fork-based pull test verifies a child process can receive messages from a parent server |

### Test design notes

- Proto and sync tests `chdir` into a fresh `mkdtemp` directory so `messages.db` and `registry.db` are isolated per test. The original CWD is restored in every teardown.
- The sync fork test uses `sync_add_peer("127.0.0.1", port)` in the child to bootstrap peer discovery (the child has an empty `registry.db`; multicast is not relied upon in tests).
- `sync_unregister` resets `g_disc_started = 0` after joining the discovery thread so that successive register/unregister cycles within the same process (as happen in sequential tests) do not double-join the thread.
- The crypto expected values are verified against Python `hashlib` and OpenSSL. The wrong-key AES test allows either NULL (padding check fails) or a result that differs from the plaintext, because PKCS#7 padding can occasionally appear valid with a random key.

## Architecture

### Protocol model (`src/proto.c`, `src/proto.h`)

Messages are stored in a flat-file database (`messages.db`, located in the process CWD). Each line has the format:

```
<32-hex-prefix>.<hex(IV || ciphertext || HMAC)>
```

The protocol uses a **linked-chain** structure to order messages without timestamps:

- **Initiator** creates a shared `user_key` + `secret_id`. `SHA256(secret_id)` becomes the first prefix.
- Each "group" of messages written under a prefix also contains an encrypted **FID** (forward ID): a random 16-byte value whose hash becomes the *next* prefix. This is how the chain advances.
- The chain alternates between two **sides**: even-numbered groups (0, 2, 4…) belong to the initiator side, odd-numbered groups to the responder side.
- **Message ordering within a group** is deterministic: entries are sorted by their encrypted hex string (random AES IV, not sender-controlled), so all clients agree on order without a clock.
- **FID collision**: when multiple participants on the same side each write a FID, only the smallest encrypted hex value wins during the chain walk; the rest are discarded. This resolves races deterministically.

`do_chain_walk()` replays the entire chain from `initial_prefix` to reconstruct the message list and update the send/listen prefix state. It caches results and skips the walk if `messages.db` hasn't changed (`mtime` + `size` check).

**Important:** `hash_prefix()` hashes the **hex-string representation** of its input (e.g. the 32-character ASCII string `"deadbeef…"`), not the decoded raw bytes. This applies to both the `initial_prefix` derivation (`SHA256(secret_id_hex_string)`) and the chain-advance step (`SHA256(fid_hex_string)`). Any compatible reimplementation must hash the hex string.

Each message is encrypted as `entity_id(16 hex chars) + '\n' + text`. The `entity_id` is a randomly-generated 8-byte value assigned per participant on init/join.

Keys are derived from `user_key` via SHA256: `AES key = SHA256(user_key)`, `HMAC key = SHA256("hmac:" + user_key)`. Encryption is AES-256-CBC with a random IV prepended; authentication is HMAC-SHA256 appended after the ciphertext.

Chat state (keys, role, entity_id) is persisted as `<basedir>/chats/<name>.chat` in `key=value` format.

### Sync and discovery (`src/sync.c`, `src/sync.h`)

`sync_start_server()` opens a TCP listener on all interfaces (random port, uses `SO_REUSEPORT` so hole-punch sockets can bind to the same port). Returns the port number.

`sync_register(port)`:
1. **UPnP** — if `DCOMMS_HOST` is not already set, tries UPnP IGD discovery (implemented in `upnp.c`). On success, sets `DCOMMS_HOST` to the router's external IP and maps the TCP port. This makes the sync server reachable from the internet through most home routers.
2. Reads `DCOMMS_HOST` (or defaults to `127.0.0.1`) and records `host:port` in `registry.db`.
3. Starts the **multicast discovery thread** (UDP, group `239.255.77.77:55777`, TTL=1). The thread announces our `host:port` every 5 s and adds any unknown peers it hears to `registry.db`.

`sync_with_peers()` reads `registry.db`, connects to each peer via TCP, pulls their `messages.db` and `registry.db`, and appends any unseen lines. The server side streams both files separated by `---REGISTRY---`.

`connect_to_peer()` first tries a normal TCP connect (1 s timeout). On failure it falls back to **TCP hole punching**: binds a new socket to the local sync port with `SO_REUSEPORT`, then does a non-blocking connect. Both sides do this on each `sync_with_peers` cycle; eventually the outgoing SYNs overlap and a simultaneous open succeeds.

`sync_unregister()` removes our entry from `registry.db`, calls `upnp_cleanup` to delete the port mapping, shuts down the server socket, and joins the discovery thread.

`sync_add_peer(host, port)` is thread-safe (uses `flock`); it is called from the DHT callback thread and the multicast thread.

### DHT peer discovery (`src/dht_client.c`, `src/dht_client.h`)

One background thread drives a Mainline DHT node (jech/dht, MIT, fetched via CMake FetchContent).

- **Infohash derivation**: `SHA256(user_key_hex)[0..19]` — both peers derive the same value from the shared credential without exposing key material.
- **Bootstrap**: `dht_ping_node` for `router.bittorrent.com`, `router.utorrent.com`, `dht.transmissionbt.com`. First search delayed 30 s.
- **Event loop**: `select`-driven, capped at 1 s per iteration to stay responsive to `dht_client_stop`.
- **Announce + search**: `dht_search(infohash, sync_port, AF_INET, ...)` every 180 s per active chat. This both announces our `sync_port` and searches for other peers.
- **Callback**: on `DHT_EVENT_VALUES`, unpacks 6-byte `(IPv4, port)` entries and calls `sync_add_peer`.
- **Node identity**: loaded from `<basedir>/nodeid.db` (20 binary bytes, generated from `/dev/urandom` and persisted on first run).
- **Queue**: `g_pending[64]` ring buffer protected by `pthread_mutex_t`. `dht_client_add_chat` enqueues user_key_hex strings from any thread; the DHT thread drains the queue each iteration.

jech/dht requires three user-provided functions (`dht_blacklisted`, `dht_hash`, `dht_random_bytes`, `dht_sendto`) — all implemented in `dht_client.c`. `dht_hash` routes through `sha256_ctx` (no extra dependency).

**Important**: `dht.h` does not include its own prerequisites (`<stddef.h>`, `<stdio.h>`, `<time.h>`, socket headers). All system headers must be included before `#include "dht.h"` in any file that uses it.

### UPnP client (`src/upnp.c`, `src/upnp.h`)

Self-contained UPnP IGD client, no external library. Called from `sync_register` / `sync_unregister`.

1. **SSDP M-SEARCH** (UDP multicast to `239.255.255.250:1900`) — finds router, extracts `LOCATION` URL.
2. **HTTP GET** LOCATION — fetches device description XML, finds `WANIPConnection` or `WANPPPConnection` `controlURL`.
3. **SOAP `GetExternalIPAddress`** — retrieves the router's public IP.
4. **SOAP `AddPortMapping`** — maps `external_port:port → internal_ip:port` for TCP, 3600 s lease.
5. **SOAP `DeletePortMapping`** — called from `upnp_cleanup` on shutdown.

Uses HTTP/1.0 with `Connection: close` to avoid dealing with chunked encoding. XML is parsed with simple string search (UPnP XML format is standardised and predictable).

### Crypto primitives (`src/aes.c`, `src/sha256.c`)

Self-contained C implementations of AES-256-CBC (PKCS#7 padding) and SHA-256 (also used for HMAC). No external crypto library dependency.

## Thread safety contract

- `proto_db_rdlock()` / `proto_db_wrlock()` / `proto_db_unlock()` guard all `messages.db` access across threads within one process.
- `flock(LOCK_EX/SH)` guards cross-process access to `messages.db` and `registry.db`.
- `proto_list()` acquires the read lock internally; callers must not hold it when calling `proto_send()`.
- **`proto_chat` structs are not internally thread-safe.** The DB lock protects the file; it does not protect the `proto_chat` fields (`cache_valid`, `send_prefix`, `msgs`, etc.). Concurrent calls on the same `proto_chat` instance from different threads are a data race. Callers are responsible for per-chat serialization.
- `sync_add_peer()` uses `flock` internally and is safe to call from any thread (DHT callback thread, multicast thread, or application thread).
- All `dht_*` library calls happen exclusively on `g_dht_thread`; `dht_client_add_chat` communicates via a mutex-protected ring buffer.

## File layout

| File | Location | Description |
|------|----------|-------------|
| `messages.db` | process CWD | Append-only encrypted message store |
| `registry.db` | process CWD | Peer registry — `host:port` per line |
| `<basedir>/nodeid.db` | basedir arg to `dht_client_start` | 20-byte DHT node identity (binary) |
| `<basedir>/chats/<name>.chat` | basedir arg to `proto_save_chat` | Saved chat credentials (mode 0600) |
