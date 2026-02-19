# d-comms

A minimal, encrypted, decentralized messaging library written in C99.
No server. No network daemon. Peers discover each other automatically — on the same LAN via multicast and across the internet via the BitTorrent Mainline DHT.

---

## Why d-comms

Most encrypted messaging systems solve the privacy problem by trusting a smaller set of servers. d-comms removes the server entirely.

### Purpose

d-comms is designed for situations where you want private communication without any infrastructure:

- **No account, no registration.** A chat session is created by exchanging two hex strings (32 chars each) through any channel you already trust — a QR code, a voice call, a shared note.
- **No server to run or trust.** Peers find each other directly: on the same LAN via multicast UDP, across the internet via the BitTorrent Mainline DHT network, and through NAT via UPnP or TCP hole punching.
- **Embeddable.** d-comms is a plain C99 static library with no runtime dependencies beyond pthreads. It links into any application — a TUI, a GUI, a daemon, or firmware.

### Advantages

**Over centralized messengers (Signal, WhatsApp, Telegram):**

| | Signal / WhatsApp | d-comms |
|---|---|---|
| Requires phone number | Yes | No |
| Requires account | Yes | No |
| Central server handles delivery | Yes | No — peers sync directly |
| Works without internet (LAN) | No | Yes — multicast discovery |
| Operator can correlate contacts | Yes (metadata) | No — DHT infohash reveals no key |
| Library you can embed | No | Yes |

**Over federated systems (Matrix, XMPP):**

- No homeserver to deploy, maintain, or trust.
- No DNS records, TLS certificates, or open ports required.
- Peers behind NAT are reached automatically — UPnP is tried first; TCP hole punching is the fallback.

**Over file-based or git-based messaging:**

- Content is encrypted at rest. Every line in `messages.db` is AES-256-CBC ciphertext authenticated with HMAC-SHA256. A filesystem-level attacker learns nothing.
- Message order is agreed upon deterministically by all readers without timestamps, a coordinator, or a consensus protocol.

**Over ad-hoc socket protocols:**

- Peers are discovered automatically. You do not need to know your peer's IP address in advance — the DHT finds them anywhere on the internet, using the shared secret as the only rendezvous point.
- Sync is pull-based and idempotent. Partial syncs, retries, and concurrent writers are all handled correctly.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [The Protocol](#the-protocol)
  - [Key Derivation](#key-derivation)
  - [The Chain Structure](#the-chain-structure)
  - [Message Format](#message-format)
  - [Turn System](#turn-system)
  - [Message Ordering](#message-ordering)
- [The Database](#the-database)
- [Peer Discovery and Sync](#peer-discovery-and-sync)
  - [LAN — Multicast](#lan--multicast)
  - [Internet — Mainline DHT](#internet--mainline-dht)
  - [NAT Traversal — UPnP and Hole Punching](#nat-traversal--upnp-and-hole-punching)
  - [Sync Protocol](#sync-protocol)
- [Security Model](#security-model)
- [Using the Library](#using-the-library)
  - [Build](#build)
  - [API Reference](#api-reference)
  - [Integration Example](#integration-example)
- [File Reference](#file-reference)
- [Limits and Constants](#limits-and-constants)

---

## Overview

d-comms implements an **encrypted, turn-based chat** on top of a plain append-only text file (`messages.db`). The entire "network" is that flat file — propagated across peers by a TCP sync layer that is fed peer addresses from two automatic discovery mechanisms.

The protocol organizes participants into two **turn groups**: Group A and Group B. Any number of clients can join either group — every client that calls `proto_initialize` is in Group A, and every client that calls `proto_join` with the same credentials is in Group B. Within a group, each client is identified by a unique random `entity_id`; their messages all appear in the same turn slot and are ordered deterministically.

**Key properties:**

- Encryption-at-rest: all content in `messages.db` is AES-256-CBC encrypted
- Authentication: every ciphertext is protected by HMAC-SHA256
- Anonymity: participants are identified only by random 8-byte entity IDs
- No central authority: the shared secret is exchanged out-of-band
- LAN discovery: multicast UDP (239.255.77.77:55777) finds peers on the same network automatically
- Internet discovery: Mainline DHT finds peers anywhere on the internet using the shared `user_key` as a rendezvous point — no server required
- NAT traversal: UPnP port mapping (attempted automatically) and TCP hole punching (fallback)
- Deterministic ordering: message order is agreed upon by all readers without timestamps

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │                       Application                        │
 │              (your code / TUI / GUI / CLI)               │
 └──────────────────┬───────────────────────────────────────┘
                    │  C API  (proto.h / sync.h / dht_client.h)
 ┌──────────────────▼───────────────────────────────────────┐
 │                     dcomms_core.a                        │
 │  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌───────┐  │
 │  │ proto.c  │  │  sync.c  │  │dht_client.c│  │upnp.c │  │
 │  │(protocol)│  │(TCP sync)│  │(DHT thread)│  │(UPnP) │  │
 │  └────┬─────┘  └────┬─────┘  └─────┬──────┘  └───────┘  │
 │       │             │              │                      │
 │  ┌────▼─────────────▼──────────────▼──────────────────┐  │
 │  │          aes.c / sha256.c  (crypto layer)          │  │
 │  └────────────────────────────────────────────────────┘  │
 └──────────────────────────────────────────────────────────┘
          │             │              │
          │ read/write  │ TCP          │ UDP (DHT)
          ▼             ▼              ▼
   ┌────────────┐  ┌──────────────┐  ┌──────────────────────┐
   │messages.db │  │ registry.db  │  │  Mainline DHT (UDP)  │
   │   (CWD)    │  │    (CWD)     │  │  239.255.77.77:55777 │
   └────────────┘  └──────────────┘  │  (LAN multicast)     │
                                     └──────────────────────┘
```

### Components

| Component | File(s) | Role |
|-----------|---------|------|
| Protocol layer | `proto.c`, `proto.h` | Chain walking, encryption, key derivation, DB read/write |
| Sync layer | `sync.c`, `sync.h` | TCP server, registry, LAN multicast discovery, peer merge, UPnP, hole punching |
| DHT client | `dht_client.c`, `dht_client.h` | Mainline DHT thread, peer announce/search, bootstrap |
| UPnP client | `upnp.c`, `upnp.h` | SSDP discovery, port mapping, external IP resolution |
| AES-256 | `aes.c`, `aes.h` | Block cipher, CBC mode, PKCS7 padding |
| SHA-256 / HMAC | `sha256.c`, `sha256.h` | Hashing and message authentication |

---

## The Protocol

### Key Derivation

A chat session requires two pieces of shared secret, generated by whoever sets it up (any client in Group A):

```
user_key  ──SHA256──►  aes_key  (32 bytes)   — encrypts all content
                ──SHA256("hmac:"||user_key)──►  hmac_key (32 bytes)  — authenticates
secret_id ──SHA256──►  initial_prefix (first 16 bytes → 32 hex chars)
```

```
 user_key (32 hex chars, 16 bytes random)
     │
     ├──► SHA256(user_key)          = aes_key  [32 bytes]
     └──► SHA256("hmac:" + user_key) = hmac_key [32 bytes]

 secret_id (32 hex chars, 16 bytes random)
     └──► SHA256(secret_id_hex_string)[0..15]  = initial_prefix [32 hex chars]
```

The `initial_prefix` is the entry point of the message chain. It is derived from `secret_id`, which is also shared out-of-band. Knowing only the prefix does not reveal either key.

---

### The Chain Structure

Messages are organized in a **linked chain of groups**. Each group is owned by one turn group (alternating: Group A, Group B, Group A, …). Any number of clients can write into a group while it is their turn.

```
 initial_prefix = SHA256(secret_id)[0..15]
       │
       ▼
 ┌─────────────────────────────────────────┐
 │  Group 0  (Group A clients write here)  │
 │  prefix = initial_prefix                │
 │                                         │
 │  DB entries with this prefix:           │
 │  ├── Enc(FID₀)              ← forward ID│
 │  ├── Enc(eid_c1 + msg_A)    ← client1  │
 │  └── Enc(eid_c2 + msg_B)    ← client2  │
 └──────────────────┬──────────────────────┘
                    │  SHA256(FID₀)[0..15]
                    ▼
 ┌─────────────────────────────────────────┐
 │  Group 1  (Group B clients write here)  │
 │  prefix = SHA256(FID₀)[0..15]           │
 │                                         │
 │  DB entries with this prefix:           │
 │  ├── Enc(FID₁)              ← forward ID│
 │  ├── Enc(eid_c3 + msg_C)    ← client3  │
 │  └── Enc(eid_c4 + msg_D)    ← client4  │
 └──────────────────┬──────────────────────┘
                    │  SHA256(FID₁)[0..15]
                    ▼
 ┌─────────────────────────────────────────┐
 │  Group 2  (Group A clients write here)  │
 │  …                                      │
 └─────────────────────────────────────────┘
```

Each group is linked to the next by the **Forward ID (FID)**:
- A FID is 16 random bytes (32 hex chars), generated fresh per group
- It is encrypted and stored in the current group's prefix bucket
- Its SHA256 hash forms the *next* group's prefix — **note:** SHA256 is applied to the 32-character lowercase hex string representation of the FID, not the raw 16 bytes
- Anyone who can decrypt the FID can follow the chain

A group with no FID is the **tail** — the chain ends there.

---

### Message Format

Every entry in `messages.db` is a single line:

```
<prefix>.<encrypted_hex>
```

Where:
- `prefix` = 32 lowercase hex chars (= first 16 bytes of SHA256 of some secret)
- `encrypted_hex` = hex-encoded binary blob structured as:

```
 encrypted_hex = hex( IV(16) || AES-CBC-ciphertext || HMAC-SHA256(IV||ciphertext)(32) )
```

After decryption, the plaintext is one of:

**Forward ID (FID):**
```
 <32 hex chars>           — exactly 32 lowercase hex chars, no newline inside
```

**Message:**
```
 <entity_id(16 hex)>\n<user message text>
```

The entity ID is a random 8-byte identifier generated locally per chat session. It never changes for the same `proto_chat` instance and is used to color-code senders consistently across all participants.

---

### Turn System

The protocol enforces **alternating turns** between the two groups. All members of a group may write during their group's turn:

```
  Group 0    Group 1    Group 2    Group 3    Group 4   …
  ───────    ───────    ───────    ───────    ───────
  Group A    Group B    Group A    Group B    Group A
 (client1,  (client3,  (client1,  (client3,  (client1,
  client2…)  client4…)  client2…)  client4…)  client2…)
```

#### Why alternation is necessary

The FID written into each group is what creates the next group's prefix — it is the only way the chain can advance. This means whoever writes the FID for a given prefix slot decides where the chain goes next.

Without alternation, both groups could write FIDs into the same prefix slot concurrently. The tiebreaker (smallest encrypted hex wins) can resolve a race between multiple members *within* the same group writing a FID, because all of them are on the same side and the winner is still that group's FID. But if members from *different* groups both write FIDs into the same slot, the tiebreaker has no way to determine which group should own the next prefix — the chain's ownership sequence would become ambiguous and diverge across readers.

Alternation solves this structurally: each prefix slot is exclusively owned by one turn group (even-numbered slots belong to Group A, odd-numbered to Group B). Only the owning group writes the FID that advances the chain out of their slot. The other group can only listen on that prefix, waiting for the FID to appear. Because of this, every reader independently agrees on which group owns every group number, without any coordination beyond the shared secret.

#### State machine

```
  state = 0 (uninit)
      │
      ├──► proto_initialize() ──► state = 1 (can_send)   [Group A client]
      └──► proto_join()       ──► state = 2 (need_list)  [Group B client, waits for chain]

  state = 2 ──► proto_list() walks chain ──► state = 1 if Group B's turn found
                                         ──► state = 2 if not yet (no FID seen)
```

A client in state `2` cannot send until it has walked the chain and confirmed its turn has started. Within a group, multiple members may race to write the FID; the protocol picks the **lexicographically smallest encrypted hex string** as the canonical FID, so all readers agree on the same winner.

---

### Message Ordering

Within a single group, multiple messages may be written concurrently by the owning party. The order is determined by sorting on the **encrypted hex string** of each message — a value controlled by the random AES IV, not the sender's wall clock:

```
 Messages in group N, sorted by encrypted_hex:

   Enc(eid + "hello")  = "0a3f..."  ← appears first (smallest)
   Enc(eid + "world")  = "4bc1..."  ← appears second
   Enc(eid + "!")      = "f201..."  ← appears last
```

Since the IV is sampled from `/dev/urandom` at write time, no sender can influence their position in the list. All readers compute the same order.

---

## The Database

`messages.db` lives in the **current working directory** of the process. It is a plain text file, append-only, with one record per line.

```
 messages.db
 ─────────────────────────────────────────────────────────────────────
 a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6.4f2a...9b1c    ← FID in group 0
 a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6.c8d3...7e02    ← message in group 0
 71ab3cd9f8e1204567890abcdef12345.9f4a...21bb    ← FID in group 1
 71ab3cd9f8e1204567890abcdef12345.0011...ffee    ← message in group 1
 …
```

**Locking:** writes use `pthread_rwlock_t` (intra-process) combined with `flock(LOCK_EX/LOCK_SH)` (inter-process). Readers take shared locks; writers take exclusive locks.

**Merging:** the sync layer only appends lines not already present (deduplication via hash set). The file grows monotonically — no compaction or deletion.

---

## Peer Discovery and Sync

Two independent mechanisms feed peer addresses into the same registry (`registry.db`) and TCP sync layer.

### LAN — Multicast

`sync_register` starts a background thread that periodically sends a UDP datagram to the multicast group `239.255.77.77:55777` (TTL=1, link-local). Any other instance on the same subnet that receives this announcement adds the sender's `host:port` to its registry immediately. Peers on the same machine also see each other's announcements via multicast loopback.

### Internet — Mainline DHT

`dht_client_start` launches a background thread that:

1. Creates a UDP socket and initialises a Mainline DHT node (using **jech/dht**, the same library used by Transmission and qBittorrent).
2. Bootstraps by pinging `router.bittorrent.com`, `router.utorrent.com`, and `dht.transmissionbt.com`.
3. Waits 30 seconds for the routing table to populate.
4. For each chat added via `dht_client_add_chat(user_key_hex)`, derives a 20-byte **infohash** as `SHA256(user_key_hex)[0..19]` — the same value on both sides because they share `user_key` — and calls `dht_search` with the local sync port.
5. Re-runs each search every 180 seconds.
6. On `DHT_EVENT_VALUES` (peers found), extracts each `(IPv4, port)` pair and calls `sync_add_peer`, which persists the entry to `registry.db`.

The infohash leaks no key material: it is derived from the hex-encoded key string, not the raw key bytes, and only the first 20 bytes of a 32-byte SHA256 are used. Reverse-engineering the AES key from the infohash is not feasible.

`dht_client_add_chat` is thread-safe and can be called at any time. New chats are queued and processed on the DHT thread's next iteration.

### NAT Traversal — UPnP and Hole Punching

Most peers are behind NAT. Two complementary techniques are applied automatically:

**UPnP (inside `sync_register`):** Before recording the local sync port in the registry, `sync_register` checks whether `DCOMMS_HOST` is already set. If not, it attempts UPnP IGD discovery (SSDP multicast to `239.255.255.250:1900`), retrieves the router's external IP, and requests a TCP port mapping (`external_port:sync_port → internal:sync_port`). On success it sets `DCOMMS_HOST` to the external IP so that the address written to `registry.db` and announced via multicast/DHT is the router's public IP. The mapping is removed when `sync_unregister` is called. If UPnP is unavailable the process continues without it.

**TCP hole punching (inside `connect_to_peer`):** When a direct TCP connect to a peer fails, a second attempt is made using `SO_REUSEPORT` to bind the outgoing socket to the same port as the local sync server before calling `connect`. This sends a SYN whose source port is predictable by the remote peer. If both sides perform this simultaneously their NATs create matching state and a simultaneous TCP open succeeds. Both sides attempt this on every `sync_with_peers` cycle, so repeated retries make success likely even without precise timing coordination.

| Scenario | Resolved by |
|---|---|
| Same LAN | Multicast discovery |
| Different networks, UPnP-capable router | UPnP port mapping |
| Behind NAT, no UPnP, non-symmetric NAT | TCP hole punching |

### Sync Protocol

The TCP sync protocol is pull-based. The server streams two sections separated by `---REGISTRY---`:

```
<messages.db content, one line per write>
---REGISTRY---
<registry.db content, one host:port per line>
```

Clients connecting to a peer receive both the message lines (appended to local `messages.db` if not already present) and the peer's known registry entries (gossiped, appended to local `registry.db`). This propagates new peers through the network without a central directory.

---

## Security Model

```
 Threat model: passive attacker can read messages.db

 Protected:   message content (AES-256-CBC)
              sender identity (random entity IDs per session)
              channel linkability (prefixes are SHA256 hashes)
              replay / forgery (HMAC-SHA256 on every ciphertext)

 Not protected: traffic analysis (file growth rate, timing)
               active tampering detection at the DB level
               multi-party confidentiality (all clients in the same group share the same key)
               key exchange (user_key + secret_id must be shared out-of-band)
               DHT infohash enumeration (infohash is public; prevents key recovery
                 but does reveal that two peers share a chat credential)
```

**Encryption:** AES-256-CBC with a fresh random 16-byte IV per message.

**Authentication:** HMAC-SHA256 computed over `IV || ciphertext` (encrypt-then-MAC). Verification uses a constant-time byte comparison to prevent timing attacks.

**Key separation:** separate keys for AES and HMAC, both derived from `user_key` via SHA256 with domain separation (`"hmac:"` prefix).

**Channel unlinkability:** the `messages.db` prefix for any group is `SHA256(random_id)[0..15]`. Without the encryption key, prefixes look like unrelated random values.

---

## Using the Library

### Build

```sh
cmake -S . -B build
cmake --build build
```

This produces `build/libdcomms_core.a`. jech/dht is fetched automatically by CMake via FetchContent (requires internet access on first configure). Link with `-lpthread`:

```sh
gcc myapp.c -I/path/to/d-comms/src -L/path/to/d-comms/build \
    -ldcomms_core -lpthread -o myapp
```

Or as a CMake subdirectory:

```cmake
add_subdirectory(d-comms)
target_link_libraries(myapp PRIVATE dcomms_core)
```

---

### API Reference

#### `proto.h` — Protocol layer

```c
// Create a new chat session. Outputs user_key and secret_id (both 33-char strings).
// Share user_key + secret_id with the other party out-of-band.
int proto_initialize(proto_chat *chat, char *out_user_key, char *out_secret_id);

// Join an existing chat using credentials received from the initiator.
void proto_join(proto_chat *chat, const char *user_key, const char *secret_id);

// Send a message. Returns 0 on success, -1 if not your turn or not initialized.
int proto_send(proto_chat *chat, const char *msg);

// Read all messages. Returns a pointer to an internal cache (invalidated on next call).
// Result contains .texts[], .entity_ids[], .sender[], .count.
// sender[i] = 0 → initiator, 1 → responder.
const proto_messages *proto_list(proto_chat *chat);

// Save chat credentials to <basedir>/chats/<name>.chat (permissions 0600).
int proto_save_chat(const proto_chat *chat, const char *name, const char *basedir);

// Load and resume a chat from saved file. Walks the chain to restore state.
int proto_load_chat(proto_chat *chat, const char *name, const char *basedir);

// Release memory held by the chat's message cache.
void proto_chat_cleanup(proto_chat *chat);

// DB-level reader/writer locks (for custom multi-threaded access patterns).
void proto_db_rdlock(void);
void proto_db_wrlock(void);
void proto_db_unlock(void);
```

#### `sync.h` — Sync and discovery layer

```c
// Start the background TCP sync server (binds to all interfaces, random port).
// Returns the bound port, or -1 on error.
int sync_start_server(void);

// Register this instance in registry.db and start LAN multicast discovery.
// Also attempts UPnP port mapping to advertise the correct external IP.
// Reads DCOMMS_HOST env var for the advertised host; defaults to 127.0.0.1.
// Set DCOMMS_HOST to your public IP to reach internet peers when UPnP is unavailable.
void sync_register(int port);

// Remove this instance from registry.db, delete the UPnP mapping, and
// shut down the TCP server and discovery thread.
void sync_unregister(void);

// Manually add a known peer (host:port) to registry.db.
// Thread-safe. No-op if the entry is already present.
void sync_add_peer(const char *host, int port);

// Pull messages.db from all registered peers and merge new lines.
// Also gossips registry entries. Returns count of new message lines added.
int sync_with_peers(void);
```

#### `dht_client.h` — Mainline DHT peer discovery

```c
// Start the DHT client on the given sync_port.
// basedir is used to persist the node ID (nodeid.db).
// Returns 0 on success, -1 on error.
int dht_client_start(int sync_port, const char *basedir);

// Announce and search for a chat identified by its user_key_hex (32 hex chars).
// Derives infohash as SHA256(user_key_hex)[0..19].
// Thread-safe; can be called from any thread at any time.
void dht_client_add_chat(const char *user_key_hex);

// Stop the DHT client and join the background thread.
void dht_client_stop(void);
```

#### `proto_messages` struct

```c
typedef struct {
    char **texts;       // decoded message strings
    char **entity_ids;  // 16-char hex anonymous sender ID per message
    int  *sender;       // 0 = initiator, 1 = responder
    int   count;        // number of messages
} proto_messages;
```

---

### Integration Example

```c
#include <stdio.h>
#include <unistd.h>
#include "proto.h"
#include "sync.h"
#include "dht_client.h"

int main(void)
{
    /* --- Group A: any client that calls proto_initialize --- */

    proto_chat chat;
    char user_key[64], secret_id[64];

    if (proto_initialize(&chat, user_key, secret_id) != 0) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    printf("Share with peer:\n  set %s %s\n", user_key, secret_id);

    /* Start sync (UPnP attempted automatically inside sync_register) */
    int port = sync_start_server();
    if (port > 0) sync_register(port);

    /* Start DHT and announce this chat */
    if (port > 0) {
        dht_client_start(port, ".");
        dht_client_add_chat(user_key);
    }

    /* Send a message */
    proto_send(&chat, "Hello from client1!");

    /* Sync with any discovered peers */
    sync_with_peers();

    /* List all messages */
    const proto_messages *msgs = proto_list(&chat);
    for (int i = 0; i < msgs->count; i++) {
        printf("[%s] %s\n",
               msgs->entity_ids[i],
               msgs->texts[i]);
    }

    /* Save for next session */
    proto_save_chat(&chat, "myfriend", ".");

    dht_client_stop();
    sync_unregister();
    proto_chat_cleanup(&chat);
    return 0;
}
```

```c
/* --- Group B: any client that calls proto_join (client2, client3, …) --- */

proto_chat chat;
const char *key = "the_user_key_from_initiator";
const char *id  = "the_secret_id_from_initiator";
proto_join(&chat, key, id);

int port = sync_start_server();
if (port > 0) sync_register(port);
if (port > 0) {
    dht_client_start(port, ".");
    dht_client_add_chat(key);
}

sync_with_peers();

const proto_messages *msgs = proto_list(&chat);
/* After Group A's slot appears, state becomes 1 and Group B clients can send */
if (chat.state == 1)
    proto_send(&chat, "Hello from client2!");

dht_client_stop();
sync_unregister();
proto_chat_cleanup(&chat);
```

---

## File Reference

| Path | Location | Description |
|------|----------|-------------|
| `messages.db` | process CWD | Append-only encrypted message store |
| `registry.db` | process CWD | Peer registry — `host:port` per line |
| `<basedir>/nodeid.db` | `basedir` passed to `dht_client_start` | 20-byte persistent DHT node identity |
| `<basedir>/chats/<name>.chat` | `basedir` passed to `proto_save_chat` | Saved chat session credentials (mode 0600) |

### `.chat` file format

```
user_key=<32 hex chars>
secret_id=<32 hex chars>
is_initiator=<0|1>
entity_id=<16 hex chars>
```

### Environment variables

| Variable | Effect |
|----------|--------|
| `DCOMMS_HOST` | Advertised IP written to `registry.db` and announced via multicast. Set to your public IP when UPnP is unavailable. Defaults to `127.0.0.1`. When UPnP succeeds this is set automatically inside `sync_register`. |

---

## Limits and Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `ID_BYTES` | 16 | Byte length of random IDs (user_key, secret_id, FIDs) |
| `PREFIX_BYTES` | 16 | Byte length of DB prefix (first 16 bytes of SHA256) |
| `MAX_MSG` | 4096 | Maximum plaintext message length in bytes |
| `MAX_LINE` | 8192 | Maximum line length in messages.db |
| `AES_KEY_SIZE` | 32 | AES-256 key size in bytes |
| `AES_IV_SIZE` | 16 | AES CBC IV size in bytes |
| `SYNC_TIMEOUT` | 1 s | TCP connect/recv timeout for peer sync |
| DHT bootstrap delay | 30 s | Wait after init before first DHT search |
| DHT search interval | 180 s | Re-announce / re-search period per chat |
| (peers) | 64 | Maximum peers processed per `sync_with_peers` call |
| (DHT active chats) | 64 | Maximum simultaneously tracked DHT infohashes |
