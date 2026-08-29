# VeilDB Multi-Device Sync — End-to-End Validation

This document records a real, end-to-end validation of VeilDB's multi-device
sync: two genuine OS processes (`veildb` CLI binaries) pairing over out-of-band
pairing bundles, exchanging operations over real TCP, and converging on a
deterministic CRDT resolution — including the queryable merge log and the live
revocation behaviour.

Everything below was produced against the actual `veildb` binary on Windows
(powershell) with two separate on-disk SQLite databases and distinct signing
keys per device. No stubs, no in-process mocks, no shared memory.

---

## 1. What changed (summary)

| Area | Change |
|------|--------|
| `storage` | `MergeLogEntry` type, schema v2 `merge_log` table, `record_merge_entry` / `list_merge_entries` / `merge_entry_exists` / `delete_metadata` engine methods |
| `query` | Deterministic CRDT conflict resolution: `cmp_winners` (causal dominance → `device_id`/seq tiebreak), `resolve_conflicts`, `ConflictOutcome`, `ResolutionRule`; `reconstruct_from_ops`, `get`, and `query_at` all apply the deterministic winner regardless of append order |
| `sync` | `TrustProvider` trait + `StaticTrustProvider` (live trust lookup instead of a snapshot `HashSet`); real Ed25519 signature verification of every synced op in step 9; `SyncError::NotImplemented` for Cloud/P2P stubs; new `discovery` module (UDP multicast `239.255.0.7:45678`, signed announcements) |
| `core` | `PairingBundle` (signed, carries `db_id` + KDF `salt`), `export_pairing` / `import_pairing` (joiner adopts db identity + salt, so the data key derives from the shared passphrase), `sync_with_peer` / `sync_listen_once` / `sync`/`SyncBackendKind`, `discover_peers`, `merge_log`, `record_merge_log`, `LiveTrustProvider`; `revoke_device` now works immediately (live trust check, no stale snapshot) |
| `cli` | `device export-pairing`, `device import-pairing`, `discover`, `merges` (+ `--listen` on sync, `--passphrase` for scripting) |
| tests | `cli/tests/multi_device_sync.rs` — three two-process integration tests |

---

## 2. Build

```powershell
cargo build --workspace
```

The full workspace test suite (unit + integration) passes:

```text
running 10 tests   # veildb-query (incl. 3 new deterministic-conflict tests)
test result: ok. 10 passed; 0 failed

running 12 tests   # veildb-storage
test result: ok. 12 passed; 0 failed

running 11 tests   # veildb-sync (incl. 2 discovery tests)
test result: ok. 11 passed; 0 failed

running 3 tests    # veildb-cli (two-process integration)
test result: ok. 3 passed; 0 failed
```

---

## 3. Two-device end-to-end run (real processes)

### 3.1 Init two independent devices

```
PS> veildb --db devA.vdb --passphrase "shared-secret" init
Database initialized: ...\devA.vdb
  DB ID: 7f68beda06d83b9c41eaa60c5ce555366422cc0516d0c12e5430c31f2591c044
  Device ID: 2a5eb4785c8b5c0c2c86ca2e091db88cb03f720ef10850960b59cbce5ff2d8d7
  Key version: 1

PS> veildb --db devB.vdb --passphrase "shared-secret" init
Database initialized: ...\devB.vdb
  DB ID: d140462902090f818713701cceba4cdc156aa850f833c4595eaac03adba91434   <- different DB
  Device ID: 128725957d06fd1f11d454cc5a438aecef71bd2a93db5ec868d69b647e4749dd
  Key version: 1
```

Each device has its own database identity and its own signing key.

### 3.2 Pairing

The existing device (A) exports a signed pairing bundle; the joining device (B)
imports it, which approves A and — because B's database is still empty —
**adopts A's db_id and KDF salt** so the shared passphrase derives the same data
key on B. The data key never travels over the wire.

```
PS> veildb --db devA.vdb --passphrase "shared-secret" device export-pairing pair-a.json
Pairing bundle written: ...\pair-a.json
  DB ID: 7f68beda06d83b9c41eaa60c5ce555366422cc0516d0c12e5430c31f2591c044
  Approver device: 2a5eb4785c8b5c0c2c86ca2e091db88cb03f720ef10850960b59cbce5ff2d8d7

PS> veildb --db devB.vdb --passphrase "shared-secret" device import-pairing pair-a.json
Pairing bundle imported and device approved:
  Device ID: 2a5eb4785c8b5c0c2c86ca2e091db88cb03f720ef10850960b59cbce5ff2d8d7
  Public key: 5a29dd17...3b0f6aa5

PS> veildb --db devB.vdb --passphrase "shared-secret" device export-pairing pair-b.json
Pairing bundle written: ...\pair-b.json
  DB ID: 7f68beda06d83b9c41eaa60c5ce555366422cc0516d0c12e5430c31f2591c044   <- now A's identity
  Approver device: 3095e432caf80d913193245e89f781264cece382ce8a55f2e3f608b2dd8b2401

PS> veildb --db devA.vdb --passphrase "shared-secret" device import-pairing pair-b.json
Pairing bundle imported and device approved:
  Device ID: 3095e432caf80d913193245e89f781264cece382ce8a55f2e3f608b2dd8b2401
  Public key: 05f4eb18...b40662e4
```

Both devices now trust each other (symmetric mutual trust):

```
PS> veildb --db devA.vdb --passphrase "shared-secret" device list
Device ID                                Public Key   Trusted    Approved By
2a5eb4785c8b5c0c2c86ca2e091db88cb03f720ef10850960b59cbce5ff2d8d7 5a29dd17...3b0f6aa5 YES  -
3095e432caf80d913193245e89f781264cece382ce8a55f2e3f608b2dd8b2401 05f4eb18...b40662e4 YES  2a5eb478...
```

### 3.3 Independent writes (including a concurrent write to the same key)

```
PS> veildb --db devA.vdb --passphrase "shared-secret" put greeting "hello from A"
Stored 'greeting' (op 2a5eb4785c8b5c0c2c86ca2e091db88cb03f720ef10850960b59cbce5ff2d8d7.1)

PS> veildb --db devB.vdb --passphrase "shared-secret" put farewell "bye from B"
Stored 'farewell' (op 3095e432caf80d913193245e89f781264cece382ce8a55f2e3f608b2dd8b2401.1)

PS> veildb --db devA.vdb --passphrase "shared-secret" put conflict "A wins?"
Stored 'conflict' (op 2a5eb4785c8b5c0c2c86ca2e091db88cb03f720ef10850960b59cbce5ff2d8d7.2)

PS> veildb --db devB.vdb --passphrase "shared-secret" put conflict "B wins?"
Stored 'conflict' (op 3095e432caf80d913193245e89f781264cece382ce8a55f2e3f608b2dd8b2401.2)
```

Both devices wrote to `conflict` with no prior exchange — a genuine concurrent
conflict under the vector-clock.


### 3.4 Real TCP sync (A listens, B dials)

```
PS> veildb --db devB.vdb --passphrase "shared-secret" sync --backend lan --addr 127.0.0.1:49001
Sync report:
  Received: 2 ops
  Sent: 2 ops
  Merged: 2 ops
  Merkle root: e97ff7f106ba62886ab4c65376b7c4983eb0eec7683e9b023b195e9419ebdb82
  Status: OK
  Message: Sync completed successfully
```

The listener (A) prints its own report:

```
listening on 127.0.0.1:49001
Sync report:
  Received: 2 ops
  Sent: 2 ops
  Merged: 2 ops
  Merkle root: e97ff7f106ba62886ab4c65376b7c4983eb0eec7683e9b023b195e9419ebdb82   <- identical to B
  Status: OK
  Message: Sync completed successfully
```

Both devices converged on the **same Merkle root** after exchanging operations.

### 3.5 Post-sync state on both devices

```
PS> veildb --db devA.vdb --passphrase "shared-secret" get farewell
bye from B

PS> veildb --db devB.vdb --passphrase "shared-secret" get greeting
hello from A
```

### 3.6 Deterministic conflict resolution + queryable merge log

Both devices independently resolve `conflict` to the **same winner** — B's write
(device ID `3095e432…` > `2a5eb478…` byte-wise — the deterministic device-ID
tiebreak for concurrent ops):

```
PS> veildb --db devA.vdb --passphrase "shared-secret" get conflict
B wins?

PS> veildb --db devB.vdb --passphrase "shared-secret" get conflict
B wins?

PS> veildb --db devA.vdb --passphrase "shared-secret" merges
Key                  Winner                 Loser                  Rule
conflict             3095e432...dd8b2401.2  2a5eb478...5ff2d8d7.2 concurrent-device-tiebreak

PS> veildb --db devB.vdb --passphrase "shared-secret" merges
Key                  Winner                 Loser                  Rule
conflict             3095e432...dd8b2401.2  2a5eb478...5ff2d8d7.2 concurrent-device-tiebreak
```

The merge logs are **identical and queryable on both replicas**, and they agree
with the resolved state. Because both devices have the same operation set, they
compute the same winner and the same rule, independent of sync direction or
append order.

---

## 4. Revocation takes effect immediately

The trust check is live (storage-backed `TrustProvider`), not a snapshot, so a
revocation is honored on the very next handshake:

```
PS> veildb --db devA.vdb --passphrase "shared-secret" device revoke 3095e432caf80d913193245e89f781264cece382ce8a55f2e3f608b2dd8b2401
Device revoked: 3095e432caf80d913193245e89f781264cece382ce8a55f2e3f608b2dd8b2401

PS> veildb --db devB.vdb --passphrase "shared-secret" sync --backend lan --addr 127.0.0.1:49002
Error: Sync error: I/O error: An established connection was aborted ...   (client sees the dropped conn)

# the listener (A) is the enforcing side and reports:
Error: Sync error: Peer not trusted: [...]
```

The revoked device cannot complete a sync session — its handshake is refused by
the (now untrusting) peer. This is exercised by the
`revoked_device_is_rejected_immediately` integration test.

---

## 5. Integration tests (two real OS processes)

`cli/tests/multi_device_sync.rs` spawns actual `veildb` binaries:

1. **`two_processes_pair_and_sync_converge`** — pair, write independently, sync
   over real TCP, assert both replicas hold both values; a second sync round
   transfers `0 ops` (CRDT idempotence).
2. **`concurrent_writes_resolve_deterministically`** — both devices write the
   same key before any sync; after sync they converge on one value and the merge
   log records `concurrent-device-tiebreak` identically on both.
3. **`revoked_device_is_rejected_immediately`** — after a successful sync, A
   revokes B; B's next sync attempt fails on both ends.

```text
running 3 tests
test revoked_device_is_rejected_immediately ... ok
test two_processes_pair_and_sync_converge ...... ok
test concurrent_writes_resolve_deterministically ... ok

test result: ok. 3 passed; 0 failed
```

Run them with:

```powershell
cargo test -p veildb-cli --test multi_device_sync
```

---

## 6. Threat model notes

- **Pairing bundle** carries only non-secret `db_id` + KDF `salt` and the
  approver's public key, all Ed25519-signed. No passphrase or data key ever
  leaves a device.
- **Operation signatures** are Ed25519-verified against each device's stored
  public key on receipt (protocol step 9), not just length-checked.
- **Discovery announcements** (`discovery.rs`) are signed and bind device ID to
  public key; listeners verify before dialing.
- **Merge determinism**: winner is decided by vector-clock causal dominance,
  then device ID (byte-wise ascending), then sequence — commutative,
  associative, and idempotent, so every replica holding the same operations
  converges identically.

