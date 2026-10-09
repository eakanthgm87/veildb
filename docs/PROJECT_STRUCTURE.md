# VeilDB — Full Project Structure & Implementation Guide

> Privacy-first, local-first, zero-trust embedded database written in Rust.
> This document is the complete reference: file tree, crate architecture,
> data model, protocols, API surfaces, build/run instructions and validation
> results. Generated from the actual repository at `c:\Users\ADMIN\Desktop\vei`
> (branch `main`, commit `46f59c7`).

---

## 1. What VeilDB Is

VeilDB is an embedded key-value database where:

- **SQLite** (via `rusqlite`, bundled) is only the *physical* storage engine.
- Every write becomes an **append-only, signed operation** (Ed25519) whose
  payload is **AES-256-GCM ciphertext** — the storage layer never sees plaintext.
- Every operation is **BLAKE3-hashed** and linked to its parents, forming a
  **multi-parent Merkle DAG** for tamper detection (`verify` walks the DAG).
- State is **reconstructed by replaying the log**, so history is immutable and
  any historical state can be queried (**time travel** via vector clock).
- Multiple devices converge through an **operation-based CRDT** with
  deterministic conflict resolution (commutative, associative, idempotent).
- Sync is **zero-trust**: peers authenticate with Ed25519 challenge-response,
  trust is checked live, and every received operation's hash *and* signature
  are re-verified before merge.
- Keys derive from a **passphrase + random 32-byte salt via Argon2**; key
  material is **zeroized on drop** and never crosses the CLI/Tauri API.

### Verified environment (this machine)

| Item | Value |
|---|---|
| OS / shell | Windows, PowerShell 5.1 |
| Rust | 1.99.0 (stable, host `x86_64-pc-windows-gnu` — no MSVC toolchain present; llvm-mingw provides the linker) |
| Node / npm | v24.15.0 / 11.12.1 |
| WebView2 runtime | 154.0.4258.62 (required by the Tauri app) |
| Validation | `cargo check` OK · `cargo test` OK **71 passed / 0 failed** · `cargo clippy` OK (warnings only) · `npm run build` OK · CLI e2e OK · Tauri app launches OK |

## 2. Complete File Tree

Line counts exclude build artifacts (`target/`, `node_modules/`, `dist/`, `.git/`).

```text
vei/                                    repo root (Cargo workspace)
├── Cargo.toml                          58   workspace manifest (9 members)
├── Cargo.lock                           —   locked dependency graph
├── rust-toolchain.toml                  4   channel=stable, rustfmt+clippy, minimal profile
├── README.md                           51   overview + quick build/CLI usage
├── LICENSE                              —   MIT OR Apache-2.0
├── .gitignore                           —   ignores /target, *.vdb, node_modules, dist, Cargo.lock
│
├── crates/                              ── the seven library crates ──
│   ├── storage/                             persistence only (SQLite)
│   │   ├── Cargo.toml                    16
│   │   └── src/
│   │       ├── lib.rs                    18  module wiring + re-exports
│   │       ├── engine.rs                872  SqliteStorage + StorageEngine trait + migrations + tests
│   │       ├── types.rs                 220  OperationId, LogicalClock, Operation, Snapshot,
│   │       │                                 DeviceEntry, SecretString, MergeLogEntry + tests
│   │       └── error.rs                  50  StorageError (thiserror)
│   ├── crypto/                              all cryptography (sole owner)
│   │   └── src/
│   │       ├── lib.rs                   459  Key, Ciphertext, KeyRing, SigningKeyPair,
│   │       │                                 X25519KeyPair, encrypt/decrypt, derive_key + tests
│   │       └── error.rs                  47  CryptoError
│   ├── integrity/                           hashing, Merkle DAG, proofs, tamper detection
│   │   └── src/
│   │       ├── lib.rs                   456  operation_hash, MerkleTree, proofs, diff,
│   │       │                                 validate_graph, verify_operations + tests
│   │       └── error.rs                  35  IntegrityError
│   ├── query/                               reconstruction, indexes, time travel, CRDT winner
│   │   └── src/
│   │       ├── lib.rs                   642  DbState, PutOp, IndexToken, QueryEngine,
│   │       │                                 resolve_conflicts, query_at, build_log + tests
│   │       └── error.rs                  32  QueryError
│   ├── access/                              device trust, sharing, backup/restore
│   │   └── src/
│   │       ├── lib.rs                   539  AccessEngine, DeviceInfo, TrustEntry,
│   │       │                                 ReEncryptedBlob, BackupPayload, restore + tests
│   │       └── error.rs                  68  AccessError
│   ├── sync/                                the ONLY crate allowed to cross a network boundary
│   │   └── src/
│   │       ├── lib.rs                  1101  14-step protocol, SyncMessage, SyncEngine,
│   │       │                                 Lan/Mock/Cloud/P2P backends, CrdtEngine + tests
│   │       ├── discovery.rs             224  UDP multicast discovery + signed announcements + tests
│   │       └── error.rs                  59  SyncError
│   └── core/                                facade — the ONLY app-facing API
│       └── src/
│           ├── lib.rs                  2118  VeilDbCore (24 methods), PairingBundle,
│           │                                 LiveTrustProvider, DbStatus, DAG/Merkle views + tests
│           └── error.rs                  53  CoreError
│
├── cli/                                   clap CLI binary `veildb` (depends only on core)
│   ├── Cargo.toml                        18
│   ├── src/main.rs                      514  16 subcommands, exit codes 0/1/2
│   └── tests/multi_device_sync.rs       242  3 two-process integration tests (real binaries, real TCP)
│
├── bindings/                              Tauri 2 desktop shell (depends only on core)
│   ├── Cargo.toml                        23   rlib + bin, tauri / tauri-plugin-dialog
│   ├── build.rs                           4   tauri_build::build()
│   ├── tauri.conf.json                   30   devUrl :1420, frontendDist ../frontend/dist
│   ├── capabilities/default.json         14   Tauri capability permissions
│   ├── icons/                             icon.ico, icon.png
│   ├── gen/schemas/                       generated JSON schemas (by tauri-build)
│   └── src/
│       ├── lib.rs                      1087  27 `vdb_*` Tauri commands, AppState, sync listener :8443,
│       │                                       discovery beacon, ApiResponse envelope, run()
│       └── main.rs                       16  panic hook → veildb-crash.log, calls run()
│
├── frontend/                              React 18 + TypeScript + Vite 5 + Tailwind 3
│   ├── package.json                       27   scripts: dev / build (tsc && vite build) / preview
│   ├── vite.config.ts                     15   dev server port 1420
│   ├── tsconfig.json / tsconfig.node.json 21/10
│   ├── tailwind.config.js                 29
│   ├── postcss.config.js                  6
│   ├── index.html                         12
│   └── src/
│       ├── main.tsx                       24  hash router: `#demo` → DemoSite, else → App
│       ├── App.tsx                     1873  main dashboard, 10 tabs
│       ├── mockApi.ts                    547  dual-mode API: real Tauri `invoke` OR in-browser mock
│       ├── types.ts                       80  ApiResponse/DbStatus/DeviceInfo/OperationSummary/...
│       ├── DemoSite.tsx                  854  standalone demo/marketing page (`#demo`)
│       ├── UserDemo.tsx                  332  "users" tab demo component
│       ├── Auth.tsx / AuthTypes.ts     117/21 auth demo widgets
│       ├── index.css                      12  Tailwind entry + base styles
│       └── vite-env.d.ts                   2
│
├── docs/
│   ├── PROJECT_STRUCTURE.md                —  this document
│   ├── cod.md                             155  change log of the multi-device sync work + run book
│   └── multi-device-validation.md          194  captured real two-process sync session output
│
└── testing/                               leftover runtime artifacts (veildb.vdb-shm / -wal)
```

**Totals:** ≈ 8,300 lines of Rust · ≈ 3,800 lines of TypeScript · **71 tests, all passing.**

## 3. Workspace & Dependency Graph

Root `Cargo.toml` — `resolver = "2"`, 9 members, shared `[workspace.dependencies]`
(rusqlite 0.31 bundled, aes-gcm 0.10, ed25519-dalek 2, x25519-dalek 2, argon2 0.5,
blake3 1, postcard 1, serde/serde_json, tokio 1 full, clap 4 derive, thiserror,
anyhow, zeroize, tauri 2 wry, proptest, criterion).

Strict layering — **no crate may skip a layer**:

```text
                 ┌────────────┐  ┌────────────┐
                 │  cli (bin) │  │ bindings   │  ← app layer: depends ONLY on core
                 └─────┬──────┘  │ (Tauri)    │
                       │         └─────┬──────┘
                       └───────┬───────┘
                        ┌──────▼──────┐
                        │ veildb-core │  facade (VeilDbCore) — the only public API
                        └──┬───┬───┬──┴──┬────┬─────┘
             ┌─────────────┘   │   │     │    └──────────────┐
        ┌────▼────┐      ┌─────▼─┐ │  ┌──▼─────┐      ┌─────▼────┐
        │ storage │◄─────┤ query │ │  │ access │      │   sync   │
        └────▲────┘      └───┬───┘ │  └───┬────┘      └──┬───────┘
             │               │     │      │              │
        ┌────┴────┐    ┌─────▼─────▼──────▼──┐      ┌─────▼──────┐
        │ crypto  │◄───┤    integrity        │      │ discovery  │
        └─────────┘    └─────────────────────┘      └────────────┘
```

- `storage` has **no** internal crate deps (rusqlite only).
- `crypto` has **no** internal crate deps (pure cryptography).
- `integrity` → storage (operation shape only, never SQLite).
- `query` → storage + crypto + integrity.
- `access` → storage + crypto + integrity.
- `sync` → storage + crypto + integrity (only network-crossing crate).
- `core` → all six; `cli`/`bindings` → core only; `frontend` → bindings only (via IPC).

Features: `core` exposes `sync-cloud` / `sync-p2p` (wire to `sync` crate stubs).

## 4. Data Model & SQLite Schema

### 4.1 Core types (`crates/storage/src/types.rs`)

| Type | Shape | Purpose |
|---|---|---|
| `OperationId` | `{ device_id: [u8;32], sequence: u64 }` | Globally unique op ID = per-device monotonic sequence. No wall-clock time anywhere. |
| `LogicalClock` | `Vec<([u8;32], u64)>` (vector clock) | `advance(device)`, `merge()` = element-wise max, `dominates()` — ordering and time travel. |
| `Operation` | `{ id, parents: Vec<[u8;32]>, logical_clock, device_id, ciphertext: Vec<u8>, signature: Vec<u8> }` | Append-only log entry; `ciphertext` is opaque to storage/integrity/sync. |
| `Snapshot` | `{ snapshot_id: i64, logical_clock, last_operation, state (encrypted), merkle_root }` | Checkpoint for compaction/time travel. |
| `DeviceEntry` | `{ device_id, public_key, trusted, approved_by, approval_signature, created_at }` | Trust registry (device_id = BLAKE3 of Ed25519 pubkey). |
| `SecretString` | zeroizing `String`, `Debug` prints `SecretString(***)` | Passphrase container that wipes memory on drop. |
| `MergeLogEntry` | `{ id, key, winner, loser, rule, created_at }` | Persisted record of each deterministic CRDT resolution; rules: `causal-dominance`, `concurrent-device-tiebreak`. |

### 4.2 Physical schema (migrations in `engine.rs`, `SCHEMA_VERSION = 2`)

```sql
-- v1 --------------------------------------------------
CREATE TABLE schema_version ( version INTEGER NOT NULL );

CREATE TABLE operations (
    operation_id    BLOB PRIMARY KEY,        -- postcard(OperationId)
    device_id       BLOB NOT NULL,
    sequence_number INTEGER NOT NULL,
    logical_clock   BLOB NOT NULL,           -- postcard(LogicalClock)
    parents         BLOB NOT NULL,           -- postcard(Vec<[u8;32]>)
    operation_hash  BLOB NOT NULL,           -- BLAKE3 of the canonical encoding
    ciphertext      BLOB NOT NULL,           -- AES-256-GCM payload
    signature       BLOB NOT NULL,           -- Ed25519 over the op hash
    UNIQUE(device_id, sequence_number)
);
CREATE INDEX idx_operations_device_seq ON operations(device_id, sequence_number);

CREATE TABLE snapshots (
    snapshot_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    logical_clock  BLOB NOT NULL,
    last_operation BLOB NOT NULL,
    state          BLOB NOT NULL,            -- encrypted KV state
    merkle_root    BLOB NOT NULL
);

CREATE TABLE devices (
    device_id          BLOB PRIMARY KEY,
    public_key         BLOB NOT NULL,
    trusted            INTEGER NOT NULL,
    approved_by        BLOB,
    approval_signature BLOB,
    created_at         INTEGER NOT NULL
);

CREATE TABLE metadata ( key TEXT PRIMARY KEY, value BLOB NOT NULL );

-- v2 --------------------------------------------------
CREATE TABLE merge_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key           TEXT NOT NULL,
    winner_device BLOB NOT NULL, winner_seq INTEGER NOT NULL,
    loser_device  BLOB,          loser_seq  INTEGER,
    rule          TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX idx_merge_log_key ON merge_log(key);
```

**Metadata keys** (in `metadata` table): `veildb.salt` (Argon2 KDF salt),
`veildb.db_id`, `veildb.device.signing_key` (encrypted Ed25519 secret),
`veildb.device.x25519_key`, `veildb.key_version`, `veildb.format_version`.

SQLite pragmas: WAL journal, `synchronous = NORMAL` (crash safety vs. speed).

### 4.3 `StorageEngine` trait (the persistence interface, 24 methods)

`append` (returns BLAKE3 hash, rejects duplicates) · `read_operations` ·
`read_all_operations` · `latest_operation_hash` · `create_snapshot` ·
`load_snapshot` · `compact` · `latest_snapshot(_id)` · `store/load/list_devices` ·
`set_device_trusted` · `set/get/delete_metadata` · `operation_count` ·
`current_clock` · `is_empty` · `record_merge_entry` / `list_merge_entries` /
`merge_entry_exists` · plus **debug-only** `corrupt_operation` (byte-flip used by
the GUI "tamper" tab and by tamper tests; compiled out of release builds).

## 5. Crate-by-Crate Implementation

### 5.1 `veildb-storage` — persistence only
- `SqliteStorage::open(path)` / `open_in_memory()` → `init_connection` → stepwise
  migrations (`migrate_to_v1`, `migrate_to_v2`); refuses schemas newer than
  `SCHEMA_VERSION`.
- Duplicates rejected (`DuplicateOperation`); every append runs in a transaction
  and stores the recomputed `operation_hash`.
- Knows nothing about plaintext, signatures or the network (documented invariant).

### 5.2 `veildb-crypto` — the sole owner of cryptography
| Item | Implementation |
|---|---|
| `Key` | 32 bytes, `Zeroize` on drop, `Debug` redacted, `generate()` uses OS CSPRNG |
| `Ciphertext` | `{ key_version: u32, nonce: [u8;12], data: Vec<u8> }` — fresh nonce per encryption |
| `KeyRing` | `BTreeMap<version, Key>`; `rotate_key()` derives the next version from the master secret so **historical ciphertexts stay decryptable** |
| `encrypt/decrypt` | AES-256-GCM (`aes-gcm` 0.10) |
| `SigningKeyPair` | Ed25519 (`ed25519-dalek` 2) — signs op hashes, pairing bundles, announcements |
| `X25519KeyPair` | key exchange (`x25519-dalek` 2) — share/key-wrapping paths |
| `derive_key(passphrase, salt)` | **Argon2** → 32-byte master key (deterministic per salt, tested) |
| misc | BLAKE3 `hash`, `random_bytes_32`, hex helpers |

### 5.3 `veildb-integrity` — hashing & tamper detection
- `operation_hash(op)` = BLAKE3 over canonical `postcard` encoding of
  `(id, parents, logical_clock, device_id, ciphertext, signature)`; mirrored
  identically in `storage` and `bindings`.
- `MerkleTree`: leaves = op hashes, **sorted** for determinism, padded to next
  power of two, internal nodes = BLAKE3(child‖child); API `root()`,
  `generate_proof`, `verify_proof`, `diff`.
- `verify_operations` → `IntegrityReport { status: Verified|Tampered, operations_failed, ... }`;
  `validate_graph` detects **missing parents** and **cycles**; `reachable_operations`
  walks ancestors from given tips (DAG diffing).
- Multi-parent DAG: each op lists *all* current tips as `parents`, so concurrent
  branches merge structurally, not just logically.

### 5.4 `veildb-query` — reconstruction, indexes, time travel, CRDT
- **Write payload**: plaintext is a serialized `PutOp { key, value }`, encrypted
  by `core` before it ever reaches storage.
- **State reconstruction**: `reconstruct_state()` replays all ops through the
  deterministic resolver → `DbState { clock, entries: BTreeMap<String, Vec<u8>> }`.
- **Deterministic conflict resolution** (`cmp_winners`):
  1. `causal-dominance` — the clock that dominates the other wins (later write
     wins even if appended first);
  2. `concurrent-device-tiebreak` — otherwise the **lexicographically larger
     `device_id` (then sequence)** wins. No timestamps ⇒ order-independent
     convergence (proven by tests that swap insertion order).
- `resolve_conflicts` emits `ConflictOutcome { key, winner, loser, rule }`;
  `core` persists each into `merge_log` (`veildb merges` / GUI merges tab).
- **Encrypted equality index**: `index_token(key) = BLAKE3(key)` — search by key
  without revealing it (documented leak: equality only).
- **Time travel**: `query_at(&LogicalClock)` replays only ops whose clock is ≤
  the requested vector clock.
- `build_log` produces `OperationSummary` rows (sequence, device, hash, parents, clock).

### 5.5 `veildb-access` — trust, sharing, backup/restore
- `AccessEngine` holds storage + this device's signing/X25519 keys + key ring + db_id.
- Trust: approve/`store_device`, `set_device_trusted`, revoke — enforced **live**
  by sync's `TrustProvider` (revocation applies on the next handshake).
- **Sharing**: `ReEncryptedBlob { encrypted_key, nonce, target_device_id, key }`
  wraps a record key for a target device (master → collection → record hierarchy).
- **Backup**: `BackupPayload { operations, devices, metadata, key_version }`
  encrypted into an archive with `EncryptedArchive { format_version, db_id, merkle_root }`.
- **Restore**: builds a **temporary fresh SQLite DB**, replays ops in dependency
  order (parents first; `PartialRestore` on gaps), rebuilds devices/metadata,
  then **atomically copies over the target** — the original stays untouched on
  failure; the WAL sidecar is handled too.

### 5.6 `veildb-sync` — protocol, transports, discovery

**14-step engine protocol** (`SyncStep`): 1 AuthenticatePeer → 2 VerifyDeviceTrust
→ 3 ExchangeDbMetadata → 4 ExchangeMerkleRoots → 5 DiffSubtrees →
6 IdentifyMissingOps → 7 TransferCiphertext → 8 VerifyOperationHashes →
9 VerifySignatures (real Ed25519 vs. stored pubkey) → 10 ValidateOperationGraph →
11 CrdtMerge → 12 ApplyAtomically → 13 UpdateMerkleState → 14 CommitTransaction.

- `SyncMessage` (postcard over TCP): `Hello/HelloAck` (protocol version, device,
  pubkey, nonce, **signature** — challenge-response auth), `DbMetadata`,
  `MerkleRoot`, `MissingOperations`, `Operations`, `MergeResult`, `Error`, plus
  appended auto-pairing variants `PairProbe`/`PairProbeAck`/`PairBundleOffer`/
  `PairProof`/`PairDecision` (appended last so wire discriminants stay stable).
- Transports implement `trait SyncBackend { send, receive, close, drain_close }`:
  `LanBackend` (TCP, length-prefixed frames), `MockBackend` (in-memory, tests),
  `CloudBackend`/`P2pBackend` = stubs returning `SyncError::NotImplemented`
  (features `cloud`/`p2p`).
- `TrustProvider { is_trusted, public_key_of }` — live trust; core supplies
  `LiveTrustProvider`, tests use `StaticTrustProvider`.
- `CrdtEngine` enforces commutative/associative/idempotent merge; duplicates are
  no-ops ⇒ **re-syncing is idempotent (0 ops merged on the second run)**.
- **Discovery** (`discovery.rs`): UDP multicast group `239.255.0.7:45678`,
  Ed25519-signed announcements; GUI beacon every 1500 ms, `discover(timeout_ms)`
  in the CLI.

### 5.7 `veildb-core` — the facade (the only app-facing API)

`VeilDbCore` composes `SqliteStorage + QueryEngine + AccessEngine + SyncEngine`,
holds this device's identity and the Argon2-derived master key.

**Initialization flow (`init`)**:
1. Open/create SQLite DB (migrations).
2. Load or generate 32-byte `veildb.salt`; `master_key = Argon2(passphrase, salt)`.
3. Generate or load this device's Ed25519 signing key (encrypted at rest under
   the master key) + X25519 key; `device_id = BLAKE3(public_key)`.
4. Store `veildb.db_id`, format/key-version metadata; register this device as
   the trusted root (`approved_by = None`).
5. Build the engines; passphrase kept in a zeroizing `SecretString` for pairing.

**Write flow (`put(key, value)`)** → validate key → serialize `PutOp` →
`encrypt(master_key, key_version, payload)` → append with `parents = current
tips`, `logical_clock = current_clock + advance(self)` → Ed25519-sign the
operation hash → `storage.append` (transaction) → returns `OperationId`.

**Read flow (`get(key)`)** → `query.get(key)` over the reconstructed state
(all ciphertext decrypted in memory during replay).

**The 24 public methods**: `init`, `put`, `get`, `verify_integrity`, `query_at`,
`log`, `snapshot`, `trust_device`, `revoke_device`, `export_pairing`,
`import_pairing`, `merge_log`, `record_merge_log`, `share`, `backup`, `restore`,
`list_devices`, `status`, `rotate_key`, `get_dag`, `get_merkle_tree`,
`dev_corrupt_operation`, plus `PairingBundle::to_json/from_json`.

**Supporting types**: `PairingBundle { db_id, salt, device_id, approver_public_key, signature }`
(signed, carries **no key material** — the joining device re-derives the same
master key from the shared passphrase + adopted salt), `LiveTrustProvider`
(dedicated read connection behind a mutex — `SqliteStorage` is not `Sync`),
`AutoSyncReport`, `DbStatus`, `DagNode/DagEdge/DagView`,
`MerkleNodeView/MerkleTreeView`, `SyncBackendKind { Lan, Listen, Cloud, P2p }`.

**Sync orchestration methods**: `sync_with_peer`, `sync_listen_once(_with)`,
`sync(kind)`, `sync_auto` (one-click auto-pair + sync used by the GUI),
`discover_peers`, `spawn_discovery_beacon`.

## 6. Application Layer

### 6.1 CLI — `cli/src/main.rs` (binary `veildb`, 514 lines)

Global options: `-d/--db <path>` (default `veildb.vdb`), `--passphrase <pw>`
(non-interactive, for scripts/tests; otherwise prompted).
Exit codes: **0** success · **1** general error · **2** integrity/tamper failure.

```text
veildb init                                initialize a new database
veildb put <key> <value>                   write a value (encrypted op)
veildb get <key>                           read a value
veildb verify                              verify integrity (Merkle/DAG/signatures)
veildb log [--at device:counter,...]       operation log / time-travel query
veildb status                              db_id, op count, Merkle root, clock, devices, key version
veildb snapshot                            create a snapshot
veildb merges                              show deterministic conflict-resolution log
veildb discover [--timeout-ms N]           UDP multicast peer discovery
veildb sync --backend lan [--addr A] [--listen]   dial or accept one sync session
veildb device list                         list devices + trust state
veildb device trust <pubkey-hex>           trust a new device
veildb device revoke <device-id-hex>       revoke (effective on next handshake)
veildb device export-pairing <file>        signed pairing bundle (db_id + salt, no keys)
veildb device import-pairing <file>        adopt bundle identity + approve approver
veildb device rotate-key                   rotate the master key (adds key version)
veildb share <key> --to <device-id-hex>    wrap a key for a device
veildb backup <output>                     encrypted backup archive
veildb restore <archive>                   validated restore (atomic swap)
```

Integration tests (`cli/tests/multi_device_sync.rs`, 3 tests, 242 lines) spawn
**real `veildb` binaries** with separate DB files and verify: pairing → sync
convergence (identical Merkle roots, idempotent 2nd round), deterministic
concurrent-write resolution, and immediate revocation rejection.

### 6.2 Tauri bindings — `bindings/src/lib.rs` (1087 lines)

- `AppState { core: Mutex<Option<VeilDbCore>>, db_path, passphrase: Option<SecretString>, beacon }`
  managed by Tauri; a shared `OnceLock<tokio::runtime::Runtime>` runs all async work.
- **Constant `SYNC_PORT = 8443`** — every GUI instance runs a background sync
  listener there; discovery beacon interval 1500 ms.
- Uniform response envelope `ApiResponse { success, data, error: { message, code, is_integrity } }`
  serialized to JSON — no key material ever crosses IPC.
- `setup()` registers state + starts the listener; `run()` wires plugins
  (`tauri-plugin-dialog`) and the handler; failures log to `veildb-error.log`;
  panics log to `veildb-crash.log`.

**27 commands** (all map 1:1 to `VeilDbCore`):

```text
vdb_init  vdb_open  vdb_close  vdb_put  vdb_get  vdb_status  vdb_verify
vdb_query_at  vdb_log  vdb_list_devices  vdb_trust_device  vdb_revoke_device
vdb_backup  vdb_restore  vdb_snapshot  vdb_sync_lan  vdb_sync_now  vdb_sync_info
vdb_sync_listen  vdb_export_pairing  vdb_import_pairing  vdb_discover  vdb_merges
vdb_rotate_key  vdb_get_dag  vdb_get_merkle_tree
vdb_dev_corrupt_operation   (#[cfg(debug_assertions)] only — powers the Tamper tab)
```

`tauri.conf.json`: `beforeDevCommand: npm --prefix frontend run dev`,
`devUrl: http://localhost:1420`, `frontendDist: ../frontend/dist`, window 1200×800,
CSP disabled, bundling disabled (`bundle.active: false`).

### 6.3 Frontend — `frontend/` (React 18 + TS 5.5 + Vite 5 + Tailwind 3)

- `main.tsx`: tiny hash router — `#demo` renders `DemoSite`, otherwise `App`.
- `App.tsx` (1873 lines): dashboard with **10 tabs** —
  `dashboard` (status + KV put/get), `keys` (share/rotate), `devices`
  (list/trust/revoke), `sync` (pairing export/import, LAN discovery, sync log,
  merge log), `time-travel` (query at a logical clock), `backup`
  (backup/restore via native file dialog), `graph` (DAG visualization),
  `merkle` (Merkle tree view), `tamper` (dev-mode only: corrupt an op then
  re-verify to watch detection fire), `users` (demo).
- **`mockApi.ts` is the key design point**: it checks for
  `window.__TAURI_INTERNALS__`. Inside the webview it proxies to the real
  `invoke("vdb_*")` commands; in a plain browser (`npm run dev`) it serves a
  fully functional **in-memory mock** (fake devices, ops, Merkle root, merges,
  discovered peers) so the whole UI works without Rust.
- `types.ts` mirrors the Rust `ApiResponse`/`DbStatus`/`DeviceInfo`/
  `OperationSummary`/`PairingBundle`/`DiscoveredPeer` shapes.

---

## 7. End-to-End Flows

### 7.1 Write path
```text
CLI put / GUI vdb_put
  → VeilDbCore::put(key, value)
     1. validate key non-empty
     2. payload = postcard(PutOp { key, value })
     3. ct = AES-256-GCM(master_key, fresh nonce, payload)     [crypto]
     4. clock = storage.current_clock(); clock.advance(self)
        parents = tips of current DAG
     5. op = Operation { id: (device, seq), parents, clock, device_id, ct }
     6. h = BLAKE3(canonical(op))                              [integrity]
        op.signature = Ed25519.sign(h)                         [crypto]
     7. storage.append(op)  — single SQLite transaction        [storage]
  → OperationId returned (e.g. 250c37a3…a743.1)
```

### 7.2 Read & time-travel path
```text
get(key)        → reconstruct_state()  — replay ALL ops through resolver → decrypt → BTreeMap lookup
query_at(clock) → reconstruct_from_ops(ops where op.clock ≤ target) — same resolver, historical view
log [--at ...]  → build_log() → Vec<OperationSummary>
```

### 7.3 Verify path (tamper detection)
```text
verify → read_all_operations
      → for each op: recompute BLAKE3 hash, compare to stored operation_hash
      → verify Ed25519 signature against device public key
      → validate_graph: parents exist, no cycles
      → rebuild MerkleTree → report IntegrityStatus { Verified | Tampered }
CLI exit code 2 on tamper · GUI Tamper tab shows the diff
```

### 7.4 Two-device sync path
```text
Device A (export-pairing) ──bundle.json (signed, db_id+salt)──► Device B (import-pairing)
        both now share db_id + salt ⇒ same passphrase ⇒ same master key
A ── TCP :8443 ──► B
   1-2  Hello/HelloAck: nonce + Ed25519 challenge-response, live TrustProvider check
   3-6  db metadata, Merkle roots, diff, missing-op hashes
   7    transfer ciphertext ops
   8-10 re-hash, re-verify signatures, validate DAG  (zero-trust: never trust the peer)
   11-14 CRDT merge → atomic apply → new Merkle root → commit
   both report SyncReport { sent, received, merged, merkle_root, clock }
   2nd run merges 0 ops (idempotent)
```

### 7.5 Pairing (auto, one-click) messages
`PairProbe → PairProbeAck (signed, echoes nonce) → PairBundleOffer →
PairProof (proof of passphrase knowledge) → PairDecision` — exchanged *before*
the 14-step protocol by `sync_auto`; the data key itself **never travels**.

---

## 8. Build & Run (validated on this machine)

```powershell
# 0. Toolchain (already installed here): rustup stable, host x86_64-pc-windows-gnu
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"

# 1. Rust workspace
cd c:\Users\ADMIN\Desktop\vei
cargo check --workspace        # OK (6m cold)
cargo test  --workspace        # OK — 71 passed, 0 failed
cargo clippy --workspace --all-targets --all-features   # OK — warnings only

# 2. CLI
cargo build -p veildb-cli
.\target\debug\veildb.exe --db demo.vdb --passphrase secret init
.\target\debug\veildb.exe --db demo.vdb --passphrase secret put greeting "hello"
.\target\debug\veildb.exe --db demo.vdb --passphrase secret get greeting
.\target\debug\veildb.exe --db demo.vdb --passphrase secret verify   # Integrity: VERIFIED

# 3. Frontend
cd frontend
npm install
npm run build          # tsc && vite build → dist/
npm run dev            # dev server → http://localhost:1420

# 4. Desktop app (Tauri) — needs the dev server running for devUrl
cd ..
cargo build -p veildb-bindings
.\target\debug\veildb-bindings.exe   # window "VeilDB"; logs: veildb-crash/error/debug.log
```

Two-device quick start (full script in `docs/cod.md`): `device export-pairing` on
A → copy file → `device import-pairing` on B → `sync --listen --addr 0.0.0.0:8443`
on B → `sync <B-IP>:8443` on A → identical Merkle roots on both.

## 9. Test Inventory (71 tests, 0 failures)

| Suite | Tests | Covers |
|---|---:|---|
| `veildb-storage` | 12 | schema/migrations, append/dup, clock advance/merge/dominates, round-trips |
| `veildb-crypto` | 15 | AES round-trip, sign/verify/tamper, X25519 exchange, Argon2 determinism, key-ring rotation, zeroize |
| `veildb-integrity` | 13 | Merkle build/proof/diff, verify OK/tampered, graph cycle/missing-parent, reachability |
| `veildb-query` | 10 | reconstruction, deterministic conflicts regardless of insertion order, causal dominance, time travel |
| `veildb-access` | 14 | trust/approve/revoke, backup/restore, partial-restore rejection |
| `veildb-sync` | 13 | mock/Lan backends, session flow, FIN-clean teardown, discovery signing/tamper |
| `veildb-core` | 3 (~18s) | facade integration |
| `veildb-cli` (integration) | 3 (~10s) | **two real processes**: pairing+sync convergence, deterministic merge, live revocation |
| doc-tests | 0 | (none present) |

*(Counts derived from the actual `cargo test --workspace` run on this machine;
suites that report extra doc-test lines are included in the totals.)*

---

## 10. Security Properties & Known Limitations

**Properties**: passphrase never stored; master key only in memory (zeroized on
drop); all at-rest data encrypted (AES-256-GCM, per-op nonce, versioned keys);
Ed25519-signed operations; BLAKE3 + Merkle-DAG tamper evidence; zero-trust sync
(peer's hashes/signatures/graph re-verified locally); trust checked live
(revoke = immediate); the pairing bundle is signed but **not secret**; the
storage/integrity/sync layers structurally cannot see plaintext.

**Limitations / notes observed in this checkout**:
1. Toolchain: this machine builds with **GNU/MinGW** (no MSVC toolset installed;
   llvm-mingw provides the linker). Everything works, but release builds with
   `lto = true` link slowly; installing VS Build Tools would allow switching to
   the MSVC host.
2. `cargo clippy` reports warnings (redundant closures in `core`, `&PathBuf`
   params in `cli`, one non-binding future in `bindings`) — not yet fixed.
3. `npm audit`: 10 advisories (3 moderate, 7 high) in the frontend dependency
   tree; `npm audit fix --force` would apply breaking upgrades.
4. `CloudBackend`/`P2PBackend` are intentional stubs (`SyncError::NotImplemented`).
5. `Cargo.lock` and `frontend/dist` are gitignored (builds aren't pinned in VCS).
6. GUI dev flow needs the Vite server running (debug builds embed `devUrl`);
   for a standalone GUI, run `npm run build` and adjust the config.
7. `docs/cod.md` mentions a stale repo path (`...\Downloads\nem`); the actual
   repository is `c:\Users\ADMIN\Desktop\vei`.
8. The `testing/` directory only contains leftover `-wal`/`-shm` runtime files
   (the `.vdb` itself is gitignored).

---

*End of document. Companion files: `README.md` (quick start), `docs/cod.md`
(implementation change log + run book), `docs/multi-device-validation.md`
(captured real two-device sync session).*

