All work is complete and validated. The deletions shown (`WebView2Loader.dll`, `demo/`, `steps.md`, `tauri_*.log`) are pre-existing repository changes unrelated to this task; my changes are the modified crates/CLI and the new untracked files.

## Summary

I implemented end-to-end multi-device sync across real OS processes for VeilDB, completing every item in the plan:

### ✔ Query crate — deterministic CRDT merge
- Added `cmp_winners` (causal dominance → `device_id`/seq tiebreak), `resolve_conflicts`, `ConflictOutcome`, and `ResolutionRule` (`causal-dominance` / `concurrent-device-tiebreak`).
- `reconstruct_from_ops`, `get`, and `query_at` all now apply the deterministic winner regardless of append order, so replicas converge identically.
- 3 new tests prove conflicts resolve the same way regardless of insertion order and the merge report is queryable.

### ✔ Sync crate — live trust, real signatures, discovery
- Replaced the snapshot `HashSet` with a `TrustProvider` trait + `StaticTrustProvider`, so `revoke_device` takes effect immediately.
- Step 9 now does real Ed25519 verification of every synced op against the device's stored public key.
- Cloud/P2P stubs return `SyncError::NotImplemented` instead of `CoreError::Serialization`.
- New `discovery.rs`: UDP multicast (`239.255.0.7:45678`) with signed announcements, `discover`/`spawn_beacon`, plus encode/decode/validate and unit tests.

### ✔ Core crate — pairing, sync, merge log
- `LiveTrustProvider` (storage-backed, mutex-wrapped since `SqliteStorage` isn't `Sync`).
- `export_pairing`/`import_pairing` with a signed `PairingBundle` carrying `db_id` + KDF `salt` — the joining device adopts the database identity so the shared passphrase derives the same data key (the key itself never travels).
- `sync_with_peer`, `sync_listen_once(_with)`, `sync`/`SyncBackendKind` (incl. `Listen`), `discover_peers`, `merge_log`, `record_merge_log`.
- `revoke_device` now works immediately (live check).
- Fixed a latent bug: regenerated signing keypairs on an existing DB were never persisted, so device identity changed across opens — now always persisted.

### ✔ CLI
- Added `device export-pairing`, `device import-pairing`, `discover`, `merges`, plus `--listen` on sync and `--passphrase` for scripting.

### ✔ Two-process integration tests (`cli/tests/multi_device_sync.rs`)
- 3 tests spawn real `veildb` binaries: pairing + sync convergence (with a 0-op idempotent second round), deterministic concurrent-write resolution, and immediate revocation rejection. All pass.

### ✔ Docs
- `docs/multi-device-validation.md` with real captured terminal output showing pairing, TCP sync (identical Merkle roots), deterministic conflict resolution (`B wins?` on both, identical merge logs), and live revocation rejection.

### Validation
- Full workspace builds and all 11 test suites pass (0 failures), including the 3 new integration tests and 2 discovery tests.

One intentional behavior note: when a revoked device is the dialing *client*, it sees a raw connection abort (`os error 10053`) because the trust rejection happens on the listener side, which drops the connection — the sync correctly fails on both ends, as verified by the integration test.


Here's how to build and run the project. There are **three entry points**: a CLI binary, a Tauri desktop app, and the frontend dev server.

---

## Prerequisites

- **Rust** (1.75+) with `cargo`
- **Node.js** (18+) with `npm` (for the frontend / Tauri app)

---

## 1. Build everything (Rust workspace)

From the repo root (`c:\Users\ADMIN\Downloads\nem`):

```powershell
cargo build
```

This compiles all 8 crates plus the CLI and the bindings crate. The CLI binary lands at `target\debug\veildb.exe`.

---

## 2. Run the CLI

```powershell
# Initialize a new database
cargo run -p veildb-cli -- init --db alice.vdb

# Put / get data
cargo run -p veildb-cli -- --db alice.vdb put foo bar
cargo run -p veildb-cli -- --db alice.vdb get foo

# Multi-device: export a pairing bundle from device A
cargo run -p veildb-cli -- --db alice.vdb device export-pairing

# On device B: import that bundle (joins the same database identity)
cargo run -p veildb-cli -- --db bob.vdb device import-pairing '<paste-bundle-json>'

# Sync A -> B (run these in two terminals)
cargo run -p veildb-cli -- --db bob.vdb sync --listen 127.0.0.1:8443
cargo run -p veildb-cli -- --db alice.vdb sync 127.0.0.1:8443

# Other commands
cargo run -p veildb-cli -- --db alice.vdb discover
cargo run -p veildb-cli -- --db alice.vdb merges
cargo run -p veildb-cli -- --db alice.vdb device list
cargo run -p veildb-cli -- --db alice.vdb status
```

Use `--passphrase <pw>` for non-interactive / scripted runs (the integration tests use this).

---

## 3. Run the Tauri desktop app (full GUI)

The `bindings` crate wraps the core library as Tauri commands and launches the React frontend:

```powershell
cargo run -p veildb-bindings
```

This opens the **VeilDB** desktop window with all tabs — Dashboard, Keys, Devices, **Sync** (with the new Pairing / Peer Discovery / Merge Log sections), Time Travel, Backup, etc.

---

## 4. Run the frontend standalone (browser dev server)

For fast frontend iteration without the Tauri shell:

```powershell
cd frontend
npm install      # first time only
npm run dev      # starts Vite at http://localhost:5173
```

In browser mode the app uses an in-memory **mock API** (no real database), so you can exercise the UI flows — pairing export/import, discovery, merge log, sync — with simulated responses. The mock returns empty peers/merges and a zero-op sync.

To build the frontend for production:
```powershell
cd frontend
npm run build    # outputs to frontend/dist
```

---

## 5. Run the tests

```powershell
# All crates + CLI integration tests
cargo test --workspace

# Just the multi-process sync integration tests
cargo test -p veildb-cli --test multi_device_sync
```

The integration tests spawn two real `veildb` binaries and verify pairing → sync convergence, deterministic conflict resolution, and live revocation across processes.

---

**Quick path to see the new features:** run `cargo run -p veildb-bindings` for the full GUI, or `cargo run -p veildb-cli -- --db foo.vdb device export-pairing` etc. from the CLI.



Here are the exact steps to add a second device to an existing database. You'll need **two terminals** (or two machines on the same LAN).

---

## Step 1 — Set up the existing database (Device A)

If you don't already have a database, create one with some data:

```powershell
cargo run -p veildb-cli -- init --db alice.vdb
cargo run -p veildb-cli -- --db alice.vdb put greeting "hello from Alice"
```

---

## Step 2 — Export a pairing bundle (Device A)

This produces a signed JSON bundle that carries the database identity (but **never** the encryption key):

```powershell
cargo run -p veildb-cli -- --db alice.vdb device export-pairing bundle.json
```

This writes `bundle.json` to disk. **Copy that file to Device B** (USB, email, LAN share — it's signed, not secret).

---

## Step 3 — Initialize Device B's database and import the bundle

On Device B, init a fresh database (it will adopt the bundle's identity on import), then import:

```powershell
cargo run -p veildb-cli -- init --db bob.vdb
cargo run -p veildb-cli -- --db bob.vdb device import-pairing bundle.json
```

After this, both databases share the same `db_id` and KDF salt, so the same passphrase derives the same data-encryption key. Verify:

```powershell
cargo run -p veildb-cli -- --db alice.vdb status
cargo run -p veildb-cli -- --db bob.vdb status
```

Both should show the **same `db_id`**.

---

## Step 4 — Sync A → B

**Terminal 1 (Device B — the listener):**

```powershell
cargo run -p veildb-cli -- --db bob.vdb sync --listen --addr 0.0.0.0:8443
```

**Terminal 2 (Device A — the dialer):**

```powershell
cargo run -p veildb-cli -- --db alice.vdb sync 127.0.0.1:8443
# (use Device B's real IP if on different machines)
```

Device A pushes its ops to B; both ends report `operations_sent` / `operations_received` and matching Merkle roots. Confirm convergence:

```powershell
cargo run -p veildb-cli -- --db bob.vdb get greeting
# → "hello from Alice"
```

---

## Step 5 — Verify the new device

```powershell
# On either device:
cargo run -p veildb-cli -- --db alice.vdb device list
```

You'll see both `device_id`s, both `trusted: true`, and the joining device's `approved_by` set to Device A.

---

## (Optional) Use the GUI instead of CLI

Run `cargo run -p veildb-bindings` to open the Tauri desktop app. The **Sync** tab has the same flow visually:
1. Click **Export Pairing Bundle** → copy the JSON shown
2. On the other device, paste it into the textarea → click **Import Pairing Bundle**
3. Use **Discover LAN Peers** or enter an address, then **Sync with LAN peer**

---

**Notes:**
- The pairing bundle is **signed** but not secret — it contains the `db_id` and KDF salt, not the passphrase or encryption key. Anyone with the bundle can *request* to join; approval only happens because the bundle is signed by an already-trusted device.
- Revoking a device is immediate: `veildb --db alice.vdb device revoke <device_id_hex>` — the revoked device is rejected on the next sync even without restarting.
- To add a **third** device, repeat steps 2–4 from any already-trusted device.