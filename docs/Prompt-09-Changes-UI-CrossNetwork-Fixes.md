# Master Change Prompt — VeilDB: UI Redesign, Cross-Network Sync, and Fixes

> **Audience:** a coding agent (and its teammates) modifying the **existing**
> VeilDB repository. This is NOT a greenfield build. The project already
> exists, compiles, and passes 71 tests. Your job is to make the specific
> changes below **on top of the current code**, reusing what is already there.
> Do not rebuild crates from scratch and do not restructure the workspace.

---

## 0. Read this first — the repo is NOT what the old build prompts describe

The original `Prompt-01..08` specs describe an idealized design. The code that
actually shipped diverges from them. **Trust this section, not the old specs,
for the current state:**

| Area | Old spec said | What the code ACTUALLY is (ground truth) |
|---|---|---|
| Storage backend | `redb` / `sled`, WAL, segments, group-commit | **SQLite via `rusqlite` (bundled)**, single `operations` table, WAL pragma. One crate: `crates/storage`. |
| Crate layout | `app/` for the desktop shell | **`bindings/`** (Tauri 2 shell) + **`frontend/`** (React/Vite/Tailwind), separate. No `app/`. |
| Sync transport | `libp2p` (LAN mDNS + P2P hole-punch + cloud relay) | **Custom 14-step protocol over plain TCP** (`LanBackend`), peer discovery via **UDP multicast** (`crates/sync/src/discovery.rs`). `CloudBackend`/`P2pBackend` are **feature-gated stubs that return `BackendNotAvailable`**. `libp2p` is NOT a dependency. |
| Crypto | HKDF ratchet forward-secrecy, `mlock`, Argon2 calibration, `aes-siv` index | AES-256-GCM, Ed25519, X25519, Argon2id (default params), BLAKE3, `zeroize`. Key "rotation" is a BLAKE3 chain (NOT forward-secret). Index is **BLAKE3(key)**, not AES-SIV. No `mlock`, no Argon2 calibration. |
| Core API | `write(plaintext, fields)` / `read(id)` | **`put(key, value)` / `get(key)`** key-value facade: `crates/core` → `VeilDbCore`. |
| Integrity | hash-chain + incremental Merkle + signed cross-device checkpoints + quarantine | `operation_hash` + a rebuilt `MerkleTree` + `validate_graph`. **No hash-chain, no checkpoints, no quarantine state.** |

**Rule:** when a change below touches a layer, read the real file first
(paths are given) and extend it. Keep the existing public types
(`Operation`, `OperationId`, `SyncMessage`, `VeilDbCore`, `ApiResponse`, etc.).

### Workspace map (real)
```
crates/storage   SqliteStorage, StorageEngine trait, Operation, LogicalClock   (engine.rs ~870 lines)
crates/crypto    Key, KeyRing, SigningKeyPair, X25519KeyPair, encrypt/decrypt, derive_key, pairing_proof
crates/integrity operation_hash, MerkleTree, validate_graph, verify_operations
crates/query     QueryEngine, DbState, PutOp, cmp_winners (CRDT winner), query_at (time travel)
crates/access    AccessEngine, device trust, sharing, backup/restore
crates/sync      SyncEngine (14-step), SyncMessage, LanBackend/MockBackend, CrdtEngine, discovery.rs (UDP multicast)
crates/core      VeilDbCore facade (put/get/sync_auto/verify/...), LiveTrustProvider, PairingBundle
cli/             clap binary `veildb`
bindings/        Tauri 2: src/lib.rs = 27 `vdb_*` commands, AppState, sync listener :8443, discovery beacon
frontend/        React 18 + TS + Vite 5 + Tailwind 3: App.tsx (dashboard, 10 tabs), mockApi.ts (dual-mode), DemoSite.tsx
```

### Non-negotiable invariants (do not break any of these)
1. **Zero-trust transport.** Anything crossing a network (including a relay)
   may see only opaque, already-encrypted `SyncMessage` bytes. No plaintext,
   no keys, no index tokens, no query semantics ever leave the device. The
   relay in Change 2 is a **blind byte-forwarder** — it must be implementable
   with zero knowledge of VeilDB internals.
2. **Layering.** Only `crates/sync` crosses the network. `cli` and `bindings`
   depend only on `crates/core`. Frontend talks only to `bindings` via Tauri
   IPC (plus the in-browser mock in `mockApi.ts`). Do not add network calls
   to the frontend.
3. **Crypto stays in `crates/crypto`.** No other crate calls a primitive directly.
4. **Append-only.** Never mutate or delete historical operations except via the
   existing `compact` path.
5. **Tests must stay green.** `cargo test --workspace` and `npm run build` must
   pass after every change. Add tests for new logic (see acceptance criteria).

### Tech stack (use what's already in `Cargo.toml` / `package.json`; add deps only when a change truly needs one)
- Rust 2021, `tokio`, `rusqlite` (bundled SQLite), `aes-gcm`, `ed25519-dalek`,
  `x25519-dalek`, `argon2`, `blake3`, `postcard`, `serde`, `thiserror`, `clap`,
  `tauri` v2 (+ `tauri-plugin-dialog`).
- Frontend: React 18, TypeScript (strict), Vite 5, Tailwind CSS 3.
- **Allowed new deps** (only if the change needs them): none required for
  Changes 1 and 3. For Change 2 you may add nothing new to the client (reuse
  `tokio` TCP); the relay is a standalone `tokio` binary.

---

## CHANGE 1 — Production-grade black-and-white dashboard UI

**Goal:** restyle the existing frontend into a crisp, monochrome,
production-looking **square dashboard**. This is a **restyle + layout pass**,
not a rewrite. Keep every existing feature, tab, and IPC call wired exactly as
it is in `frontend/src/App.tsx` and `mockApi.ts`.

**Files:** `frontend/src/App.tsx`, `frontend/src/index.css`,
`frontend/tailwind.config.js`, and the sub-components
(`DemoSite.tsx`, `UserDemo.tsx`, `Auth.tsx`). Do not change `mockApi.ts`
behavior or `types.ts` shapes.

### Design system
- **Palette — strict black & white + one state accent:**
  - Background `#0a0a0a`, surfaces `#111` / `#161616`, borders `#262626` (1px).
  - Text near-white `#f5f5f5`, muted `#a3a3a3`.
  - **State accent only** (never decorative): green `#22c55e` = verified / synced,
    amber `#f59e0b` = pending / conflict, red `#ef4444` = tamper / error.
  - No gradients, no colored brand headers, no drop shadows beyond the 1px border.
- **Shape language — "square":** rectangular cards with sharp or minimal
  (≤2px) corners, 1px borders, consistent 8-pt spacing grid. A dashboard
  built from a **grid of equal, bordered tiles**, not rounded floating cards.
- **Typography:** monospace (e.g. JetBrains Mono / ui-monospace) for all
  hashes, device IDs, public keys, clocks, Merkle roots; clean sans-serif
  (e.g. Inter / system-ui) for labels and prose.
- **Density:** compact tables and lists over big cards. Whitespace separates
  sections, not individual rows.
- **Layout:** left vertical nav (the existing tabs) + a top status strip
  (DB open/closed, sync status, integrity status). Integrity = tampered must be
  an **unmissable persistent red banner**, not a small badge.
- **Accessibility:** keyboard-navigable tables/forms, WCAG-AA contrast within
  the dark palette, visible focus rings.

### Constraints
- Do not remove or rename any tab or any `api.*` call. The 10 tabs keep their
  functions; only their presentation changes.
- No new heavy UI library. Hand-build with Tailwind utilities; a single
  headless primitive (e.g. Radix) is allowed only if a dialog/dropdown needs
  real a11y.
- Keep the in-browser mock mode working (so `npm run dev` without Tauri still renders).
- No `localStorage`/`sessionStorage` for app state — `core` is the source of truth.

### Acceptance
- `npm run build` passes (tsc strict + vite).
- Every pre-existing action still reaches the same IPC command.
- Screenshots of Dashboard, Records, Devices, Sync look like one deliberate
  monochrome system; tamper state shows the red banner.

---

## CHANGE 2 — Sync across different networks (not just same Wi-Fi)

**Why it only works on one Wi-Fi today:** peer discovery is **UDP multicast**
(`crates/sync/src/discovery.rs`), which never leaves the local subnet, and the
transport dials a **LAN IP on TCP :8443** (`SYNC_PORT` in
`bindings/src/lib.rs`) that is not routable from another network. `CloudBackend`
and `P2pBackend` are stubs. So two devices on different networks can neither
find nor reach each other.

**Goal:** add an **internet path** that works across NAT/different networks,
while preserving zero-trust. Do this by **reusing the existing 14-step
`SyncMessage` protocol unchanged** and only changing how the two peers get a
bidirectional byte stream to each other.

### Chosen approach — a blind relay (implement `CloudBackend`) + manual direct fallback
Preferred, because it "just works" behind NAT/CGNAT without port-forwarding and
keeps the server zero-knowledge. (Full libp2p hole-punching is explicitly out
of scope — too large; do not pull in `libp2p`.)

**2a. Relay server — new standalone binary (e.g. `relay/` crate, `tokio` only).**
- A dumb TCP rendezvous. A client connects and sends a small fixed header:
  `[room_id: 32 bytes][role: 1 byte]` where `room_id` is **`BLAKE3(db_id)`**
  (derivable by both peers, reveals nothing) and role ∈ {initiator, responder}.
- The relay pairs the two sockets sharing a `room_id` and then **pipes bytes
  verbatim in both directions** (`tokio::io::copy_bidirectional`). It never
  parses, stores, or inspects `SyncMessage`. It holds a connection only until
  its partner arrives (with a timeout) and forgets everything on disconnect.
- No TLS requirement for correctness (payload is already end-to-end encrypted
  and authenticated), but document that operators SHOULD terminate TLS in front
  of it; the VeilDB payload's confidentiality does not depend on it.
- Keep it tiny and stateless: a `HashMap<room_id, waiting_socket>` guarded by a
  `Mutex`, plus the pipe. Add a hard cap on concurrent rooms and an idle timeout.

**2b. Client — implement `CloudBackend` in `crates/sync/src/lib.rs`.**
- It already has the `SyncBackend` trait (`send`/`receive`/`close`) and
  `LanBackend` as a reference. `CloudBackend::connect(relay_addr, db_id, role)`
  opens a TCP stream to the relay, writes the rendezvous header, then behaves
  **exactly like `LanBackend`** for `send`/`receive` (length-prefixed postcard
  `SyncMessage`). Reuse the same framing helpers — factor
  `write_message`/`read_message` into a shared helper if convenient, but do not
  change the wire format.
- Remove the `#[cfg(feature = "cloud")]` stub gating so the real backend is
  always available, or keep the feature but make it real and enabled by default
  in `bindings`.

**2c. Core + bindings wiring.**
- `crates/core`: extend the sync entry point (`sync_auto` / add
  `sync_via_relay`) to accept a relay address and construct a `CloudBackend`.
  Keep the existing LAN path for same-network use.
- `bindings/src/lib.rs`: add/extend a `vdb_sync_*` command so the UI can pass a
  relay URL. Add a small persisted setting (in the existing metadata store, not
  a new file) for the relay address and whether to prefer LAN or relay.
- **Role assignment:** the dialing side is `initiator`, the listening side is
  `responder` — mirror how the current auto-pairing picks initiator/responder
  so the existing handshake and `pairing_proof` logic are unchanged.

**2d. UX for connecting across networks.**
- In the Sync tab: keep "Discover on LAN" (multicast) for same-Wi-Fi, and add a
  "Connect over internet" mode where the user enters/saves a relay address.
  Both devices must use the **same passphrase/`db_id`** (already required by
  pairing) so they land in the same relay room automatically — the user should
  not have to type IPs.
- Error messages must distinguish: relay unreachable, partner not present in
  room yet (ask them to open VeilDB and sync too), vs. auth/pairing failure.

### Zero-trust acceptance (must verify)
- The relay, given full packet capture, cannot recover any key, plaintext,
  index token, or operation content — only ciphertext `SyncMessage` sizes and
  timing. Add a test or a documented manual check demonstrating the relay only
  sees opaque bytes.
- Two `SyncEngine`s connected through an in-process mock relay converge to the
  same Merkle root (reuse the existing `MockBackend`-style test, inserting the
  rendezvous/pipe in the middle).

---

## CHANGE 3 — Fix the "Browse" button when opening a database

**Bug (real):** `pickDbPath()` in `frontend/src/App.tsx` (~line 621) opens a
**directory** picker (`directory: true`) and then **hardcodes the filename**
by appending `veildb.vdb`. So:
- Opening an **existing** database whose file is named anything other than
  `veildb.vdb`, or selecting the file directly, is impossible.
- The `catch` fallback calls `window.prompt(...)`, which is disabled/absent in
  the Tauri webview → the button silently does nothing when the dialog fails.

**Fix:**
1. Split the two intents:
   - **Init new DB:** keep a folder picker, but let the user confirm/edit the
     filename (default `veildb.vdb`) instead of silently appending it.
   - **Open existing DB:** use a **file** picker (`directory: false`) with a
     filter for the DB extension (e.g. `*.vdb`), returning the exact file path.
2. Make sure `bindings` grants the dialog capability for file open in
   `bindings/capabilities/default.json` (`tauri-plugin-dialog` is already
   initialized in `lib.rs`) so the dialog actually opens in the packaged app.
3. Replace the `window.prompt` fallback with a visible inline text input +
   error message (no silent failure). The path field must remain hand-editable.
4. Apply the same file-vs-folder correctness to `pickBackupPath` /
   `pickRestorePath` (restore picks an existing file; backup export picks a
   destination file/folder + filename).

**Acceptance:** on a packaged Tauri build, Browse opens a native dialog; an
existing `.vdb` with any name opens successfully; cancelling leaves the field
editable; no silent no-op.

---

## CHANGE 4 — Make it behave "like a normal DB": correctness & hardening

These are real defects found in the current code that undermine the "works
normally + stays secure" goal. Fix them as part of this work. Each needs a
regression test.

1. **Unbounded network allocation (DoS).** `LanBackend::read_message`
   (`crates/sync/src/lib.rs`) does `vec![0u8; len]` from an attacker-controlled
   `u32` length — a peer can request a ~4 GiB allocation per frame. Add a
   `MAX_FRAME_LEN` cap (e.g. 64 MiB) and return `SyncError` if exceeded, before
   allocating. Apply the same cap in `CloudBackend`.
2. **Stack overflow on long histories.** `validate_graph` → `detect_cycle`
   (`crates/integrity/src/lib.rs`) is recursive; chain depth = number of
   writes, so a few thousand writes overflow the stack during sync step 10 and
   `verify`. Rewrite cycle detection **iteratively** (explicit stack, like the
   adjacent `reachable_operations`).
3. **Device identity not bound to its key in the handshake.** In `SyncEngine::sync`
   the trust check uses `peer_device_id` taken from the message, while the
   signature only proves ownership of the presented `public_key`. Add a check
   that `peer_device_id == BLAKE3(public_key)` (that is how `device_id()` is
   derived locally) before the trust gate, and reject on mismatch.
4. **Dead verification step.** Step 8 ("Verify operation hashes") is a no-op
   (`let _ = h;`). Either implement a real check (e.g. confirm each received
   op's hash is one the peer advertised in its hash set) or delete the step and
   its protocol comment so the code stops claiming a guarantee it doesn't provide.
   Do not leave a verification step that verifies nothing.
5. **`verify_integrity` can't detect leaf tampering.** `verify_operations`
   (`crates/integrity`) only checks that parent references resolve; a tampered
   tip op re-hashes and passes. Make verification also re-check each op's
   **signature** against the signer's stored public key (same recompute-hash-
   with-empty-signature scheme used in sync step 9), so local
   `verify_integrity` actually detects tampering as the README claims.
6. **(Optional, perf — do only if time allows)** `put` scans all operations to
   compute the next sequence and `get` linearly scans all ops per lookup
   (`crates/core`, `crates/query`). For "normal DB" responsiveness on larger
   logs, back these with the existing SQLite indices (query max sequence per
   device via SQL; look up by stored index token via an indexed column) instead
   of full in-memory scans. Keep behavior identical; this is a speed change only.

**Do NOT** attempt to add HKDF forward-secrecy, `mlock`, Argon2 calibration,
checkpoints, or AES-SIV in this pass — they are larger redesigns and out of
scope. If you want to flag them, add a `shortcut:` comment, don't build them.

---

## Global acceptance checklist (run before declaring done)
- [ ] `cargo build --workspace` and `cargo test --workspace` pass (new tests included).
- [ ] `cargo clippy --workspace --all-targets` has no new warnings.
- [ ] `npm run build` (frontend) passes under TS strict mode.
- [ ] Same-Wi-Fi sync still works (LAN path untouched or improved).
- [ ] Two devices on **different networks** sync successfully through the relay,
      converging to the same Merkle root, with the relay seeing only opaque bytes.
- [ ] Browse opens an existing `.vdb` of any name in the packaged app.
- [ ] UI is monochrome, square-tiled, production-looking; tamper state is an
      unmissable red banner.
- [ ] Change-4 regression tests: oversized-frame rejected; deep chain
      (e.g. 50k ops) validates without stack overflow; handshake rejects a
      device_id that doesn't match its public key; `verify_integrity` detects a
      tampered op.

## What not to do
- Don't swap SQLite for redb/sled, don't introduce `libp2p`, don't restructure
  the workspace to the old `app/` layout.
- Don't change the `SyncMessage` wire format or `Operation`/`OperationId` shapes.
- Don't move crypto out of `crates/crypto` or let the relay/ frontend touch plaintext.
- Don't delete passing tests to make a change compile — fix the change.
