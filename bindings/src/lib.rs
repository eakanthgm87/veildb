//! VeilDB Tauri bindings.
//!
//! Tauri commands that map 1:1 to `core` methods. Depends only on
//! `core`. No direct storage/crypto/sync access.
//!
//! All errors crossing the Tauri boundary are serializable (`CoreError`
//! → JSON). Never expose private/master keys, raw key material,
//! SQLite connections, or internal storage structures across IPC.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use veildb_core::{
    IntegrityStatus, LogicalClock, PairingBundle, SecretString, SyncBackendKind, VeilDbCore,
};

/// The shared application state holding the core instance.
pub struct AppState {
    /// The core instance (protected by a mutex for thread safety).
    core: Mutex<Option<VeilDbCore>>,
    /// The database path.
    db_path: Mutex<Option<PathBuf>>,
}

impl AppState {
    /// Create a new empty app state.
    pub fn new() -> Self {
        Self {
            core: Mutex::new(None),
            db_path: Mutex::new(None),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// A serializable error response for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// The error message.
    pub message: String,
    /// The error code.
    pub code: Option<i32>,
    /// Whether this is an integrity/tamper error.
    pub is_integrity: bool,
}

impl From<veildb_core::error::CoreError> for ApiError {
    fn from(e: veildb_core::error::CoreError) -> Self {
        let msg = e.to_string();
        let is_integrity = msg.contains("integrity") || msg.contains("tamper");
        Self {
            message: msg,
            code: None,
            is_integrity,
        }
    }
}

/// A successful response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the operation succeeded.
    pub success: bool,
    /// The result data (if success).
    pub data: Option<T>,
    /// The error (if failure).
    pub error: Option<ApiError>,
}

impl<T> ApiResponse<T> {
    /// Create a success response.
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Create an error response.
    pub fn err(e: impl Into<ApiError>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(e.into()),
        }
    }
}

// Command module to avoid macro scoping issues
#[allow(dead_code)]
mod commands {
    use super::*;

    #[tauri::command]
    pub fn vdb_init(
        state: State<'_, AppState>,
        path: String,
        passphrase: String,
    ) -> ApiResponse<serde_json::Value> {
        let path_buf = PathBuf::from(&path);
        if path_buf.exists() {
            return ApiResponse::err(ApiError {
                message: "Database already exists".to_string(),
                code: Some(1),
                is_integrity: false,
            });
        }

        let secret = SecretString::new(passphrase);
        match VeilDbCore::init(&path_buf, secret) {
            Ok(core) => {
                let status = match core.status() {
                    Ok(s) => s,
                    Err(e) => return ApiResponse::err(ApiError::from(e)),
                };
                let mut guard = state.core.lock().unwrap();
                *guard = Some(core);
                *state.db_path.lock().unwrap() = Some(path_buf);
                ApiResponse::ok(serde_json::json!({
                    "db_id": hex(&status.db_id),
                    "device_id": hex(&status.self_device_id),
                    "key_version": status.key_version,
                }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_open(
        state: State<'_, AppState>,
        path: String,
        passphrase: String,
    ) -> ApiResponse<serde_json::Value> {
        let path_buf = PathBuf::from(&path);
        if !path_buf.exists() {
            return ApiResponse::err(ApiError {
                message: format!("Database not found: {}", path),
                code: Some(1),
                is_integrity: false,
            });
        }

        let secret = SecretString::new(passphrase);
        match VeilDbCore::init(&path_buf, secret) {
            Ok(core) => {
                let status = match core.status() {
                    Ok(s) => s,
                    Err(e) => return ApiResponse::err(ApiError::from(e)),
                };
                let mut guard = state.core.lock().unwrap();
                *guard = Some(core);
                *state.db_path.lock().unwrap() = Some(path_buf);
                ApiResponse::ok(serde_json::json!({
                    "db_id": hex(&status.db_id),
                    "device_id": hex(&status.self_device_id),
                    "key_version": status.key_version,
                }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_close(state: State<'_, AppState>) -> ApiResponse<()> {
        let mut guard = state.core.lock().unwrap();
        *guard = None;
        *state.db_path.lock().unwrap() = None;
        ApiResponse::ok(())
    }

    #[tauri::command]
    pub fn vdb_put(
        state: State<'_, AppState>,
        key: String,
        value: String,
    ) -> ApiResponse<serde_json::Value> {
        let mut guard = state.core.lock().unwrap();
        let core = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.put(&key, value.as_bytes()) {
            Ok(op_id) => ApiResponse::ok(serde_json::json!({
                "device_id": hex(&op_id.device_id),
                "sequence": op_id.sequence,
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_get(state: State<'_, AppState>, key: String) -> ApiResponse<String> {
        let guard = state.core.lock().unwrap();
        let core = guard.as_ref();
        let core = match core {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.get(&key) {
            Ok(value) => ApiResponse::ok(String::from_utf8_lossy(&value).to_string()),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_status(state: State<'_, AppState>) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.status() {
            Ok(status) => ApiResponse::ok(serde_json::json!({
                "db_id": hex(&status.db_id),
                "operation_count": status.operation_count,
                "merkle_root": hex(&status.merkle_root),
                "logical_clock": status.logical_clock.entries
                    .iter().map(|(d, c)| format!("{}:{}", hex(d), c))
                    .collect::<Vec<_>>(),
                "latest_snapshot_id": status.latest_snapshot_id,
                "snapshot_merkle_root": status.snapshot_merkle_root.map(|r| hex(&r)),
                "device_count": status.device_count,
                "self_device_id": hex(&status.self_device_id),
                "self_public_key": hex(&status.self_public_key),
                "key_version": status.key_version,
                "format_version": status.format_version,
                "bootstrapped": status.bootstrapped,
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_verify(state: State<'_, AppState>) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.verify_integrity() {
            Ok(status) => {
                let (label, is_ok) = match status {
                    IntegrityStatus::Verified => ("VERIFIED", true),
                    IntegrityStatus::Tampered => ("TAMPERED", false),
                    IntegrityStatus::Unverified => ("UNVERIFIED", false),
                };
                ApiResponse::ok(serde_json::json!({
                    "status": label,
                    "verified": is_ok,
                }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_query_at(
        state: State<'_, AppState>,
        clock: String,
    ) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        let clock = match parse_clock(&clock) {
            Ok(c) => c,
            Err(e) => return ApiResponse::err(ApiError {
                message: e,
                code: None,
                is_integrity: false,
            }),
        };
        match core.query_at(clock) {
            Ok(state) => {
                let entries: Vec<serde_json::Value> = state
                    .entries
                    .iter()
                    .map(|(k, v)| {
                        serde_json::json!({
                            "key": k,
                            "value": String::from_utf8_lossy(v),
                        })
                    })
                    .collect();
                ApiResponse::ok(serde_json::json!({
                    "clock": state.clock.entries
                        .iter().map(|(d, c)| format!("{}:{}", hex(d), c))
                        .collect::<Vec<_>>(),
                    "entries": entries,
                }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_log(state: State<'_, AppState>) -> ApiResponse<serde_json::Value> {
        let mut guard = state.core.lock().unwrap();
        let core = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.log(None) {
            Ok(log) => {
                let entries: Vec<serde_json::Value> = log
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "sequence": e.id.sequence,
                            "device_id": hex(&e.device_id),
                            "hash": hex(&e.hash),
                            "parent_count": e.parent_count,
                            "clock": e.clock.entries
                                .iter().map(|(d, c)| format!("{}:{}", hex(d), c))
                                .collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                ApiResponse::ok(serde_json::json!({ "operations": entries }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_list_devices(state: State<'_, AppState>) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.list_devices() {
            Ok(devices) => {
                let entries: Vec<serde_json::Value> = devices
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "device_id": hex(&d.device_id),
                            "public_key": hex(&d.public_key),
                            "trusted": d.trusted,
                            "approved_by": d.approved_by.map(|a| hex(&a)),
                            "created_at": d.created_at,
                        })
                    })
                    .collect();
                ApiResponse::ok(serde_json::json!({ "devices": entries }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_trust_device(
        state: State<'_, AppState>,
        public_key: String,
    ) -> ApiResponse<serde_json::Value> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        let pk = match parse_hex(&public_key) {
            Ok(p) => p.to_vec(),
            Err(e) => return ApiResponse::err(ApiError {
                message: e,
                code: None,
                is_integrity: false,
            }),
        };
        match core_ref.trust_device(&pk) {
            Ok(entry) => ApiResponse::ok(serde_json::json!({
                "device_id": hex(&entry.device_id),
                "trusted": entry.trusted,
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_revoke_device(
        state: State<'_, AppState>,
        device_id: String,
    ) -> ApiResponse<()> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        let id = match parse_hex(&device_id) {
            Ok(p) => p.to_vec(),
            Err(e) => return ApiResponse::err(ApiError {
                message: e,
                code: None,
                is_integrity: false,
            }),
        };
        match core_ref.revoke_device(&id) {
            Ok(()) => ApiResponse::ok(()),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_backup(state: State<'_, AppState>, output: String) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.backup(&PathBuf::from(&output)) {
            Ok(archive) => ApiResponse::ok(serde_json::json!({
                "format_version": archive.format_version,
                "db_id": hex(&archive.db_id),
                "merkle_root": hex(&archive.merkle_root),
                "path": output,
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_restore(state: State<'_, AppState>, archive: String) -> ApiResponse<()> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core_ref.restore(&PathBuf::from(&archive)) {
            Ok(()) => ApiResponse::ok(()),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_snapshot(state: State<'_, AppState>) -> ApiResponse<i64> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core_ref.snapshot() {
            Ok(id) => ApiResponse::ok(id),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_sync_lan(
        state: State<'_, AppState>,
        addr: String,
    ) -> ApiResponse<serde_json::Value> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        let backend = SyncBackendKind::Lan { addr };

        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(core_ref.sync(backend)) {
            Ok(report) => ApiResponse::ok(serde_json::json!({
                "operations_received": report.operations_received,
                "operations_sent": report.operations_sent,
                "operations_merged": report.operations_merged,
                "merkle_root": hex(&report.merkle_root),
                "success": report.success,
                "message": report.message,
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    /// Accept ONE incoming TCP sync session (server / listen side).
    ///
    /// Blocks until a peer connects and the handshake completes. Use
    /// `vdb_sync_lan` on the dialing side.
    #[tauri::command]
    pub fn vdb_sync_listen(
        state: State<'_, AppState>,
        addr: String,
    ) -> ApiResponse<serde_json::Value> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(core_ref.sync_listen_once(&addr)) {
            Ok(report) => ApiResponse::ok(serde_json::json!({
                "operations_received": report.operations_received,
                "operations_sent": report.operations_sent,
                "operations_merged": report.operations_merged,
                "merkle_root": hex(&report.merkle_root),
                "success": report.success,
                "message": report.message,
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    /// Export a signed pairing bundle for a new device.
    ///
    /// Returns the bundle as pretty JSON. The joining device presents
    /// it via `vdb_import_pairing`.
    #[tauri::command]
    pub fn vdb_export_pairing(
        state: State<'_, AppState>,
    ) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core_ref = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core_ref.export_pairing() {
            Ok(bundle) => {
                let json = match bundle.to_json() {
                    Ok(j) => j,
                    Err(e) => return ApiResponse::err(ApiError::from(e)),
                };
                ApiResponse::ok(serde_json::json!({
                    "db_id": hex(&bundle.db_id),
                    "salt": hex(&bundle.salt),
                    "device_id": hex(&bundle.device_id),
                    "approver_public_key": hex(&bundle.approver_public_key),
                    "signature": hex(&bundle.signature),
                    "json": json,
                }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    /// Import a pairing bundle and approve the inviting device.
    ///
    /// Takes the bundle's serialized JSON (as exported by
    /// `vdb_export_pairing`). If this device's database is still
    /// empty and belongs to a different database, it adopts the
    /// inviting database's identity (db_id + KDF salt).
    #[tauri::command]
    pub fn vdb_import_pairing(
        state: State<'_, AppState>,
        bundle_json: String,
    ) -> ApiResponse<serde_json::Value> {
        let bundle = match PairingBundle::from_json(&bundle_json) {
            Ok(b) => b,
            Err(e) => return ApiResponse::err(ApiError::from(e)),
        };
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core_ref.import_pairing(&bundle) {
            Ok(entry) => ApiResponse::ok(serde_json::json!({
                "device_id": hex(&entry.device_id),
                "public_key": hex(&entry.public_key),
                "trusted": entry.trusted,
                "approved_by": entry.approved_by.map(|a| hex(&a)),
                "created_at": entry.created_at,
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    /// Discover peers on the LAN via UDP multicast.
    #[tauri::command]
    pub fn vdb_discover(
        state: State<'_, AppState>,
        timeout_ms: u64,
    ) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core_ref = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(core_ref.discover_peers(timeout_ms)) {
            Ok(peers) => {
                let list: Vec<serde_json::Value> = peers.iter().map(|p| {
                    serde_json::json!({
                        "device_id": hex(&p.device_id),
                        "public_key": hex(&p.public_key),
                        "sync_addr": p.sync_addr.to_string(),
                    })
                }).collect();
                ApiResponse::ok(serde_json::json!({ "peers": list }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    /// Query the persistent merge log (deterministic conflict resolutions).
    #[tauri::command]
    pub fn vdb_merges(state: State<'_, AppState>) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core_ref = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core_ref.merge_log() {
            Ok(entries) => {
                let list: Vec<serde_json::Value> = entries.iter().map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "key": e.key,
                        "winner": format!("{}.{}", hex(&e.winner.device_id), e.winner.sequence),
                        "loser": e.loser.map(|l| format!("{}.{}", hex(&l.device_id), l.sequence)),
                        "rule": e.rule,
                        "created_at": e.created_at,
                    })
                }).collect();
                ApiResponse::ok(serde_json::json!({ "entries": list }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_rotate_key(state: State<'_, AppState>) -> ApiResponse<serde_json::Value> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core_ref.rotate_key() {
            Ok(new_version) => ApiResponse::ok(serde_json::json!({
                "key_version": new_version,
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_get_dag(state: State<'_, AppState>) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.get_dag() {
            Ok(dag) => {
                let nodes: Vec<serde_json::Value> = dag.nodes.iter().map(|n| {
                    serde_json::json!({
                        "id": n.id,
                        "device_id": hex(&n.device_id),
                        "sequence": n.sequence,
                        "hash": hex(&n.hash),
                        "parents": n.parents.iter().map(|p| hex(p)).collect::<Vec<_>>(),
                        "signature_status": n.signature_status,
                        "clock": n.clock,
                    })
                }).collect();
                let edges: Vec<serde_json::Value> = dag.edges.iter().map(|e| {
                    serde_json::json!({
                        "from": hex(&e.from),
                        "to": hex(&e.to),
                    })
                }).collect();
                ApiResponse::ok(serde_json::json!({
                    "nodes": nodes,
                    "edges": edges,
                }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    #[tauri::command]
    pub fn vdb_get_merkle_tree(state: State<'_, AppState>) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let core = match guard.as_ref() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match core.get_merkle_tree() {
            Ok(tree) => {
                let leaves: Vec<serde_json::Value> = tree.leaves.iter().map(|l| {
                    serde_json::json!({
                        "id": l.id,
                        "hash": hex(&l.hash),
                        "level": l.level,
                        "index": l.index,
                        "is_leaf": l.is_leaf,
                    })
                }).collect();
                let internal: Vec<serde_json::Value> = tree.internal_nodes.iter().map(|n| {
                    serde_json::json!({
                        "id": n.id,
                        "hash": hex(&n.hash),
                        "level": n.level,
                        "index": n.index,
                        "is_leaf": n.is_leaf,
                    })
                }).collect();
                ApiResponse::ok(serde_json::json!({
                    "root": hex(&tree.root),
                    "leaves": leaves,
                    "internal_nodes": internal,
                }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }

    /// Dev-only: corrupt an operation's ciphertext.
    ///
    /// This is ONLY available in debug builds. It flips bytes in the
    /// operation's ciphertext to simulate tampering. Never callable
    /// from the CLI's normal command set and not a `core` method usable
    /// outside dev builds.
    #[cfg(debug_assertions)]
    #[tauri::command]
    pub fn vdb_dev_corrupt_operation(
        state: State<'_, AppState>,
        device_id: String,
        sequence: u64,
    ) -> ApiResponse<()> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        let id = match parse_hex(&device_id) {
            Ok(p) => p,
            Err(e) => return ApiResponse::err(ApiError {
                message: e,
                code: None,
                is_integrity: false,
            }),
        };
        match core_ref.dev_corrupt_operation(&id, sequence) {
            Ok(()) => ApiResponse::ok(()),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }
}

use commands::*;

fn not_initialized() -> ApiError {
    ApiError {
        message: "Database not initialized or opened".to_string(),
        code: Some(1),
        is_integrity: false,
    }
}

fn parse_hex(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("Expected 64 hex chars, got {}", s.len()));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("Invalid hex: {e}"))?;
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_clock(s: &str) -> Result<LogicalClock, String> {
    let mut clock = LogicalClock::new();
    for part in s.split(',') {
        let (device, counter) = part
            .split_once(':')
            .ok_or_else(|| format!("Invalid clock format: {part}"))?;
        let device_bytes = parse_hex(device)?;
        let counter: u64 = counter.parse().map_err(|e| format!("Invalid counter: {e}"))?;
        clock.entries.push((device_bytes, counter));
    }
    clock.entries.sort();
    Ok(clock)
}

/// Setup the Tauri plugin.
pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let log_file = std::env::current_exe()
        .unwrap_or_default()
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("veildb-debug.log");

    let mut f = std::fs::File::create(&log_file)?;
    writeln!(f, "=== VeilDB Setup ===")?;
    writeln!(f, "Working dir: {:?}", std::env::current_dir())?;
    writeln!(f, "Exe path: {:?}", std::env::current_exe())?;

    // Window is created from tauri.conf.json — no programmatic creation needed.
    writeln!(f, "Window configured via tauri.conf.json")?;

    // Manage app state.
    app.manage(AppState::new());

    writeln!(f, "Setup complete.")?;

    Ok(())
}

/// Register all Tauri commands.
pub fn run() {
    let result = tauri::Builder::default()
        .setup(setup)
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            vdb_init,
            vdb_open,
            vdb_close,
            vdb_put,
            vdb_get,
            vdb_status,
            vdb_verify,
            vdb_query_at,
            vdb_log,
            vdb_list_devices,
            vdb_trust_device,
            vdb_revoke_device,
            vdb_backup,
            vdb_restore,
            vdb_snapshot,
            vdb_sync_lan,
            vdb_sync_listen,
            vdb_export_pairing,
            vdb_import_pairing,
            vdb_discover,
            vdb_merges,
            vdb_rotate_key,
            vdb_get_dag,
            vdb_get_merkle_tree,
            #[cfg(debug_assertions)]
            vdb_dev_corrupt_operation,
        ])
        .run(tauri::generate_context!());

    if let Err(e) = result {
        let log_file = std::env::current_exe()
            .unwrap_or_default()
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("veildb-error.log");
        let _ = std::fs::write(&log_file, format!("Tauri run error: {e}\n"));
        eprintln!("error while running tauri application: {e}");
    }
}