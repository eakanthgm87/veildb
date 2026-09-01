//! VeilDB Tauri bindings.
//!
//! Tauri commands that map 1:1 to `core` methods. Depends only on
//! `core`. No direct storage/crypto/sync access.
//!
//! All errors crossing the Tauri boundary are serializable (`CoreError`
//! → JSON). Never expose private/master keys, raw key material,
//! SQLite connections, or internal storage structures across IPC.
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use veildb_core::{
    IntegrityStatus, LogicalClock, PairingBundle, SecretString, VeilDbCore,
};
use veildb_sync::SyncBackend;
/// The TCP port the GUI's background sync listener binds to. Every
/// VeilDB app instance on the LAN listens here, so a one-click sync
/// never requires the peer to run any command.
pub const SYNC_PORT: u16 = 8443;
/// The discovery beacon interval.
const BEACON_INTERVAL_MS: u64 = 1500;
/// A shared tokio runtime for all async work (sync sessions, the
/// background listener, the discovery beacon). Created lazily.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("failed to create tokio runtime"))
}
/// The shared application state holding the core instance.
pub struct AppState {
    /// The core instance (protected by a mutex for thread safety).
    core: Mutex<Option<VeilDbCore>>,
    /// The database path.
    db_path: Mutex<Option<PathBuf>>,
    /// The passphrase used to open the current database (kept for
    /// pairing operations; zeroized on drop).
    passphrase: Mutex<Option<SecretString>>,
    /// The running discovery beacon (shutdown sender + task handle).
    beacon: Mutex<Option<(tokio::sync::mpsc::Sender<()>, tokio::task::JoinHandle<()>)>>,
}
impl AppState {
    /// Create a new empty app state.
    pub fn new() -> Self {
        Self {
            core: Mutex::new(None),
            db_path: Mutex::new(None),
            passphrase: Mutex::new(None),
            beacon: Mutex::new(None),
        }
    }
}
impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
/// Append a line to the debug log next to the executable.
fn append_log(msg: &str) {
    use std::io::Write;
    let log_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("veildb-debug.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}
/// Stop the discovery beacon, if one is running.
fn stop_beacon(state: &AppState) {
    if let Some((tx, handle)) = state.beacon.lock().unwrap().take() {
        let _ = tx.send(());
        handle.abort();
    }
}
/// (Re)start the discovery beacon for the currently open database so
/// other devices can discover this machine with one click. No-op when
/// no database is open.
fn start_beacon(state: &AppState) {
    stop_beacon(state);
    let guard = state.core.lock().unwrap();
    if let Some(core) = guard.as_ref() {
        match runtime().block_on(core.spawn_discovery_beacon(SYNC_PORT, BEACON_INTERVAL_MS)) {
            Ok(handle) => {
                *state.beacon.lock().unwrap() = Some(handle);
                append_log(&format!("discovery beacon started (sync port {SYNC_PORT})"));
            }
            Err(e) => append_log(&format!("failed to start discovery beacon: {e}")),
        }
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
        state: State<'_, Arc<AppState>>,
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
        let secret = SecretString::new(passphrase.clone());
        match VeilDbCore::init(&path_buf, secret) {
            Ok(core) => {
                let status = match core.status() {
                    Ok(s) => s,
                    Err(e) => return ApiResponse::err(ApiError::from(e)),
                };
                let mut guard = state.core.lock().unwrap();
                *guard = Some(core);
                *state.db_path.lock().unwrap() = Some(path_buf);
                *state.passphrase.lock().unwrap() = Some(SecretString::new(passphrase));
                drop(guard);
                start_beacon(&state);
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
        state: State<'_, Arc<AppState>>,
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
        let secret = SecretString::new(passphrase.clone());
        match VeilDbCore::init(&path_buf, secret) {
            Ok(core) => {
                let status = match core.status() {
                    Ok(s) => s,
                    Err(e) => return ApiResponse::err(ApiError::from(e)),
                };
                let mut guard = state.core.lock().unwrap();
                *guard = Some(core);
                *state.db_path.lock().unwrap() = Some(path_buf);
                *state.passphrase.lock().unwrap() = Some(SecretString::new(passphrase));
                drop(guard);
                start_beacon(&state);
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
    pub fn vdb_close(state: State<'_, Arc<AppState>>) -> ApiResponse<()> {
        stop_beacon(&state);
        let mut guard = state.core.lock().unwrap();
        *guard = None;
        *state.db_path.lock().unwrap() = None;
        *state.passphrase.lock().unwrap() = None;
        ApiResponse::ok(())
    }
    #[tauri::command]
    pub fn vdb_put(
        state: State<'_, Arc<AppState>>,
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
    pub fn vdb_get(state: State<'_, Arc<AppState>>, key: String) -> ApiResponse<String> {
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
    pub fn vdb_status(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
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
    pub fn vdb_verify(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
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
        state: State<'_, Arc<AppState>>,
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
    pub fn vdb_log(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
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
    pub fn vdb_list_devices(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
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
        state: State<'_, Arc<AppState>>,
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
        state: State<'_, Arc<AppState>>,
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
    pub fn vdb_backup(state: State<'_, Arc<AppState>>, output: String) -> ApiResponse<serde_json::Value> {
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
    pub fn vdb_restore(state: State<'_, Arc<AppState>>, archive: String) -> ApiResponse<()> {
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
    pub fn vdb_snapshot(state: State<'_, Arc<AppState>>) -> ApiResponse<i64> {
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
        state: State<'_, Arc<AppState>>,
        addr: String,
    ) -> ApiResponse<serde_json::Value> {
        // Back-compat alias: the manual-address one-click sync.
        vdb_sync_now(state, Some(addr))
    }
    /// One-click sync: dial the given address, or discover LAN peers
    /// via UDP multicast when no address is given. Handles pairing
    /// automatically (proof of shared passphrase + identity adoption
    /// for an empty database) and then runs the CRDT sync.
    #[tauri::command]
    pub fn vdb_sync_now(
        state: State<'_, Arc<AppState>>,
        addr: Option<String>,
    ) -> ApiResponse<serde_json::Value> {
        let mut guard = state.core.lock().unwrap();
        let core = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match runtime().block_on(core.sync_auto(addr)) {
            Ok(r) => ApiResponse::ok(serde_json::json!({
                "peer_addr": r.peer_addr,
                "peer_device_id": r.peer_device_id.map(|d| hex(&d)),
                "paired": r.paired,
                "adopted": r.adopted,
                "discovered": r.discovered.iter().map(|p| serde_json::json!({
                    "device_id": hex(&p.device_id),
                    "public_key": hex(&p.public_key),
                    "db_id": hex(&p.db_id),
                    "sync_addr": p.sync_addr.to_string(),
                })).collect::<Vec<_>>(),
                "success": r.success,
                "message": r.message,
                "operations_received": r.report.as_ref().map(|x| x.operations_received),
                "operations_sent": r.report.as_ref().map(|x| x.operations_sent),
                "operations_merged": r.report.as_ref().map(|x| x.operations_merged),
                "merkle_root": r.report.as_ref().map(|x| hex(&x.merkle_root)),
            })),
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }
    /// Info about this machine's sync endpoint for the GUI (port,
    /// listener + beacon status, best-effort LAN IP).
    #[tauri::command]
    pub fn vdb_sync_info(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
        let beacon_running = state.beacon.lock().unwrap().is_some();
        let db_open = state.core.lock().unwrap().is_some();
        let local_ip = detect_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
        ApiResponse::ok(serde_json::json!({
            "sync_port": SYNC_PORT,
            "listening": true,
            "beacon_running": beacon_running,
            "db_open": db_open,
            "local_ip": local_ip,
        }))
    }
    /// Accept ONE incoming TCP sync session (server / listen side).
    ///
    /// Binds a temporary listener — the GUI normally relies on the
    /// background listener started at app launch instead.
    #[tauri::command]
    pub fn vdb_sync_listen(
        state: State<'_, Arc<AppState>>,
        addr: String,
    ) -> ApiResponse<serde_json::Value> {
        let mut guard = state.core.lock().unwrap();
        let core_ref = match guard.as_mut() {
            Some(c) => c,
            None => return ApiResponse::err(not_initialized()),
        };
        match runtime().block_on(core_ref.sync_listen_auto(&addr, || {})) {
            Ok(r) => ApiResponse::ok(serde_json::json!({
                "peer_addr": r.peer_addr,
                "paired": r.paired,
                "adopted": r.adopted,
                "success": r.success,
                "message": r.message,
                "operations_received": r.report.as_ref().map(|x| x.operations_received),
                "operations_sent": r.report.as_ref().map(|x| x.operations_sent),
                "operations_merged": r.report.as_ref().map(|x| x.operations_merged),
                "merkle_root": r.report.as_ref().map(|x| hex(&x.merkle_root)),
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
        state: State<'_, Arc<AppState>>,
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
        state: State<'_, Arc<AppState>>,
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
            Ok(entry) => {
                // The device may have adopted a new database identity
                // — refresh the discovery beacon so announcements
                // carry the adopted db_id.
                drop(guard);
                start_beacon(&state);
                ApiResponse::ok(serde_json::json!({
                    "device_id": hex(&entry.device_id),
                    "public_key": hex(&entry.public_key),
                    "trusted": entry.trusted,
                    "approved_by": entry.approved_by.map(|a| hex(&a)),
                    "created_at": entry.created_at,
                }))
            }
            Err(e) => ApiResponse::err(ApiError::from(e)),
        }
    }
    /// Discover VeilDB peers on the LAN via UDP multicast. Returns
    /// every verified peer (with its db_id) so the GUI can show which
    /// ones already belong to this database and which would be joined
    /// via auto-pairing.
    #[tauri::command]
    pub fn vdb_discover(
        state: State<'_, Arc<AppState>>,
        timeout_ms: u64,
    ) -> ApiResponse<serde_json::Value> {
        let guard = state.core.lock().unwrap();
        let my_db: Option<[u8; 32]> = guard.as_ref().map(|c| {
            c.status().map(|s| s.db_id).unwrap_or([0u8; 32])
        });
        let rt = runtime();
        let peers = match rt.block_on(veildb_sync::discovery::discover_all(
            std::time::Duration::from_millis(timeout_ms),
        )) {
            Ok(p) => p,
            Err(e) => {
                return ApiResponse::err(ApiError {
                    message: e.to_string(),
                    code: None,
                    is_integrity: false,
                })
            }
        };
        let list: Vec<serde_json::Value> = peers
            .iter()
            .map(|p| {
                serde_json::json!({
                    "device_id": hex(&p.device_id),
                    "public_key": hex(&p.public_key),
                    "db_id": hex(&p.db_id),
                    "sync_addr": p.sync_addr.to_string(),
                    "same_db": my_db.map(|m| m == p.db_id).unwrap_or(false),
                })
            })
            .collect();
        ApiResponse::ok(serde_json::json!({ "peers": list }))
    }
    /// Query the persistent merge log (deterministic conflict resolutions).
    #[tauri::command]
    pub fn vdb_merges(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
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
    pub fn vdb_rotate_key(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
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
    pub fn vdb_get_dag(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
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
    pub fn vdb_get_merkle_tree(state: State<'_, Arc<AppState>>) -> ApiResponse<serde_json::Value> {
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
        state: State<'_, Arc<AppState>>,
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
/// Best-effort detection of this machine's LAN IP (for display in
/// the GUI). Uses the connected-UDP-socket trick: no packet is sent.
fn detect_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}
/// Serve ONE inbound sync session on the background listener:
/// locks the core (if a DB is open), runs probe → auto-pair → sync.
/// When no database is open the peer gets a clear error frame.
///
/// Runs inside `spawn_blocking`: the core mutex is held for the whole
/// session (same as a foreground `vdb_sync_now`), which serializes
/// concurrent sessions but keeps command handlers safe.
///
/// If the core is already locked (this machine is itself mid-sync as
/// the dialer, or two peers clicked Sync at the same instant), we do
/// NOT block forever — we reply with a clean error instead. That turns
/// what would otherwise be a deadlock + "connection reset" into a
/// clear, retryable message.
fn handle_incoming_session(state: Arc<AppState>, stream: tokio::net::TcpStream, peer: String) {
    // If the core is currently busy (a foreground sync holds the lock),
    // give it a generous grace period to finish before rejecting — this
    // lets the very common "both users click within a second" case
    // succeed instead of erroring. We never block indefinitely: a pure
    // blocking lock here could deadlock against an outbound sync. A
    // third call that still can't get the lock is rejected with the
    // shared busy message; the dialing side retries a few times, so a
    // short-lived foreground sync self-heals without user action.
    let mut guard = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while guard.is_none() {
        match state.core.try_lock() {
            Ok(g) => guard = Some(g),
            Err(_) => {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    let mut guard = match guard {
        Some(g) => g,
        None => {
            // IMPORTANT: drain the dialer's probe before closing.
            // If we close the socket with unread data still buffered,
            // macOS sends a TCP RST and the dialer sees
            // "Connection reset by peer (os error 54)" rather than our
            // clean busy message.
            let send_busy = async {
                let mut backend = veildb_sync::LanBackend::from_stream(stream);
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(1000),
                    backend.receive(),
                )
                .await;
                backend
                    .send(veildb_sync::SyncMessage::Error {
                        message: veildb_core::VeilDbCore::MSG_PEER_BUSY.to_string(),
                    })
                    .await
            };
            let _ = runtime().block_on(send_busy);
            append_log(&format!(
                "sync session from {peer} rejected: another sync is in progress on this peer"
            ));
            return;
        }
    };
    match guard.as_mut() {
        None => {
            // Same drain-before-close trick: consume the probe so the
            // close is a clean FIN, not an RST.
            let send_err = async {
                let mut backend = veildb_sync::LanBackend::from_stream(stream);
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(1000),
                    backend.receive(),
                )
                .await;
                backend
                    .send(veildb_sync::SyncMessage::Error {
                        message: "No database is open on this peer — open a database and try again."
                            .to_string(),
                    })
                    .await
            };
            let _ = runtime().block_on(send_err);
            append_log(&format!("sync session from {peer} rejected: no database open"));
        }
        Some(core) => match runtime().block_on(core.serve_sync_stream(stream)) {
            Ok(r) => {
                append_log(&format!(
                    "inbound sync from {peer}: paired={} adopted={} sent={} recv={} merged={}",
                    r.paired,
                    r.adopted,
                    r.report.as_ref().map(|x| x.operations_sent).unwrap_or(0),
                    r.report.as_ref().map(|x| x.operations_received).unwrap_or(0),
                    r.report.as_ref().map(|x| x.operations_merged).unwrap_or(0),
                ));
            }
            Err(e) => append_log(&format!("inbound sync from {peer} failed: {e}")),
        },
    }
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
    // Manage app state (Arc so the background listener can clone it).
    let state = Arc::new(AppState::new());
    app.manage(state.clone());
    // Background sync listener: binds SYNC_PORT for the whole app
    // lifetime so this machine can RECEIVE one-click sync sessions
    // without the user running any command. A second instance on the
    // same machine would fail to bind — that's fine (log and skip).
    {
        let state_for_listener = state.clone();
        std::thread::Builder::new()
            .name("veildb-sync-listener".into())
            .spawn(move || {
                runtime().block_on(async move {
                    match tokio::net::TcpListener::bind(("0.0.0.0", SYNC_PORT)).await {
                        Ok(listener) => {
                            append_log(&format!(
                                "background sync listener started on 0.0.0.0:{SYNC_PORT}"
                            ));
                            loop {
                                match listener.accept().await {
                                    Ok((stream, peer)) => {
                                        append_log(&format!(
                                            "inbound sync connection from {peer}"
                                        ));
                                        let st = state_for_listener.clone();
                                        let peer_s = peer.to_string();
                                        tokio::task::spawn_blocking(move || {
                                            handle_incoming_session(st, stream, peer_s)
                                        });
                                    }
                                    Err(e) => {
                                        append_log(&format!("listener accept error: {e}"));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            append_log(&format!(
                                "background sync listener could not bind port {SYNC_PORT}: {e} \
                                 (another VeilDB instance may be running)"
                            ));
                        }
                    }
                });
            })?;
    }
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
            vdb_sync_now,
            vdb_sync_info,
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
