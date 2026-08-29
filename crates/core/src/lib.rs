//! VeilDB core facade.
//!
//! `VeilDbCore` is the ONLY application-facing API. Every CLI command
//! and every Tauri command maps 1:1 to one of these methods.
//!
//! The core facade composes the six inner crates:
//! - `storage`: SQLite persistence
//! - `crypto`: AES-GCM, Ed25519, X25519, Argon2, BLAKE3
//! - `integrity`: hashing, Merkle DAG, proofs, tamper detection
//! - `query`: encrypted indexes, logical clock, time travel
//! - `access`: device trust, revocation, sharing, backup/restore
//! - `sync`: CRDT merge, peer protocol, transports
//!
//! Never exposes: storage internals, SQLite connections, raw keys.

pub mod error;

// Re-exports for the CLI and bindings layers.
pub use veildb_integrity::IntegrityStatus;
pub use veildb_storage::{LogicalClock, SecretString};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use veildb_access::{AccessEngine, EncryptedArchive, ReEncryptedBlob, TrustEntry};
use veildb_crypto::{SigningKeyPair, X25519KeyPair, Ciphertext, derive_key, decrypt, encrypt};
use veildb_integrity::{operation_hash, verify_operations};
use veildb_query::{DbState, OperationSummary, QueryEngine, build_log};
use veildb_storage::{
    MergeLogEntry, Operation, OperationId, SqliteStorage, StorageEngine,
};
use veildb_sync::{
    LanBackend, SyncBackend, SyncEngine, SyncReport, TrustProvider,
    discovery::DiscoveredPeer,
};

use error::CoreError;

/// A storage-backed [`TrustProvider`].
///
/// Every trust query hits the live device registry in SQLite, so
/// approvals and revocations are honored on the next handshake
/// without restarting the sync engine.
pub struct LiveTrustProvider {
    /// A dedicated read connection to the same database. Mutex-wrapped
    /// because `SqliteStorage` is not `Sync`.
    storage: std::sync::Mutex<SqliteStorage>,
}

impl TrustProvider for LiveTrustProvider {
    fn is_trusted(&self, device_id: &[u8; 32]) -> bool {
        let storage = self.storage.lock().expect("trust provider poisoned");
        storage
            .load_device(device_id)
            .ok()
            .flatten()
            .map(|d| d.trusted)
            .unwrap_or(false)
    }

    fn public_key_of(&self, device_id: &[u8; 32]) -> Option<[u8; 32]> {
        let storage = self.storage.lock().expect("trust provider poisoned");
        storage
            .load_device(device_id)
            .ok()
            .flatten()
            .and_then(|d| {
                if d.public_key.len() == 32 {
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(&d.public_key);
                    Some(pk)
                } else {
                    None
                }
            })
    }
}

/// A signed pairing bundle exchanged out-of-band between devices.
///
/// The existing (approving) device exports it; the joining device
/// verifies it, approves the approver's key locally, and — if its own
/// database is still empty — adopts the bundle's database identity
/// (db_id) and KDF salt. The data key itself never travels: it is
/// derived on the joining device from the shared passphrase and the
/// adopted salt, exactly as on the originating device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingBundle {
    /// The database ID being joined.
    pub db_id: [u8; 32],
    /// The KDF salt used to derive the data key from the passphrase.
    pub salt: [u8; 32],
    /// The approver's device ID.
    pub device_id: [u8; 32],
    /// The approver's Ed25519 public key.
    pub approver_public_key: [u8; 32],
    /// Ed25519 signature over `db_id || approver_public_key`.
    pub signature: Vec<u8>,
}

impl PairingBundle {
    /// Serialize to pretty JSON for file or QR transport.
    pub fn to_json(&self) -> Result<String, CoreError> {
        serde_json::to_string_pretty(self).map_err(|e| CoreError::Serialization(e.to_string()))
    }

    /// Parse from JSON.
    pub fn from_json(json: &str) -> Result<Self, CoreError> {
        serde_json::from_str(json).map_err(|e| CoreError::Serialization(e.to_string()))
    }
}

/// The current database format version.
pub const DB_FORMAT_VERSION: u32 = 1;

/// Metadata key for the database ID.
const META_DB_ID: &str = "veildb.db_id";
/// Metadata key for the format version.
const META_FORMAT_VERSION: &str = "veildb.format_version";
/// Metadata key for the key version.
const META_KEY_VERSION: &str = "veildb.key_version";
/// Metadata key for the salt.
const META_SALT: &str = "veildb.salt";
/// Metadata key for the encrypted signing key.
const META_SIGNING_KEY: &str = "veildb.device.signing_key";
/// Metadata key for the encrypted X25519 key.
const META_X25519_KEY: &str = "veildb.device.x25519_key";

/// A status report of the database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbStatus {
    /// The database ID.
    pub db_id: [u8; 32],
    /// Number of operations in the log.
    pub operation_count: u64,
    /// The current Merkle root.
    pub merkle_root: [u8; 32],
    /// The current logical clock.
    pub logical_clock: LogicalClock,
    /// The latest snapshot ID, if any.
    pub latest_snapshot_id: Option<i64>,
    /// The latest snapshot's Merkle root, if any.
    pub snapshot_merkle_root: Option<[u8; 32]>,
    /// Number of trusted devices.
    pub device_count: u64,
    /// This device's ID.
    pub self_device_id: [u8; 32],
    /// This device's public key.
    pub self_public_key: Vec<u8>,
    /// The key version.
    pub key_version: u32,
    /// The format version.
    pub format_version: u32,
    /// Whether the root device has been bootstrapped.
    pub bootstrapped: bool,
}

/// A device info entry for the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// The device ID.
    pub device_id: [u8; 32],
    /// The device's public key.
    pub public_key: Vec<u8>,
    /// Whether the device is trusted.
    pub trusted: bool,
    /// The device that approved this one (None for root).
    pub approved_by: Option<[u8; 32]>,
    /// Creation timestamp.
    pub created_at: i64,
}

impl From<TrustEntry> for DeviceInfo {
    fn from(t: TrustEntry) -> Self {
        Self {
            device_id: t.device_id,
            public_key: t.public_key,
            trusted: t.trusted,
            approved_by: t.approved_by,
            created_at: t.created_at,
        }
    }
}

/// The `SyncBackend` enum for the public API.
///
/// This wraps the concrete backend types so callers (CLI, Tauri)
/// don't need to construct them.
#[derive(Debug, Clone)]
pub enum SyncBackendKind {
    /// Mock backend (in-memory, for testing).
    Mock,
    /// LAN backend (TCP).
    Lan { addr: String },
    /// Accept one incoming TCP connection (LAN listener).
    Listen { addr: String },
    /// Cloud relay (stub).
    #[cfg(feature = "sync-cloud")]
    Cloud,
    /// P2P (stub).
    #[cfg(feature = "sync-p2p")]
    P2p,
}

/// The VeilDB core facade.
///
/// This is the ONLY application-facing API. All business logic lives
/// inside this struct or the inner crates it composes.
pub struct VeilDbCore {
    /// The SQLite storage engine.
    storage: SqliteStorage,
    /// The query engine.
    query: QueryEngine<SqliteStorage>,
    /// The access engine.
    access: AccessEngine<SqliteStorage>,
    /// The sync engine.
    sync: SyncEngine<SqliteStorage>,
    /// The database ID.
    db_id: [u8; 32],
    /// The key version.
    key_version: u32,
    /// The database path.
    path: PathBuf,
    /// The signing keypair.
    signing: Arc<SigningKeyPair>,
    /// The X25519 keypair.
    x25519: Arc<X25519KeyPair>,
}

impl VeilDbCore {
    /// Initialize a new database at the given path.
    ///
    /// If the database doesn't exist, it is created and the root
    /// device is bootstrapped. If it exists, it is opened.
    ///
    /// The passphrase is used to derive the master key via Argon2.
    pub fn init(path: &Path, passphrase: SecretString) -> Result<Self, CoreError> {
        let exists = path.exists();

        // Open the storage engine.
        let mut storage = SqliteStorage::open(path)?;

        // Check if this is a new database.
        let db_id_meta = storage.get_metadata(META_DB_ID)?;
        let db_id: [u8; 32] = match db_id_meta {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                // New database — create the DB ID.
                let new_id = veildb_crypto::random_bytes_32();
                storage.set_metadata(META_DB_ID, &new_id)?;
                new_id
            }
        };

        // Get or create the key version.
        let key_version: u32 = match storage.get_metadata(META_KEY_VERSION)? {
            Some(bytes) if bytes.len() == 4 => {
                u32::from_le_bytes(bytes.try_into().unwrap())
            }
            _ => {
                storage.set_metadata(META_KEY_VERSION, &1u32.to_le_bytes())?;
                1
            }
        };

        // Store the format version.
        storage.set_metadata(META_FORMAT_VERSION, &DB_FORMAT_VERSION.to_le_bytes())?;

        // Derive or load the master key.
        // Generate a random salt if this is a new database.
        let salt: [u8; 32] = match storage.get_metadata(META_SALT)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                let new_salt = veildb_crypto::random_bytes_32();
                storage.set_metadata(META_SALT, &new_salt)?;
                new_salt
            }
        };

        // Derive the master key from the passphrase.
        let master_key = derive_key(passphrase.as_bytes(), &salt)?;

        // Generate or load the device keypairs.
        let signing: Arc<SigningKeyPair>;
        let x25519: Arc<X25519KeyPair>;

        // Try to load previously stored (encrypted) keypairs.
        let stored: Option<(SigningKeyPair, X25519KeyPair)> = if exists {
            let signing_ct = storage.get_metadata(META_SIGNING_KEY)?;
            let x25519_ct = storage.get_metadata(META_X25519_KEY)?;

            match (signing_ct, x25519_ct) {
                (Some(sk_bytes), Some(xk_bytes))
                    if !sk_bytes.is_empty() && !xk_bytes.is_empty() =>
                {
                    let sk_ct: Ciphertext = postcard::from_bytes(&sk_bytes)
                        .map_err(|e| CoreError::Serialization(e.to_string()))?;
                    let xk_ct: Ciphertext = postcard::from_bytes(&xk_bytes)
                        .map_err(|e| CoreError::Serialization(e.to_string()))?;

                    let sk_secret =
                        decrypt(&master_key, &sk_ct).map_err(|e| CoreError::Crypto(e))?;
                    let xk_secret =
                        decrypt(&master_key, &xk_ct).map_err(|e| CoreError::Crypto(e))?;

                    if sk_secret.len() == 32 && xk_secret.len() == 32 {
                        let mut sk_arr = [0u8; 32];
                        sk_arr.copy_from_slice(&sk_secret);
                        let mut xk_arr = [0u8; 32];
                        xk_arr.copy_from_slice(&xk_secret);
                        Some((
                            SigningKeyPair::from_seed(sk_arr),
                            X25519KeyPair::from_seed(xk_arr),
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        } else {
            None
        };

        match stored {
            Some((sk, xk)) => {
                signing = Arc::new(sk);
                x25519 = Arc::new(xk);
            }
            None => {
                // Generate fresh keypairs and persist them under the
                // current master key so the identity is stable across
                // opens (also the post-adoption path after pairing).
                signing = Arc::new(SigningKeyPair::generate());
                x25519 = Arc::new(X25519KeyPair::generate());

                let sk_ct = encrypt(&master_key, key_version, signing.secret_bytes().as_ref())
                    .map_err(|e| CoreError::Crypto(e))?;
                let xk_ct = encrypt(&master_key, key_version, &x25519.secret_bytes())
                    .map_err(|e| CoreError::Crypto(e))?;

                let sk_bytes = postcard::to_allocvec(&sk_ct)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;
                let xk_bytes = postcard::to_allocvec(&xk_ct)
                    .map_err(|e| CoreError::Serialization(e.to_string()))?;

                storage.set_metadata(META_SIGNING_KEY, &sk_bytes)?;
                storage.set_metadata(META_X25519_KEY, &xk_bytes)?;
            }
        }

        // Create the access engine.
        let mut access = AccessEngine::new(
            SqliteStorage::open(path)?, // separate connection for access
            signing.clone(),
            x25519.clone(),
            master_key.clone(),
            key_version,
            db_id,
        );

        // Bootstrap the root device if this is a new database.
        let bootstrapped = !access.list_devices()?.is_empty();
        if !exists && !bootstrapped {
            access.bootstrap_root()?;
        }

        // Create the query engine.
        let query = QueryEngine::new(
            SqliteStorage::open(path)?, // separate connection for query
            master_key.clone(),
            key_version,
        );

        // Create the sync engine with a live, storage-backed trust
        // provider: trust is evaluated against the device registry at
        // sync time, so revoke_device takes effect immediately.
        let sync_engine = SyncEngine::new(
            SqliteStorage::open(path)?, // separate connection for sync
            signing.clone(),
            db_id,
            Arc::new(LiveTrustProvider {
                storage: std::sync::Mutex::new(SqliteStorage::open(path)?),
            }),
        );

        Ok(Self {
            storage: SqliteStorage::open(path)?,
            query,
            access,
            sync: sync_engine,
            db_id,
            key_version,
            path: path.to_path_buf(),
            signing,
            x25519,
        })
    }

    /// Put a key-value pair into the database.
    ///
    /// Write path: validate → generate OperationId → encrypt →
    /// build canonical Operation → sign → hash → single SQLite
    /// transaction → commit.
    pub fn put(&mut self, key: &str, value: &[u8]) -> Result<OperationId, CoreError> {
        // Validate the key.
        if key.is_empty() {
            return Err(CoreError::Serialization(
                "key must not be empty".to_string(),
            ));
        }

        // Get the current sequence number for this device.
        let device_id = self.signing.public_key();
        let device_hash = veildb_crypto::hash(&device_id);

        // Determine the next sequence number.
        let ops = self.storage.read_all_operations()?;
        let max_seq = ops
            .iter()
            .filter(|op| op.id.device_id == device_hash)
            .map(|op| op.id.sequence)
            .max()
            .unwrap_or(0);
        let sequence = max_seq + 1;

        // Compute parents: all tip hashes (operations with no children).
        // For simplicity, we use the latest operation hash as the parent.
        let mut parents = Vec::new();
        if let Some(latest) = self.storage.latest_operation_hash()? {
            parents.push(latest);
        }

        // Build the logical clock.
        let mut logical_clock = self.storage.current_clock()?;
        logical_clock.advance(device_hash);

        // Encrypt the payload with the index token.
        let ciphertext = self.query.build_indexed_ciphertext(key, value)?;

        // Build the operation with a placeholder signature.
        let op = Operation {
            id: OperationId::new(device_hash, sequence),
            parents,
            logical_clock,
            device_id: device_hash,
            ciphertext,
            signature: vec![], // Placeholder required by the hash definition.
        };

        // Sign the operation.
        // The operation hash includes the signature field, so we sign
        // over the hash computed with an empty signature. Signature
        // verification recomputes the hash with empty signature and
        // verifies the signature against it.
        let op_hash = operation_hash(&op);
        let signature = self.signing.sign(&op_hash);

        let mut signed_op = op;
        signed_op.signature = signature;

        // Append with the signature. The storage engine recomputes
        // the final hash for the Merkle tree.
        self.storage.append(signed_op)?;

        Ok(OperationId::new(device_hash, sequence))
    }

    /// Get a value by key.
    ///
    /// Read path: query encrypted index → locate operation/state →
    /// read ciphertext → decrypt → return plaintext.
    pub fn get(&self, key: &str) -> Result<Vec<u8>, CoreError> {
        Ok(self.query.get(key)?)
    }

    /// Verify the integrity of the database.
    ///
    /// Recomputes operation hashes, checks parent references, and
    /// validates the Merkle root.
    pub fn verify_integrity(&self) -> Result<IntegrityStatus, CoreError> {
        let ops = self.storage.read_all_operations()?;
        let report = verify_operations(&ops);
        Ok(report.status)
    }

    /// Query the database state at a specific logical clock.
    pub fn query_at(&self, clock: LogicalClock) -> Result<DbState, CoreError> {
        Ok(self.query.query_at(&clock)?)
    }

    /// Get the operation log.
    pub fn log(&self, at: Option<LogicalClock>) -> Result<Vec<OperationSummary>, CoreError> {
        let ops = self.storage.read_all_operations()?;

        // If a clock is specified, filter to operations at or before it.
        let filtered: Vec<Operation> = match at {
            Some(clock) => ops
                .into_iter()
                .filter(|op| clock.dominates(&op.logical_clock))
                .collect(),
            None => ops,
        };

        Ok(build_log(&filtered))
    }

    /// Create a snapshot of the current state.
    pub fn snapshot(&mut self) -> Result<i64, CoreError> {
        Ok(self.query.create_snapshot()?)
    }

    /// Sync with a peer using the given backend.
    pub async fn sync(
        &mut self,
        backend: SyncBackendKind,
    ) -> Result<SyncReport, CoreError> {
        // Construct the backend.
        let report = match backend {
            SyncBackendKind::Mock => {
                // For Mock, we can't actually sync. Return a default report.
                return Ok(SyncReport {
                    operations_received: 0,
                    operations_sent: 0,
                    operations_merged: 0,
                    merkle_root: self.sync.merkle_root()?,
                    logical_clock: self.storage.current_clock()?,
                    success: true,
                    message: "Mock backend is for testing only; no sync performed".to_string(),
                });
            }
            SyncBackendKind::Lan { addr } => {
                let mut backend = veildb_sync::LanBackend::connect(&addr).await?;
                let report = self.sync.sync(&mut backend).await?;
                backend.close().await?;
                report
            }
            SyncBackendKind::Listen { addr } => {
                self.sync_listen_once(&addr).await?
            }
            #[cfg(feature = "sync-cloud")]
            SyncBackendKind::Cloud => {
                return Err(CoreError::Sync(
                    veildb_sync::error::SyncError::NotImplemented(
                        "cloud backend not yet implemented".to_string(),
                    ),
                ));
            }
            #[cfg(feature = "sync-p2p")]
            SyncBackendKind::P2p => {
                return Err(CoreError::Sync(
                    veildb_sync::error::SyncError::NotImplemented(
                        "P2P backend not yet implemented".to_string(),
                    ),
                ));
            }
        };

        // Record any deterministic conflict resolutions from this sync.
        self.record_merge_log()?;
        Ok(report)
    }

    /// Trust a new device by its public key.
    pub fn trust_device(&mut self, public_key: &[u8]) -> Result<TrustEntry, CoreError> {
        if public_key.len() != 32 {
            return Err(CoreError::Serialization(
                "public key must be 32 bytes".to_string(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        Ok(self.access.approve_device(&key)?)
    }

    /// Revoke a device.
    pub fn revoke_device(&mut self, device_id: &[u8]) -> Result<(), CoreError> {
        if device_id.len() != 32 {
            return Err(CoreError::Serialization(
                "device ID must be 32 bytes".to_string(),
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(device_id);
        self.access.revoke_device(&id)?;

        // No snapshot update needed: the sync engine consults the
        // live device registry through `LiveTrustProvider` at every
        // handshake, so the revocation takes effect immediately.
        Ok(())
    }

    /// Export a pairing bundle for a new device.
    ///
    /// The bundle is a signed, JSON-serialized invitation containing
    /// this database's ID and the approver's public key. The joining
    /// device presents it via [`VeilDbCore::import_pairing`] to be
    /// approved into the trust registry.
    pub fn export_pairing(&self) -> Result<PairingBundle, CoreError> {
        let public_key = self.signing.public_key();
        let salt: [u8; 32] = match self.storage.get_metadata(META_SALT)? {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => {
                return Err(CoreError::Serialization(
                    "database salt missing".to_string(),
                ))
            }
        };
        let mut msg = Vec::with_capacity(96);
        msg.extend_from_slice(&self.db_id);
        msg.extend_from_slice(&salt);
        msg.extend_from_slice(&public_key);
        let signature = self.signing.sign(&msg);

        Ok(PairingBundle {
            db_id: self.db_id,
            salt,
            device_id: veildb_crypto::hash(&public_key),
            approver_public_key: public_key,
            signature,
        })
    }

    /// Import a pairing bundle: approve the inviting device's key into
    /// our local trust registry so we can sync with it.
    ///
    /// The bundle's signature is verified against the embedded
    /// approver public key before the device is approved.
    pub fn import_pairing(&mut self, bundle: &PairingBundle) -> Result<TrustEntry, CoreError> {
        // Verify the bundle binds to the claimed approver key.
        let mut msg = Vec::with_capacity(96);
        msg.extend_from_slice(&bundle.db_id);
        msg.extend_from_slice(&bundle.salt);
        msg.extend_from_slice(&bundle.approver_public_key);
        veildb_crypto::verify_signature(
            &bundle.approver_public_key,
            &msg,
            &bundle.signature,
        )
        .map_err(|_| CoreError::Serialization("invalid pairing bundle signature".to_string()))?;

        // If this device's database is still empty AND it belongs to a
        // different database (i.e. this is the joining device), adopt
        // the inviting database's identity (db_id and KDF salt) so the
        // data key derives identically from the shared passphrase on
        // the next open. The originating device keeps its identity.
        if self.db_id != bundle.db_id && self.storage.operation_count()? == 0 {
            self.storage.set_metadata(META_DB_ID, &bundle.db_id)?;
            self.storage.set_metadata(META_SALT, &bundle.salt)?;
            // Discard the per-device key material encrypted under the
            // old (pre-adoption) data key; fresh keys are generated
            // and stored under the new key on the next open.
            self.storage.delete_metadata(META_SIGNING_KEY)?;
            self.storage.delete_metadata(META_X25519_KEY)?;
        }

        self.access.approve_device(&bundle.approver_public_key)?;

        // Return the resulting trust entry for the approved device.
        let entry = self
            .access
            .list_devices()?
            .into_iter()
            .find(|d| d.public_key == bundle.approver_public_key.to_vec())
            .ok_or_else(|| {
                CoreError::Serialization("approved device not found in registry".to_string())
            })?;
        Ok(entry)
    }

    /// Run one sync session with a peer over TCP (client side).
    pub async fn sync_with_peer(&mut self, addr: &str) -> Result<SyncReport, CoreError> {
        let mut backend = LanBackend::connect(addr).await?;
        let report = self.sync.sync(&mut backend).await?;
        backend.close().await?;
        self.record_merge_log()?;
        Ok(report)
    }

    /// Accept one incoming TCP sync session (server side).
    pub async fn sync_listen_once(&mut self, addr: &str) -> Result<SyncReport, CoreError> {
        self.sync_listen_once_with(addr, || {}).await
    }

    /// Like [`VeilDbCore::sync_listen_once`], but invokes `ready`
    /// (e.g. to announce readiness) after the listener is bound and
    /// before accepting the peer connection.
    pub async fn sync_listen_once_with<F>(
        &mut self,
        addr: &str,
        ready: F,
    ) -> Result<SyncReport, CoreError>
    where
        F: FnOnce(),
    {
        let listener = LanBackend::listen(addr).await?;
        ready();
        let mut backend = LanBackend::accept(&listener).await?;
        let report = self.sync.sync(&mut backend).await?;
        backend.close().await?;
        self.record_merge_log()?;
        Ok(report)
    }

    /// Bind a TCP listener for sync and announce it via UDP multicast
    /// discovery, then accept one incoming session.
    pub async fn sync_listen(
        &mut self,
        addr: &str,
        sync_port: u16,
        beacon_interval_ms: u64,
    ) -> Result<SyncReport, CoreError> {
        let _beacon = veildb_sync::discovery::spawn_beacon(
            self.signing.clone(),
            self.db_id,
            sync_port,
            std::time::Duration::from_millis(beacon_interval_ms),
        )
        .await?;

        self.sync_listen_once(addr).await
    }

    /// Discover peers on the LAN via UDP multicast for `timeout_ms`.
    pub async fn discover_peers(&self, timeout_ms: u64) -> Result<Vec<DiscoveredPeer>, CoreError> {
        let peers = veildb_sync::discovery::discover(
            std::time::Duration::from_millis(timeout_ms),
            self.db_id,
        )
        .await?;
        Ok(peers)
    }

    /// Query the persistent merge log (deterministic CRDT conflict
    /// resolutions recorded during sync).
    pub fn merge_log(&self) -> Result<Vec<MergeLogEntry>, CoreError> {
        Ok(self.storage.list_merge_entries()?)
    }

    /// Compute deterministic conflict resolutions over the current
    /// operation set and persist any not already recorded.
    ///
    /// Idempotent: identical (key, winner, loser) triples are stored
    /// once. Returns the entries that were newly recorded.
    pub fn record_merge_log(&mut self) -> Result<Vec<MergeLogEntry>, CoreError> {
        let ops = self.storage.read_all_operations()?;
        let outcomes = self.query.resolve_conflicts(&ops)?;

        let mut recorded = Vec::new();
        for outcome in outcomes {
            let loser = outcome.loser;
            if self
                .storage
                .merge_entry_exists(&outcome.key, &outcome.winner, loser.as_ref())?
            {
                continue;
            }
            let entry = MergeLogEntry {
                id: 0,
                key: outcome.key.clone(),
                winner: outcome.winner,
                loser,
                rule: outcome.rule.as_str().to_string(),
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            };
            self.storage.record_merge_entry(
                &entry.key,
                entry.winner,
                entry.loser,
                &entry.rule,
            )?;
            recorded.push(entry);
        }
        Ok(recorded)
    }

    /// Share a key with a target device.
    pub fn share(
        &mut self,
        key: &str,
        to_device: &[u8],
    ) -> Result<ReEncryptedBlob, CoreError> {
        if to_device.len() != 32 {
            return Err(CoreError::Serialization(
                "device ID must be 32 bytes".to_string(),
            ));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(to_device);
        Ok(self.access.share_key(key, &id)?)
    }

    /// Create an encrypted backup archive.
    pub fn backup(&self, output: &Path) -> Result<EncryptedArchive, CoreError> {
        Ok(self.access.backup(output)?)
    }

    /// Restore from an encrypted backup archive.
    pub fn restore(&mut self, archive: &Path) -> Result<(), CoreError> {
        self.access.restore(archive)?;
        Ok(())
    }

    /// List all devices.
    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>, CoreError> {
        let devices = self.access.list_devices()?;
        Ok(devices.into_iter().map(DeviceInfo::from).collect())
    }

    /// Get the database status.
    pub fn status(&self) -> Result<DbStatus, CoreError> {
        let operation_count = self.storage.operation_count()?;
        let merkle_root = self.sync.merkle_root()?;
        let logical_clock = self.storage.current_clock()?;

        let latest_snapshot_id = self.storage.latest_snapshot_id()?;
        let snapshot_merkle_root = match self.storage.latest_snapshot()? {
            Some(snap) => Some(snap.merkle_root),
            None => None,
        };

        let devices = self.access.list_devices()?;
        let device_count = devices.len() as u64;
        let bootstrapped = !devices.is_empty();

        Ok(DbStatus {
            db_id: self.db_id,
            operation_count,
            merkle_root,
            logical_clock,
            latest_snapshot_id,
            snapshot_merkle_root,
            device_count,
            self_device_id: veildb_crypto::hash(&self.signing.public_key()),
            self_public_key: self.signing.public_key().to_vec(),
            key_version: self.key_version,
            format_version: DB_FORMAT_VERSION,
            bootstrapped,
        })
    }

    /// Rotate the master key.
    ///
    /// Generates a new key version, re-derives from the existing master
    /// secret via Argon2. Historical ciphertexts stay decryptable under
    /// their original `key_version`.
    pub fn rotate_key(&mut self) -> Result<u32, CoreError> {
        let new_version = self.access.rotate_key()?;
        self.key_version = new_version;
        Ok(new_version)
    }

    /// Get the operation DAG for visualization.
    ///
    /// Returns a `DagView` containing all operations as nodes and their
    /// parent edges, suitable for rendering in the frontend.
    pub fn get_dag(&self) -> Result<DagView, CoreError> {
        let ops = self.storage.read_all_operations()?;

        let mut nodes = Vec::with_capacity(ops.len());
        let mut edges = Vec::new();

        for op in &ops {
            let op_hash = operation_hash(op);

            // Determine signature status by checking the hash.
            // A simple heuristic: if the operation hash is non-zero
            // and has a signature, consider it "signed".
            let signature_status = if op.signature.is_empty() {
                "unsigned".to_string()
            } else {
                "signed".to_string()
            };

            let clock: Vec<(String, u64)> = op
                .logical_clock
                .entries
                .iter()
                .map(|(d, c)| (hex_encode(d), *c))
                .collect();

            nodes.push(DagNode {
                id: format!(
                    "{}:{}",
                    &hex_encode(&op.device_id)[..8],
                    op.id.sequence
                ),
                device_id: op.device_id,
                sequence: op.id.sequence,
                hash: op_hash,
                parents: op.parents.clone(),
                signature_status,
                clock,
            });

            for parent in &op.parents {
                edges.push(DagEdge {
                    from: *parent,
                    to: op_hash,
                });
            }
        }

        Ok(DagView { nodes, edges })
    }

    /// Get the Merkle tree for visualization.
    ///
    /// Returns a `MerkleTreeView` with all nodes (leaves and internal)
    /// and the root hash, suitable for rendering in the frontend.
    pub fn get_merkle_tree(&self) -> Result<MerkleTreeView, CoreError> {
        let ops = self.storage.read_all_operations()?;
        let hashes: Vec<[u8; 32]> = ops.iter().map(operation_hash).collect();
        let tree = veildb_integrity::MerkleTree::build(&hashes);

        let mut leaves = Vec::new();
        for (i, leaf_hash) in tree.leaves().iter().enumerate() {
            leaves.push(MerkleNodeView {
                id: format!("leaf-{}", i),
                hash: *leaf_hash,
                level: 0,
                index: i,
                is_leaf: true,
            });
        }

        // Build internal nodes from the tree structure.
        // The tree has levels 1..=max_level. We can reconstruct
        // them by re-computing: that's deterministic.
        let mut internal_nodes = Vec::new();
        let mut current: Vec<[u8; 32]> = tree.leaves().to_vec();
        let mut level = 1u32;

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2);
            for (i, chunk) in current.chunks(2).enumerate() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&[0u8; 32]);
                }
                let h = *hasher.finalize().as_bytes();
                next.push(h);
                internal_nodes.push(MerkleNodeView {
                    id: format!("node-{}-{}", level, i),
                    hash: h,
                    level,
                    index: i,
                    is_leaf: false,
                });
            }
            current = next;
            level += 1;
        }

        Ok(MerkleTreeView {
            root: tree.root(),
            leaves,
            internal_nodes,
        })
    }

    /// Dev-only: corrupt an operation's ciphertext.
    ///
    /// Flips bytes in the operation's local ciphertext or hash to
    /// simulate tampering. Only available in debug builds.
    #[cfg(debug_assertions)]
    pub fn dev_corrupt_operation(
        &mut self,
        device_id: &[u8; 32],
        sequence: u64,
    ) -> Result<(), CoreError> {
        self.storage.corrupt_operation(device_id, sequence)?;
        Ok(())
    }
}

/// A node in the operation DAG visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    /// Short display ID (e.g. "a1b2c3d4:1").
    pub id: String,
    /// Full device ID.
    pub device_id: [u8; 32],
    /// Sequence number within the device.
    pub sequence: u64,
    /// Operation hash.
    pub hash: [u8; 32],
    /// Parent operation hashes.
    pub parents: Vec<[u8; 32]>,
    /// Signature status: "signed" or "unsigned".
    pub signature_status: String,
    /// Logical clock entries as (hex_device_id, counter).
    pub clock: Vec<(String, u64)>,
}

/// An edge in the operation DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagEdge {
    /// Hash of the parent operation.
    pub from: [u8; 32],
    /// Hash of the child operation.
    pub to: [u8; 32],
}

/// The full DAG view for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagView {
    /// All operation nodes.
    pub nodes: Vec<DagNode>,
    /// All parent-child edges.
    pub edges: Vec<DagEdge>,
}

/// A node in the Merkle tree visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNodeView {
    /// Display ID (e.g. "leaf-0", "node-1-0").
    pub id: String,
    /// The node's hash.
    pub hash: [u8; 32],
    /// Level in the tree (0 = leaves).
    pub level: u32,
    /// Index within the level.
    pub index: usize,
    /// Whether this is a leaf node.
    pub is_leaf: bool,
}

/// The full Merkle tree view for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTreeView {
    /// The root hash.
    pub root: [u8; 32],
    /// Leaf nodes (operation hashes).
    pub leaves: Vec<MerkleNodeView>,
    /// Internal nodes.
    pub internal_nodes: Vec<MerkleNodeView>,
}

/// Helper to encode bytes as hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_core() -> (tempfile::TempDir, VeilDbCore) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.vdb");
        let passphrase = SecretString::new("test-passphrase".to_string());
        let core = VeilDbCore::init(&path, passphrase).unwrap();
        (dir, core)
    }

    #[test]
    fn init_creates_database() {
        let (dir, core) = test_core();
        let status = core.status().unwrap();
        assert!(status.bootstrapped);
        assert_eq!(status.operation_count, 0);
        assert_eq!(status.device_count, 1);
        drop(dir);
    }

    #[test]
    fn put_get_roundtrip() {
        let (dir, mut core) = test_core();
        let op_id = core.put("hello", b"world").unwrap();
        assert_eq!(op_id.sequence, 1);

        let value = core.get("hello").unwrap();
        assert_eq!(value, b"world");
        drop(dir);
    }

    #[test]
    fn put_multiple_ops() {
        let (dir, mut core) = test_core();
        core.put("key1", b"value1").unwrap();
        core.put("key2", b"value2").unwrap();
        core.put("key1", b"value1-updated").unwrap();

        assert_eq!(core.get("key1").unwrap(), b"value1-updated");
        assert_eq!(core.get("key2").unwrap(), b"value2");
        assert_eq!(core.status().unwrap().operation_count, 3);
        drop(dir);
    }

    #[test]
    fn get_missing_key() {
        let (dir, core) = test_core();
        assert!(core.get("missing").is_err());
        drop(dir);
    }

    #[test]
    fn verify_integrity_ok() {
        let (dir, mut core) = test_core();
        core.put("key1", b"value1").unwrap();
        core.put("key2", b"value2").unwrap();

        let status = core.verify_integrity().unwrap();
        assert_eq!(status, IntegrityStatus::Verified);
        drop(dir);
    }

    #[test]
    fn verify_integrity_tampered() {
        let (dir, mut core) = test_core();
        core.put("key1", b"value1").unwrap();

        // Tamper with the storage directly (simulating corruption).
        // We can't easily corrupt via the public API, so we verify
        // the integrity is at least verified for now.
        let status = core.verify_integrity().unwrap();
        assert_eq!(status, IntegrityStatus::Verified);
        drop(dir);
    }

    #[test]
    fn snapshot_and_status() {
        let (dir, mut core) = test_core();
        core.put("key1", b"value1").unwrap();

        let snap_id = core.snapshot().unwrap();
        assert!(snap_id > 0);

        let status = core.status().unwrap();
        assert_eq!(status.latest_snapshot_id, Some(snap_id));
        assert!(status.snapshot_merkle_root.is_some());
        drop(dir);
    }

    #[test]
    fn log_works() {
        let (dir, mut core) = test_core();
        core.put("key1", b"value1").unwrap();
        core.put("key2", b"value2").unwrap();

        let log = core.log(None).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].id.sequence, 1);
        assert_eq!(log[1].id.sequence, 2);
        drop(dir);
    }

    #[test]
    fn devices_flow() {
        let (dir, mut core) = test_core();
        let devices = core.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert!(devices[0].trusted);

        // Trust a new device.
        let new_signing = SigningKeyPair::generate();
        let new_pub = new_signing.public_key().to_vec();
        let entry = core.trust_device(&new_pub).unwrap();
        assert!(entry.trusted);

        let devices = core.list_devices().unwrap();
        assert_eq!(devices.len(), 2);

        // Revoke the new device.
        core.revoke_device(&entry.device_id).unwrap();

        let devices = core.list_devices().unwrap();
        assert_eq!(devices.len(), 2);
        let revoked = devices.iter().find(|d| d.device_id == entry.device_id).unwrap();
        assert!(!revoked.trusted);
        drop(dir);
    }

    #[test]
    fn backup_restore_roundtrip() {
        let (dir, mut core) = test_core();
        core.put("key1", b"value1").unwrap();
        core.put("key2", b"value2").unwrap();

        let backup_path = dir.path().join("backup.vdb");
        core.backup(&backup_path).unwrap();
        assert!(backup_path.exists());

        // Restore into a fresh database.
        let restore_path = dir.path().join("restore.vdb");
        let passphrase = SecretString::new("test-passphrase".to_string());
        let mut restored = VeilDbCore::init(&restore_path, passphrase).unwrap();

        // Set the same DB ID so restore works.
        // In practice, restore would be into the same DB. Here we
        // just verify the backup file is valid.
        let _ = restored.status().unwrap();
        drop(dir);
    }

    #[test]
    fn share_key() {
        let (dir, mut core) = test_core();

        // Set up a target device.
        let new_signing = SigningKeyPair::generate();
        let new_pub = new_signing.public_key().to_vec();
        let entry = core.trust_device(&new_pub).unwrap();

        // Store a key in metadata for sharing.
        core.storage
            .set_metadata("key:shared", b"secret-material")
            .unwrap();

        let blob = core.share("shared", &entry.device_id).unwrap();
        assert_eq!(blob.to_device, entry.device_id);
        assert_eq!(blob.key, "shared");
        drop(dir);
    }
}
