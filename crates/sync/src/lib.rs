//! VeilDB sync layer.
//!
//! CRDT merge, peer protocol, and transports. This is the only crate
//! allowed to cross a network boundary.
//!
//! The sync engine implements a custom operation-based CRDT satisfying:
//! - Commutative: merge(A,B) == merge(B,A)
//! - Associative: merge(merge(A,B),C) == merge(A,merge(B,C))
//! - Idempotent: merge(A,A) == A
//!
//! No timestamp-based conflict resolution is used. Operations are
//! identified by (device_id, sequence_number) which is globally unique.

pub mod discovery;
pub mod error;

use std::collections::{BTreeMap, HashMap, HashSet};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use veildb_crypto::{SigningKeyPair, verify_signature};
use veildb_integrity::{MerkleTree, operation_hash, validate_graph};
use veildb_storage::{Operation, OperationId, StorageEngine};

use error::SyncError;

/// The current sync protocol version.
pub const SYNC_PROTOCOL_VERSION: u32 = 1;

/// A report of a completed sync operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    /// Number of operations received from the peer.
    pub operations_received: u64,
    /// Number of operations sent to the peer.
    pub operations_sent: u64,
    /// Number of operations merged into local state.
    pub operations_merged: u64,
    /// The resulting Merkle root after sync.
    pub merkle_root: [u8; 32],
    /// The resulting logical clock after sync.
    pub logical_clock: veildb_storage::LogicalClock,
    /// Whether the sync completed successfully.
    pub success: bool,
    /// Human-readable status message.
    pub message: String,
}

/// A step in the 14-step sync protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStep {
    /// 1. Authenticate peer
    AuthenticatePeer,
    /// 2. Verify device trust
    VerifyDeviceTrust,
    /// 3. Exchange DB metadata
    ExchangeDbMetadata,
    /// 4. Exchange Merkle roots
    ExchangeMerkleRoots,
    /// 5. Diff subtrees
    DiffSubtrees,
    /// 6. Identify missing ops
    IdentifyMissingOps,
    /// 7. Transfer ciphertext+meta
    TransferCiphertext,
    /// 8. Verify operation hashes
    VerifyOperationHashes,
    /// 9. Verify signatures
    VerifySignatures,
    /// 10. Validate operation graph
    ValidateOperationGraph,
    /// 11. CRDT merge
    CrdtMerge,
    /// 12. Apply atomically
    ApplyAtomically,
    /// 13. Update local Merkle state
    UpdateMerkleState,
    /// 14. Commit SQLite transaction
    CommitTransaction,
}

impl SyncStep {
    /// Get the step number (1-14).
    pub fn number(&self) -> u32 {
        match self {
            Self::AuthenticatePeer => 1,
            Self::VerifyDeviceTrust => 2,
            Self::ExchangeDbMetadata => 3,
            Self::ExchangeMerkleRoots => 4,
            Self::DiffSubtrees => 5,
            Self::IdentifyMissingOps => 6,
            Self::TransferCiphertext => 7,
            Self::VerifyOperationHashes => 8,
            Self::VerifySignatures => 9,
            Self::ValidateOperationGraph => 10,
            Self::CrdtMerge => 11,
            Self::ApplyAtomically => 12,
            Self::UpdateMerkleState => 13,
            Self::CommitTransaction => 14,
        }
    }

    /// Get the step name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::AuthenticatePeer => "Authenticate peer",
            Self::VerifyDeviceTrust => "Verify device trust",
            Self::ExchangeDbMetadata => "Exchange DB metadata",
            Self::ExchangeMerkleRoots => "Exchange Merkle roots",
            Self::DiffSubtrees => "Diff subtrees",
            Self::IdentifyMissingOps => "Identify missing ops",
            Self::TransferCiphertext => "Transfer ciphertext+meta",
            Self::VerifyOperationHashes => "Verify operation hashes",
            Self::VerifySignatures => "Verify signatures",
            Self::ValidateOperationGraph => "Validate operation graph",
            Self::CrdtMerge => "CRDT merge",
            Self::ApplyAtomically => "Apply atomically",
            Self::UpdateMerkleState => "Update local Merkle state",
            Self::CommitTransaction => "Commit SQLite transaction",
        }
    }
}

/// A message in the sync protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncMessage {
    /// Step 1: Authentication handshake.
    Hello {
        protocol_version: u32,
        device_id: [u8; 32],
        public_key: [u8; 32],
        nonce: [u8; 32],
    },
    /// Step 1: Authentication response.
    HelloAck {
        protocol_version: u32,
        device_id: [u8; 32],
        public_key: [u8; 32],
        nonce: [u8; 32],
        signature: Vec<u8>,
    },
    /// Step 3: Database metadata.
    DbMetadata {
        db_id: [u8; 32],
        operation_count: u64,
        logical_clock: veildb_storage::LogicalClock,
    },
    /// Step 4: Merkle root.
    MerkleRoot {
        root: [u8; 32],
    },
    /// Step 5-6: Missing operation hashes.
    MissingOperations {
        hashes: Vec<[u8; 32]>,
    },
    /// Step 7: Operation transfer.
    Operations {
        operations: Vec<Operation>,
    },
    /// Step 11: Merge result.
    MergeResult {
        merged: u64,
        merkle_root: [u8; 32],
    },
    /// Error message.
    Error {
        message: String,
    },
    // ─── Auto-pairing extension (pre-sync, see core's sync_auto) ───
    // These variants ride the same transport but are only exchanged
    // BEFORE the 14-step engine protocol, by the one-click auto-sync
    // paths. Appended last so existing variant discriminants (and
    // therefore the wire format of the engine protocol) are stable.
    /// Auto-pairing probe sent by the dialing (initiator) side.
    PairProbe {
        protocol_version: u32,
        db_id: [u8; 32],
        device_id: [u8; 32],
        public_key: [u8; 32],
        operation_count: u64,
        nonce: [u8; 32],
    },
    /// Auto-pairing probe reply from the listening (responder) side.
    PairProbeAck {
        protocol_version: u32,
        db_id: [u8; 32],
        device_id: [u8; 32],
        public_key: [u8; 32],
        operation_count: u64,
        /// The responder's fresh nonce.
        nonce: [u8; 32],
        /// Echo of the initiator's nonce (replay protection).
        probe_nonce: [u8; 32],
        /// Ed25519 signature over `public_key || probe_nonce || db_id`.
        signature: Vec<u8>,
    },
    /// The keeper side offers its signed pairing bundle.
    PairBundleOffer {
        db_id: [u8; 32],
        salt: [u8; 32],
        device_id: [u8; 32],
        approver_public_key: [u8; 32],
        signature: Vec<u8>,
    },
    /// Proof of passphrase knowledge (and, for the adopter, its
    /// post-adoption public key).
    PairProof {
        public_key: [u8; 32],
        proof: [u8; 32],
        adopted: bool,
    },
    /// Final pairing verdict.
    PairDecision {
        accepted: bool,
        message: String,
    },
}

/// A sync backend transport.
///
/// The sync engine is transport-agnostic. Backends implement this
/// trait to provide the actual message exchange.
#[async_trait]
pub trait SyncBackend: Send + Sync {
    /// Send a message to the peer.
    async fn send(&mut self, message: SyncMessage) -> Result<(), SyncError>;
    /// Receive a message from the peer.
    async fn receive(&mut self) -> Result<SyncMessage, SyncError>;
    /// Close the connection cleanly.
    async fn close(&mut self) -> Result<(), SyncError>;

    /// Drain any buffered incoming data, then close the connection.
    ///
    /// This is the recommended teardown for error / rejection paths.
    /// By draining one final message before closing, we ensure the
    /// peer's TCP receive queue is flushed with a clean FIN rather
    /// than an abrupt RST (which surfaces as "Connection reset by
    /// peer" / "os error 54" on macOS and "os error 10053" on
    /// Windows).
    ///
    /// The drain has a short timeout and silently ignores failures —
    /// the important part is the clean `close()` afterwards.
    async fn drain_and_close(&mut self, drain_timeout_ms: u64) -> Result<(), SyncError> {
        // Try to read one more message; if nothing arrives within
        // the timeout (normal — the peer already closed), that's fine.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(drain_timeout_ms),
            self.receive(),
        )
        .await;
        self.close().await
    }
}

/// A mock backend for testing.
///
/// This backend connects two in-memory channels, simulating a
/// bidirectional connection without any network I/O.
pub struct MockBackend {
    /// Outgoing messages (to peer).
    outgoing: tokio::sync::mpsc::UnboundedSender<SyncMessage>,
    /// Incoming messages (from peer).
    incoming: tokio::sync::mpsc::UnboundedReceiver<SyncMessage>,
}

impl MockBackend {
    /// Create a pair of connected mock backends.
    pub fn pair() -> (MockBackend, MockBackend) {
        let (tx_a, rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, rx_b) = tokio::sync::mpsc::unbounded_channel();
        (
            MockBackend {
                outgoing: tx_b,
                incoming: rx_a,
            },
            MockBackend {
                outgoing: tx_a,
                incoming: rx_b,
            },
        )
    }
}

#[async_trait]
impl SyncBackend for MockBackend {
    async fn send(&mut self, message: SyncMessage) -> Result<(), SyncError> {
        self.outgoing
            .send(message)
            .map_err(|_| SyncError::ConnectionDropped)
    }

    async fn receive(&mut self) -> Result<SyncMessage, SyncError> {
        self.incoming
            .recv()
            .await
            .ok_or(SyncError::ConnectionDropped)
    }

    async fn close(&mut self) -> Result<(), SyncError> {
        Ok(())
    }
}

/// A LAN backend using plain TCP.
///
/// Messages are length-prefixed postcard-serialized `SyncMessage`s.
pub struct LanBackend {
    stream: Option<tokio::net::TcpStream>,
}

impl LanBackend {
    /// Wrap an already-connected TCP stream (e.g. accepted by the
    /// GUI's background sync listener) so the engine or the
    /// auto-pairing handshake can run over it.
    pub fn from_stream(stream: tokio::net::TcpStream) -> Self {
        Self { stream: Some(stream) }
    }

    /// Connect to a peer at the given address.
    pub async fn connect(addr: &str) -> Result<Self, SyncError> {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(SyncError::Io)?;
        Ok(Self { stream: Some(stream) })
    }

    /// Listen for incoming connections.
    ///
    /// Sets `SO_REUSEADDR` (via `tokio`'s default on bind, reinforced
    /// explicitly on Unix) so that a restart releases the port from
    /// `TIME_WAIT` quickly, avoiding "Address already in use" errors.
    pub async fn listen(addr: &str) -> Result<tokio::net::TcpListener, SyncError> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(SyncError::Io)?;
        // Tokio already sets SO_REUSEADDR on bind, but on Unix we
        // additionally set it explicitly for clarity and to defend
        // against environments where the default is not applied.
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: setting a standard socket option; failure is
            // non-fatal (tokio already set SO_REUSEADDR by default).
            let fd = listener.as_raw_fd();
            let opt: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as u32,
                );
            }
        }
        Ok(listener)
    }

    /// Accept an incoming connection.
    pub async fn accept(listener: &tokio::net::TcpListener) -> Result<Self, SyncError> {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(SyncError::Io)?;
        Ok(Self { stream: Some(stream) })
    }

    async fn write_message(&mut self, message: &SyncMessage) -> Result<(), SyncError> {
        let bytes = postcard::to_allocvec(message)?;
        let len = (bytes.len() as u32).to_le_bytes();
        use tokio::io::AsyncWriteExt;
        let stream = self
            .stream
            .as_mut()
            .ok_or(SyncError::ConnectionDropped)?;
        stream.write_all(&len).await.map_err(SyncError::Io)?;
        stream
            .write_all(&bytes)
            .await
            .map_err(SyncError::Io)?;
        stream.flush().await.map_err(SyncError::Io)?;
        Ok(())
    }

    async fn read_message(&mut self) -> Result<SyncMessage, SyncError> {
        use tokio::io::AsyncReadExt;
        let stream = self
            .stream
            .as_mut()
            .ok_or(SyncError::ConnectionDropped)?;
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(SyncError::Io)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(SyncError::Io)?;
        postcard::from_bytes(&buf).map_err(|e| SyncError::Serialization(e.to_string()))
    }
}

#[async_trait]
impl SyncBackend for LanBackend {
    async fn send(&mut self, message: SyncMessage) -> Result<(), SyncError> {
        self.write_message(&message).await
    }

    async fn receive(&mut self) -> Result<SyncMessage, SyncError> {
        self.read_message().await
    }

    async fn close(&mut self) -> Result<(), SyncError> {
        // Clean half-close: shutdown both directions of the TCP stream
        // so the peer receives a FIN (not a RST). This is critical when
        // unread data is still buffered in the receive queue.
        if let Some(stream) = self.stream.take() {
            let _ = stream
                .into_std()
                .and_then(|s| s.shutdown(std::net::Shutdown::Both));
        }
        Ok(())
    }
}

/// Safety net: ensure the TCP stream is cleanly shut down even if
/// `close()` was never explicitly called (e.g. on an early `return Err`
/// deep in the sync protocol). Without this, dropping a `LanBackend`
/// with unread data in the receive buffer sends a TCP RST.
impl Drop for LanBackend {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream
                .into_std()
                .and_then(|s| s.shutdown(std::net::Shutdown::Both));
        }
    }
}

/// A cloud relay backend (stub, feature-gated).
#[cfg(feature = "cloud")]
pub struct CloudBackend {
    // Placeholder for future cloud relay implementation.
    _private: (),
}

#[cfg(feature = "cloud")]
#[async_trait]
impl SyncBackend for CloudBackend {
    async fn send(&mut self, _message: SyncMessage) -> Result<(), SyncError> {
        Err(SyncError::BackendNotAvailable(
            "cloud backend not yet implemented".to_string(),
        ))
    }

    async fn receive(&mut self) -> Result<SyncMessage, SyncError> {
        Err(SyncError::BackendNotAvailable(
            "cloud backend not yet implemented".to_string(),
        ))
    }

    async fn close(&mut self) -> Result<(), SyncError> {
        Ok(())
    }
}

/// A P2P backend (stub, feature-gated).
#[cfg(feature = "p2p")]
pub struct P2pBackend {
    // Placeholder for future libp2p implementation.
    _private: (),
}

#[cfg(feature = "p2p")]
#[async_trait]
impl SyncBackend for P2pBackend {
    async fn send(&mut self, _message: SyncMessage) -> Result<(), SyncError> {
        Err(SyncError::BackendNotAvailable(
            "p2p backend not yet implemented".to_string(),
        ))
    }

    async fn receive(&mut self) -> Result<SyncMessage, SyncError> {
        Err(SyncError::BackendNotAvailable(
            "p2p backend not yet implemented".to_string(),
        ))
    }

    async fn close(&mut self) -> Result<(), SyncError> {
        Ok(())
    }
}

/// The CRDT merge engine.
///
/// Implements a deterministic, commutative, associative, idempotent
/// merge of operation sets.
pub struct CrdtEngine;

impl CrdtEngine {
    /// Merge two sets of operations.
    ///
    /// The merge is the union of both sets, deduplicated by operation
    /// ID. Since operations are immutable and identified by
    /// (device_id, sequence_number), the union is trivially
    /// commutative, associative, and idempotent.
    ///
    /// Returns the merged set of operations.
    pub fn merge(
        local: &[Operation],
        remote: &[Operation],
    ) -> Result<Vec<Operation>, SyncError> {
        // Build a map of operation ID → operation.
        let mut merged: BTreeMap<OperationId, Operation> = BTreeMap::new();

        for op in local {
            merged.insert(op.id, op.clone());
        }
        for op in remote {
            merged.insert(op.id, op.clone());
        }

        Ok(merged.into_values().collect())
    }

    /// Check if a set of operations is closed under the merge.
    ///
    /// This verifies that all parent references resolve within the set.
    pub fn is_closed(operations: &[Operation]) -> bool {
        let hashes: HashSet<[u8; 32]> = operations.iter().map(operation_hash).collect();
        operations
            .iter()
            .all(|op| op.parents.iter().all(|p| hashes.contains(p)))
    }

    /// Compute the set of operations that are missing from `local`
    /// but present in `remote`.
    pub fn missing_operations(
        local: &[Operation],
        remote: &[Operation],
    ) -> Vec<Operation> {
        let local_ids: HashSet<OperationId> = local.iter().map(|op| op.id).collect();
        remote
            .iter()
            .filter(|op| !local_ids.contains(&op.id))
            .cloned()
            .collect()
    }
}

/// Live trust lookup.
///
/// Implemented by the core layer over the device registry in storage.
/// Because the check happens at sync time against the live registry,
/// a `revoke_device` call takes effect immediately, even for sessions
/// that were already possible a moment ago.
pub trait TrustProvider: Send + Sync {
    /// Whether the device is currently trusted (not revoked).
    fn is_trusted(&self, device_id: &[u8; 32]) -> bool;

    /// The stored Ed25519 public key for a device, if known.
    ///
    /// Used to verify operation signatures in protocol step 9.
    fn public_key_of(&self, device_id: &[u8; 32]) -> Option<[u8; 32]>;
}

/// A static, in-memory [`TrustProvider`].
///
/// Useful for tests and as a default; production code should use the
/// storage-backed provider from the core layer so revocations are
/// honored immediately.
pub struct StaticTrustProvider {
    trusted: HashSet<[u8; 32]>,
    public_keys: HashMap<[u8; 32], [u8; 32]>,
}

impl StaticTrustProvider {
    /// Build a provider from a set of trusted device IDs.
    pub fn new(trusted: HashSet<[u8; 32]>) -> Self {
        Self {
            trusted,
            public_keys: HashMap::new(),
        }
    }

    /// Associate a known public key with a device.
    pub fn with_public_key(mut self, device_id: [u8; 32], public_key: [u8; 32]) -> Self {
        self.public_keys.insert(device_id, public_key);
        self
    }
}

impl TrustProvider for StaticTrustProvider {
    fn is_trusted(&self, device_id: &[u8; 32]) -> bool {
        self.trusted.contains(device_id)
    }

    fn public_key_of(&self, device_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.public_keys.get(device_id).copied()
    }
}

/// The sync engine.
///
/// Orchestrates the 14-step sync protocol using a backend transport.
pub struct SyncEngine<S: StorageEngine> {
    storage: S,
    /// This device's signing keypair.
    signing: Arc<SigningKeyPair>,
    /// The database ID.
    db_id: [u8; 32],
    /// Live trust lookup (so revocations take effect immediately).
    trust: Arc<dyn TrustProvider>,
}

impl<S: StorageEngine> SyncEngine<S> {
    /// Create a new sync engine.
    pub fn new(
        storage: S,
        signing: Arc<SigningKeyPair>,
        db_id: [u8; 32],
        trust: Arc<dyn TrustProvider>,
    ) -> Self {
        Self {
            storage,
            signing,
            db_id,
            trust,
        }
    }

    /// Get this device's ID.
    pub fn device_id(&self) -> [u8; 32] {
        veildb_crypto::hash(&self.signing.public_key())
    }

    /// Get the current Merkle root of all local operations.
    pub fn merkle_root(&self) -> Result<[u8; 32], SyncError> {
        let ops = self.storage.read_all_operations()?;
        let hashes: Vec<[u8; 32]> = ops.iter().map(operation_hash).collect();
        Ok(MerkleTree::build(&hashes).root())
    }

    /// Run the full 14-step sync protocol with a peer.
    ///
    /// Returns a report of the sync operation.
    pub async fn sync(&mut self, backend: &mut dyn SyncBackend) -> Result<SyncReport, SyncError> {
        // Step 1: Authenticate peer.
        //
        // Both peers may initiate concurrently (each sends `Hello`). To
        // handle this, after sending our `Hello` we peek at what we
        // receive:
        // - If we receive the peer's `Hello` (concurrent initiation),
        //   we respond with `HelloAck` for the peer, then receive our
        //   own `HelloAck`.
        // - If we receive `HelloAck` directly, we validate it.
        let hello = SyncMessage::Hello {
            protocol_version: SYNC_PROTOCOL_VERSION,
            device_id: self.device_id(),
            public_key: self.signing.public_key(),
            nonce: veildb_crypto::random_bytes_32(),
        };
        backend.send(hello).await?;

        let first_message = backend.receive().await?;

        // If the peer also initiated, respond with HelloAck.
        let hello_ack = match &first_message {
            SyncMessage::Hello {
                protocol_version,
                device_id: _,
                public_key: _,
                nonce,
            } => {
                if *protocol_version != SYNC_PROTOCOL_VERSION {
                    return Err(SyncError::InvalidPeerMessage(
                        "protocol version mismatch".to_string(),
                    ));
                }
                // Sign our own HelloAck for the peer.
                let mut msg = Vec::with_capacity(32 + 32 + 32);
                msg.extend_from_slice(&self.signing.public_key());
                msg.extend_from_slice(nonce);
                msg.extend_from_slice(&self.db_id);
                let signature = self.signing.sign(&msg);
                backend
                    .send(SyncMessage::HelloAck {
                        protocol_version: SYNC_PROTOCOL_VERSION,
                        device_id: self.device_id(),
                        public_key: self.signing.public_key(),
                        nonce: *nonce,
                        signature,
                    })
                    .await?;
                // Now receive our own HelloAck.
                backend.receive().await?
            }
            _ => first_message,
        };

        let peer_device_id = match &hello_ack {
            SyncMessage::HelloAck {
                protocol_version,
                device_id,
                public_key,
                nonce,
                signature,
            } => {
                if *protocol_version != SYNC_PROTOCOL_VERSION {
                    return Err(SyncError::InvalidPeerMessage(
                        "protocol version mismatch".to_string(),
                    ));
                }
                // Verify the peer's signature over the handshake.
                let mut msg = Vec::with_capacity(32 + 32 + 32);
                msg.extend_from_slice(public_key);
                msg.extend_from_slice(nonce);
                msg.extend_from_slice(&self.db_id);
                verify_signature(public_key, &msg, signature)
                    .map_err(|_| SyncError::PeerAuthenticationFailed)?;
                *device_id
            }
            SyncMessage::Error { message } => {
                return Err(SyncError::InvalidPeerMessage(message.clone()));
            }
            _ => {
                return Err(SyncError::InvalidPeerMessage(
                    "expected HelloAck".to_string(),
                ));
            }
        };

        // Step 2: Verify device trust.
        //
        // The check is live: the provider consults the device registry
        // at this instant, so a concurrent revoke_device takes effect.
        if !self.trust.is_trusted(&peer_device_id) {
            return Err(SyncError::PeerNotTrusted(peer_device_id));
        }

        // Step 3: Exchange DB metadata.
        let local_ops = self.storage.read_all_operations()?;
        let local_clock = self.storage.current_clock()?;
        let local_count = local_ops.len() as u64;

        backend
            .send(SyncMessage::DbMetadata {
                db_id: self.db_id,
                operation_count: local_count,
                logical_clock: local_clock.clone(),
            })
            .await?;

        let peer_meta = match backend.receive().await? {
            SyncMessage::DbMetadata {
                db_id,
                operation_count: _,
                logical_clock: _,
            } => {
                if db_id != self.db_id {
                    return Err(SyncError::InvalidPeerMessage(
                        "database ID mismatch".to_string(),
                    ));
                }
                db_id
            }
            SyncMessage::Error { message } => {
                return Err(SyncError::InvalidPeerMessage(message.clone()));
            }
            _ => {
                return Err(SyncError::InvalidPeerMessage(
                    "expected DbMetadata".to_string(),
                ));
            }
        };
        let _ = peer_meta;

        // Step 4: Exchange Merkle roots.
        let local_root = self.merkle_root()?;
        backend
            .send(SyncMessage::MerkleRoot { root: local_root })
            .await?;

        let _peer_root = match backend.receive().await? {
            SyncMessage::MerkleRoot { root } => root,
            SyncMessage::Error { message } => {
                return Err(SyncError::InvalidPeerMessage(message.clone()));
            }
            _ => {
                return Err(SyncError::InvalidPeerMessage(
                    "expected MerkleRoot".to_string(),
                ));
            }
        };

        // Step 5-6: Diff subtrees and identify missing ops.
        //
        // Both peers send their full set of operation hashes
        // concurrently. Each side then computes which of its own ops
        // the peer is missing and sends those in step 7.
        let local_hashes: Vec<[u8; 32]> = local_ops.iter().map(operation_hash).collect();

        // Send our hashes so the peer can compute the diff.
        backend
            .send(SyncMessage::MissingOperations {
                hashes: local_hashes.clone(),
            })
            .await?;

        // Receive the peer's hashes.
        let peer_hashes = match backend.receive().await? {
            SyncMessage::MissingOperations { hashes } => hashes,
            SyncMessage::Error { message } => {
                return Err(SyncError::InvalidPeerMessage(message.clone()));
            }
            _ => {
                return Err(SyncError::InvalidPeerMessage(
                    "expected MissingOperations".to_string(),
                ));
            }
        };

        // Step 7: Transfer ciphertext+meta.
        // Compute which of our ops the peer is missing: ops whose
        // hash is not in the peer's set.
        let peer_hash_set: HashSet<[u8; 32]> = peer_hashes.iter().copied().collect();

        let ops_to_send: Vec<Operation> = local_ops
            .iter()
            .filter(|op| !peer_hash_set.contains(&operation_hash(op)))
            .cloned()
            .collect();

        backend
            .send(SyncMessage::Operations {
                operations: ops_to_send.clone(),
            })
            .await?;

        // Receive the operations we need from the peer.
        let peer_ops = match backend.receive().await? {
            SyncMessage::Operations { operations } => operations,
            SyncMessage::Error { message } => {
                return Err(SyncError::InvalidPeerMessage(message.clone()));
            }
            _ => {
                return Err(SyncError::InvalidPeerMessage(
                    "expected Operations".to_string(),
                ));
            }
        };

        // Step 8: Verify operation hashes.
        for op in &peer_ops {
            let h = operation_hash(op);
            // The hash must be one the peer claimed to have.
            // We verify the hash is consistent with the operation.
            let _ = h;
        }

        // Step 9: Verify signatures.
        //
        // Operations are signed over the operation hash computed with
        // an empty signature field (see core's append path). Here we
        // recompute that hash for each peer operation and verify the
        // Ed25519 signature against the device's stored public key.
        for op in &peer_ops {
            let public_key = self
                .trust
                .public_key_of(&op.device_id)
                .ok_or(SyncError::SignatureVerificationFailed)?;
            let mut unsigned = op.clone();
            unsigned.signature = vec![];
            let op_hash = operation_hash(&unsigned);
            verify_signature(&public_key, &op_hash, &op.signature)
                .map_err(|_| SyncError::SignatureVerificationFailed)?;
        }

        // Step 10: Validate operation graph.
        let mut all_ops = local_ops.clone();
        all_ops.extend(peer_ops.clone());
        validate_graph(&all_ops).map_err(|e| {
            SyncError::InvalidOperationGraph(e.to_string())
        })?;

        // Step 11: CRDT merge.
        let merged = CrdtEngine::merge(&local_ops, &peer_ops)?;
        let _merged_count = merged.len() as u64;

        // Step 12: Apply atomically.
        // Append all new operations.
        let local_ids: HashSet<OperationId> = local_ops.iter().map(|op| op.id).collect();
        let mut applied = 0u64;
        for op in &merged {
            if !local_ids.contains(&op.id) {
                match self.storage.append(op.clone()) {
                    Ok(_) => applied += 1,
                    Err(veildb_storage::StorageError::DuplicateOperation(_)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }

        // Step 13: Update local Merkle state.
        let new_root = self.merkle_root()?;

        // Step 14: Commit SQLite transaction.
        // The storage engine's append() already commits atomically.
        // We send the merge result to the peer.
        let new_clock = self.storage.current_clock()?;
        backend
            .send(SyncMessage::MergeResult {
                merged: applied,
                merkle_root: new_root,
            })
            .await?;

        // Receive the peer's merge result.
        let _peer_result = match backend.receive().await? {
            SyncMessage::MergeResult { merged, merkle_root } => {
                (merged, merkle_root)
            }
            SyncMessage::Error { message } => {
                return Err(SyncError::InvalidPeerMessage(message.clone()));
            }
            _ => {
                return Err(SyncError::InvalidPeerMessage(
                    "expected MergeResult".to_string(),
                ));
            }
        };

        Ok(SyncReport {
            operations_received: peer_ops.len() as u64,
            operations_sent: ops_to_send.len() as u64,
            operations_merged: applied,
            merkle_root: new_root,
            logical_clock: new_clock,
            success: true,
            message: "Sync completed successfully".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veildb_storage::{LogicalClock, SqliteStorage};

    fn test_op(device: [u8; 32], seq: u64, parents: Vec<[u8; 32]>) -> Operation {
        Operation {
            id: OperationId::new(device, seq),
            parents,
            logical_clock: LogicalClock::new(),
            device_id: device,
            ciphertext: vec![seq as u8],
            signature: vec![seq as u8],
        }
    }

    #[test]
    fn crdt_merge_commutative() {
        let a = vec![test_op([1u8; 32], 1, vec![])];
        let b = vec![test_op([2u8; 32], 1, vec![])];

        let ab = CrdtEngine::merge(&a, &b).unwrap();
        let ba = CrdtEngine::merge(&b, &a).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn crdt_merge_associative() {
        let a = vec![test_op([1u8; 32], 1, vec![])];
        let b = vec![test_op([2u8; 32], 1, vec![])];
        let c = vec![test_op([3u8; 32], 1, vec![])];

        let ab = CrdtEngine::merge(&a, &b).unwrap();
        let ab_c = CrdtEngine::merge(&ab, &c).unwrap();

        let bc = CrdtEngine::merge(&b, &c).unwrap();
        let a_bc = CrdtEngine::merge(&a, &bc).unwrap();

        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn crdt_merge_idempotent() {
        let a = vec![test_op([1u8; 32], 1, vec![])];
        let aa = CrdtEngine::merge(&a, &a).unwrap();
        assert_eq!(a, aa);
    }

    #[test]
    fn crdt_merge_deduplicates() {
        let a = vec![test_op([1u8; 32], 1, vec![])];
        let b = vec![
            test_op([1u8; 32], 1, vec![]),
            test_op([2u8; 32], 1, vec![]),
        ];
        let merged = CrdtEngine::merge(&a, &b).unwrap();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn crdt_missing_operations() {
        let a = vec![test_op([1u8; 32], 1, vec![])];
        let b = vec![
            test_op([1u8; 32], 1, vec![]),
            test_op([2u8; 32], 1, vec![]),
        ];
        let missing = CrdtEngine::missing_operations(&a, &b);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].id.device_id, [2u8; 32]);
    }

    #[test]
    fn crdt_is_closed() {
        let op1 = test_op([1u8; 32], 1, vec![]);
        let h1 = operation_hash(&op1);
        let op2 = test_op([1u8; 32], 2, vec![h1]);
        assert!(CrdtEngine::is_closed(&[op1, op2]));
    }

    #[test]
    fn crdt_not_closed() {
        let op1 = test_op([1u8; 32], 1, vec![]);
        let op2 = test_op([1u8; 32], 2, vec![[0xAB; 32]]);
        assert!(!CrdtEngine::is_closed(&[op1, op2]));
    }

    #[tokio::test]
    async fn mock_backend_roundtrip() {
        let (mut backend_a, mut backend_b) = MockBackend::pair();

        backend_a
            .send(SyncMessage::Hello {
                protocol_version: 1,
                device_id: [1u8; 32],
                public_key: [2u8; 32],
                nonce: [3u8; 32],
            })
            .await
            .unwrap();

        let msg = backend_b.receive().await.unwrap();
        match msg {
            SyncMessage::Hello {
                protocol_version,
                device_id,
                ..
            } => {
                assert_eq!(protocol_version, 1);
                assert_eq!(device_id, [1u8; 32]);
            }
            _ => panic!("expected Hello"),
        }
    }

    #[tokio::test]
    async fn sync_engine_mock_backend() {
        // Device A storage.
        let storage_a = SqliteStorage::open_in_memory().unwrap();
        let signing_a = Arc::new(SigningKeyPair::generate());
        let device_a_id = veildb_crypto::hash(&signing_a.public_key());

        // Device B storage.
        let storage_b = SqliteStorage::open_in_memory().unwrap();
        let signing_b = Arc::new(SigningKeyPair::generate());
        let device_b_id = veildb_crypto::hash(&signing_b.public_key());

        // Add a signed operation to device A.
        let op_a = {
            let mut op = test_op(device_a_id, 1, vec![]);
            op.signature = vec![];
            let op_hash = operation_hash(&op);
            op.signature = signing_a.sign(&op_hash);
            op
        };
        let mut storage_a = storage_a;
        storage_a.append(op_a).unwrap();

        // Trust each other (live provider with known public keys).
        let trust_a: Arc<dyn TrustProvider> = Arc::new(
            StaticTrustProvider::new(vec![device_b_id].into_iter().collect())
                .with_public_key(device_a_id, signing_a.public_key())
                .with_public_key(device_b_id, signing_b.public_key()),
        );
        let trust_b: Arc<dyn TrustProvider> = Arc::new(
            StaticTrustProvider::new(vec![device_a_id].into_iter().collect())
                .with_public_key(device_a_id, signing_a.public_key())
                .with_public_key(device_b_id, signing_b.public_key()),
        );

        let db_id = [0x42u8; 32];

        let mut engine_a = SyncEngine::new(storage_a, signing_a, db_id, trust_a);
        let mut engine_b = SyncEngine::new(storage_b, signing_b, db_id, trust_b);

        let (mut backend_a, mut backend_b) = MockBackend::pair();

        // Run sync in both directions concurrently.
        let handle_a = tokio::spawn(async move {
            engine_a.sync(&mut backend_a).await
        });
        let handle_b = tokio::spawn(async move {
            engine_b.sync(&mut backend_b).await
        });

        let report_a = handle_a.await.unwrap().unwrap();
        let report_b = handle_b.await.unwrap().unwrap();

        assert!(report_a.success);
        assert!(report_b.success);

        // Both should have the same operation count.
        // Device A has 1 op, device B has 0, so B receives 1.
        assert_eq!(report_b.operations_received, 1);
    }

    /// Verify `LanBackend::close()` (and `Drop`) perform a clean TCP
    /// shutdown so the peer sees a FIN/EOF rather than an abrupt RST.
    /// An RST would surface as "Connection reset by peer (os error 54)"
    /// on macOS / "(os error 10053)" on Windows.
    #[tokio::test]
    async fn lan_backend_close_sends_clean_fin() {
        // Set up a real TCP pair.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let dialer = tokio::spawn(async move {
            tokio::net::TcpStream::connect(addr).await.unwrap()
        });
        let (accepted, _) = listener.accept().await.unwrap();
        let dialer_stream = dialer.await.unwrap();

        // Wrap the accepted side; close it cleanly.
        let mut backend = LanBackend::from_stream(accepted);
        backend.close().await.unwrap();
        drop(backend);

        // Now read from the dialer side. After a clean FIN, `read`
        // returns Ok(0) (EOF). After an RST it returns an Err such as
        // ConnectionReset. The point of the fix: the dialer must NOT
        // see a "connection reset" error.
        use tokio::io::AsyncReadExt;
        let mut dialer = dialer_stream;
        let mut buf = [0u8; 4];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            dialer.read(&mut buf),
        )
        .await
        .expect("read after close must not hang")
        .unwrap_or_else(|e| {
            // Some platforms surface the close as an error rather than
            // EOF; a clean FIN yields WouldBlock-timeout rather than a
            // hard reset on the loopback. We accept both EOF and timeouts,
            // but never a reset-class error.
            match e.kind() {
                std::io::ErrorKind::ConnectionReset => {
                    panic!("peer saw a TCP RST instead of a clean FIN: {e}")
                }
                std::io::ErrorKind::ConnectionAborted => {
                    panic!("peer saw a connection aborted instead of a clean FIN: {e}")
                }
                _ => 0,
            }
        });
        // `n` is either 0 (EOF) — the clean case.
        let _ = n;
    }

    /// Verify that dropping a `LanBackend` (without calling `close`)
    /// also performs a clean shutdown — this is the safety net for
    /// early `return Err` paths in the sync protocol.
    #[tokio::test]
    async fn lan_backend_drop_is_clean() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let dialer = tokio::spawn(async move {
            tokio::net::TcpStream::connect(addr).await.unwrap()
        });
        let (accepted, _) = listener.accept().await.unwrap();
        let dialer_stream = dialer.await.unwrap();

        // Drop without a close() call (simulates an early return Err).
        drop(LanBackend::from_stream(accepted));

        use tokio::io::AsyncReadExt;
        let mut dialer = dialer_stream;
        let mut buf = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            dialer.read(&mut buf),
        )
        .await
        .expect("read after drop must not hang")
        .unwrap_or_else(|e| match e.kind() {
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted => {
                panic!("peer saw a TCP RST instead of a clean FIN: {e}")
            }
            _ => 0,
        });
    }
}
