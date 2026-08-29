//! Error types for the sync layer.

use thiserror::Error;

/// Errors that can occur in the sync layer.
#[derive(Debug, Error)]
pub enum SyncError {
    /// The peer is not trusted.
    #[error("Peer not trusted: {0:?}")]
    PeerNotTrusted([u8; 32]),

    /// The peer failed authentication.
    #[error("Peer authentication failed")]
    PeerAuthenticationFailed,

    /// The peer's device was revoked.
    #[error("Peer device revoked: {0:?}")]
    PeerRevoked([u8; 32]),

    /// An operation hash verification failed.
    #[error("Operation hash verification failed")]
    OperationHashVerificationFailed,

    /// An operation signature verification failed.
    #[error("Operation signature verification failed")]
    SignatureVerificationFailed,

    /// The operation graph is invalid.
    #[error("Invalid operation graph: {0}")]
    InvalidOperationGraph(String),

    /// The peer sent an invalid message.
    #[error("Invalid peer message: {0}")]
    InvalidPeerMessage(String),

    /// The connection was dropped.
    #[error("Connection dropped")]
    ConnectionDropped,

    /// The transport is not supported.
    #[error("Unsupported transport: {0}")]
    UnsupportedTransport(String),

    /// The backend is not available.
    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    Storage(#[from] veildb_storage::StorageError),

    /// Crypto error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] veildb_crypto::error::CryptoError),

    /// Integrity error.
    #[error("Integrity error: {0}")]
    Integrity(#[from] veildb_integrity::error::IntegrityError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The feature or subsystem is not implemented yet.
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

impl From<postcard::Error> for SyncError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}