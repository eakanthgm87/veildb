//! VeilDB storage layer.
//!
//! This crate is the physical persistence layer for VeilDB. It manages
//! the SQLite database lifecycle, migrations, and all CRUD operations
//! for operations, snapshots, devices, and metadata.
//!
//! The storage layer never decrypts data, generates keys, verifies
//! signatures, CRDT-merges, or touches the network. It depends on
//! nothing else in the workspace.

pub mod engine;
pub mod error;
pub mod types;

pub use engine::{SCHEMA_VERSION, SqliteStorage, StorageEngine};
pub use error::StorageError;
pub use types::{
    DeviceEntry, LogicalClock, MergeLogEntry, Operation, OperationId, SecretString, Snapshot,
    SnapshotId,
};