//! Core data types for the storage layer.
//!
//! These types are shared across the workspace and represent the
//! fundamental operation model of VeilDB.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A globally unique operation identifier.
///
/// Operations are identified by the device that created them and a
/// per-device monotonic sequence number. This makes operations globally
/// distinguishable while allowing each device to create them independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OperationId {
    /// The device that created this operation.
    pub device_id: [u8; 32],
    /// Per-device monotonic sequence number.
    pub sequence: u64,
}

impl OperationId {
    /// Create a new operation ID.
    pub fn new(device_id: [u8; 32], sequence: u64) -> Self {
        Self { device_id, sequence }
    }
}

/// A logical clock value for ordering operations.
///
/// Uses a vector clock (device_id → counter) rather than wall-clock
/// timestamps to avoid clock-skew issues in conflict resolution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LogicalClock {
    /// Vector clock entries: (device_id, counter).
    pub entries: Vec<([u8; 32], u64)>,
}

impl LogicalClock {
    /// Create an empty logical clock.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Advance the clock for a given device.
    pub fn advance(&mut self, device_id: [u8; 32]) {
        for (id, counter) in self.entries.iter_mut() {
            if *id == device_id {
                *counter += 1;
                return;
            }
        }
        self.entries.push((device_id, 1));
    }

    /// Merge another clock into this one (element-wise max).
    pub fn merge(&mut self, other: &LogicalClock) {
        for (other_id, other_counter) in &other.entries {
            let mut found = false;
            for (id, counter) in self.entries.iter_mut() {
                if id == other_id {
                    *counter = (*counter).max(*other_counter);
                    found = true;
                    break;
                }
            }
            if !found {
                self.entries.push((*other_id, *other_counter));
            }
        }
        self.entries.sort();
    }

    /// Check if this clock is at or after another clock.
    pub fn dominates(&self, other: &LogicalClock) -> bool {
        for (other_id, other_counter) in &other.entries {
            let mut found = false;
            for (id, counter) in &self.entries {
                if id == other_id {
                    if counter < other_counter {
                        return false;
                    }
                    found = true;
                    break;
                }
            }
            if !found {
                return false;
            }
        }
        true
    }
}

impl Default for LogicalClock {
    fn default() -> Self {
        Self::new()
    }
}

/// A single operation in the append-only log.
///
/// The `ciphertext` field is opaque to the storage, integrity, and sync
/// layers — only the crypto layer can decrypt it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    /// Unique operation identifier.
    pub id: OperationId,
    /// Hashes of parent operations (multi-parent DAG, not a linear chain).
    pub parents: Vec<[u8; 32]>,
    /// Logical clock at the time of creation.
    pub logical_clock: LogicalClock,
    /// Device that created this operation.
    pub device_id: [u8; 32],
    /// Encrypted payload (opaque to storage/integrity/sync).
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature over the canonical serialization.
    pub signature: Vec<u8>,
}

/// A snapshot of the database state at a point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Logical clock at snapshot time.
    pub logical_clock: LogicalClock,
    /// Hash of the last operation included in this snapshot.
    pub last_operation: [u8; 32],
    /// Serialized database state.
    pub state: Vec<u8>,
    /// Merkle root of all operations up to this snapshot.
    pub merkle_root: [u8; 32],
}

/// A snapshot ID (row ID in the snapshots table).
pub type SnapshotId = i64;

/// A device entry in the trust store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// Device identifier (hash of public key).
    pub device_id: [u8; 32],
    /// Ed25519 public key.
    pub public_key: Vec<u8>,
    /// Whether this device is trusted.
    pub trusted: bool,
    /// Device that approved this one (None for the root device).
    pub approved_by: Option<[u8; 32]>,
    /// Signature of the approval.
    pub approval_signature: Option<Vec<u8>>,
    /// Creation timestamp (unix epoch seconds).
    pub created_at: i64,
}

/// A secret string that zeroizes on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretString(String);

impl SecretString {
    /// Create a new secret string.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Get the string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString(***)")
    }
}

/// A persisted record of one deterministic CRDT conflict resolution.
///
/// Written after a sync merge when two or more operations touched the
/// same logical key. Identical (key, winner, loser) triples are only
/// ever recorded once, so the log is idempotent across repeated syncs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeLogEntry {
    /// Row ID of the merge-log entry.
    pub id: i64,
    /// The logical key the conflicting operations wrote to.
    pub key: String,
    /// The operation that deterministically won.
    pub winner: OperationId,
    /// The operation that lost, if a single loser could be identified.
    pub loser: Option<OperationId>,
    /// The resolution rule applied ("causal-dominance" or
    /// "concurrent-device-tiebreak").
    pub rule: String,
    /// Unix timestamp of when the entry was recorded.
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_clock_advance_and_merge() {
        let mut clock_a = LogicalClock::new();
        clock_a.advance([1u8; 32]);
        clock_a.advance([1u8; 32]);
        assert_eq!(clock_a.entries, vec![([1u8; 32], 2)]);

        let mut clock_b = LogicalClock::new();
        clock_b.advance([2u8; 32]);
        clock_b.advance([2u8; 32]);
        clock_b.advance([2u8; 32]);

        clock_a.merge(&clock_b);
        assert_eq!(
            clock_a.entries,
            vec![([1u8; 32], 2), ([2u8; 32], 3)]
        );
    }

    #[test]
    fn logical_clock_dominates() {
        let mut clock_a = LogicalClock::new();
        clock_a.advance([1u8; 32]);
        clock_a.advance([1u8; 32]);

        let mut clock_b = LogicalClock::new();
        clock_b.advance([1u8; 32]);

        assert!(clock_a.dominates(&clock_b));
        assert!(!clock_b.dominates(&clock_a));
    }

    #[test]
    fn operation_id_roundtrip() {
        let id = OperationId::new([7u8; 32], 42);
        let bytes = postcard::to_allocvec(&id).unwrap();
        let decoded: OperationId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(id, decoded);
    }
}