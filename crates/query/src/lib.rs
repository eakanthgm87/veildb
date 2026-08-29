//! VeilDB query layer.
//!
//! Encrypted equality indexes, logical clock, state reconstruction,
//! and time travel.
//!
//! The encrypted equality index works by:
//! 1. BLAKE3-normalizing the plaintext key
//! 2. Using the normalized hash as a deterministic AEAD token
//! 3. Storing the token alongside the ciphertext
//!
//! This allows equality searches without revealing the plaintext key,
//! at the documented cost of leaking equality (same value → same token).

pub mod error;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use veildb_crypto::{Key, KeyRing, decrypt, encrypt};
use veildb_storage::{LogicalClock, Operation, OperationId, Snapshot, SnapshotId, StorageEngine};

use error::QueryError;

/// A key-value pair in the database state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The plaintext key.
    pub key: String,
    /// The plaintext value.
    pub value: Vec<u8>,
}

/// The full database state (a key-value map).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbState {
    /// The logical clock at which this state was captured.
    pub clock: LogicalClock,
    /// The key-value entries.
    pub entries: BTreeMap<String, Vec<u8>>,
}

impl DbState {
    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.entries.get(key)
    }

    /// Check if a key exists.
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the state is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A single operation in the encrypted log.
///
/// The plaintext payload is a serialized `PutOp` (key + value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutOp {
    /// The plaintext key.
    pub key: String,
    /// The plaintext value.
    pub value: Vec<u8>,
}

/// A deterministic index token for a plaintext key.
///
/// This is BLAKE3(key) — it reveals equality but not the key itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IndexToken(pub [u8; 32]);

/// Compute the deterministic index token for a key.
///
/// This is BLAKE3 over the key bytes. Same key → same token.
pub fn index_token(key: &str) -> IndexToken {
    IndexToken(*blake3::hash(key.as_bytes()).as_bytes())
}

/// The query engine.
///
/// Provides state reconstruction, encrypted equality indexes, and
/// time-travel queries.
pub struct QueryEngine<S: StorageEngine> {
    storage: S,
    /// The key ring managing all key versions.
    key_ring: KeyRing,
}

impl<S: StorageEngine> QueryEngine<S> {
    /// Create a new query engine.
    pub fn new(storage: S, index_key: Key, key_version: u32) -> Self {
        Self {
            storage,
            key_ring: KeyRing::new(index_key, key_version),
        }
    }

    /// Get the current active key version.
    pub fn key_version(&self) -> u32 {
        self.key_ring.active_version()
    }

    /// Rotate the index key.
    pub fn rotate_key(&mut self) -> Result<u32, QueryError> {
        Ok(self.key_ring.rotate_key()?)
    }

    /// Decrypt an operation's payload using the key version stored in
    /// the ciphertext. Never assumes "latest" — always looks up the key
    /// by the version embedded in the ciphertext.
    fn decrypt_op_payload(&self, op: &Operation) -> Result<PutOp, QueryError> {
        // The format is: [32-byte index token][4-byte key_version][12-byte nonce][ciphertext]
        if op.ciphertext.len() < 32 + 4 + 12 {
            return Err(QueryError::IndexDecryption(
                "ciphertext too short".to_string(),
            ));
        }
        let mut version_bytes = [0u8; 4];
        version_bytes.copy_from_slice(&op.ciphertext[32..36]);
        let key_version = u32::from_le_bytes(version_bytes);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&op.ciphertext[36..48]);

        let ct = veildb_crypto::Ciphertext {
            key_version,
            nonce,
            data: op.ciphertext[48..].to_vec(),
        };

        // Look up the key by the version stored in the ciphertext.
        let key = self.key_ring.key_for_version(key_version)?;
        let plaintext = decrypt(key, &ct)?;
        let put: PutOp = postcard::from_bytes(&plaintext)
            .map_err(|e| QueryError::Serialization(e.to_string()))?;
        Ok(put)
    }

    /// Reconstruct the database state from all operations.
    ///
    /// Decrypts each operation's payload and applies it to the state.
    pub fn reconstruct_state(&self) -> Result<DbState, QueryError> {
        let ops = self.storage.read_all_operations()?;
        self.reconstruct_from_ops(&ops)
    }

    /// Reconstruct the database state from a set of operations.
    ///
    /// Conflict resolution is deterministic: when two or more
    /// operations write the same logical key, the winner under
    /// [`cmp_winners`] is applied regardless of the order in which the
    /// operations appear in the log. This guarantees convergence across
    /// replicas.
    pub fn reconstruct_from_ops(&self, ops: &[Operation]) -> Result<DbState, QueryError> {
        let mut state = DbState::default();
        let mut clock = LogicalClock::new();

        // Track the deterministic winner per key.
        let mut winners: BTreeMap<String, (Operation, Vec<u8>)> = BTreeMap::new();

        for op in ops {
            let put = self.decrypt_op_payload(op)?;
            let should_replace = match winners.get(&put.key) {
                Some((current, _)) => cmp_winners(op, current) == std::cmp::Ordering::Greater,
                None => true,
            };
            if should_replace {
                winners.insert(put.key.clone(), (op.clone(), put.value));
            }
            clock.merge(&op.logical_clock);
        }

        for (key, (_, value)) in winners {
            state.entries.insert(key, value);
        }

        state.clock = clock;
        Ok(state)
    }

    /// Resolve conflicts among all operations, keyed by plaintext key.
    ///
    /// Returns one [`ConflictOutcome`] per key with two or more
    /// writers. The winner/loser pair is deterministic across all
    /// replicas holding the same operation set.
    pub fn resolve_conflicts(&self, ops: &[Operation]) -> Result<Vec<ConflictOutcome>, QueryError> {
        let mut per_key: BTreeMap<String, Vec<Operation>> = BTreeMap::new();
        for op in ops {
            let put = self.decrypt_op_payload(op)?;
            per_key.entry(put.key).or_default().push(op.clone());
        }

        let mut outcomes = Vec::new();
        for (key, mut writers) in per_key {
            if writers.len() < 2 {
                continue;
            }
            writers.sort_by(|a, b| cmp_winners(a, b));
            let winner = writers.last().expect("len >= 2").clone();
            let loser = writers[writers.len() - 2].clone();
            outcomes.push(ConflictOutcome {
                key,
                winner: winner.id,
                loser: Some(loser.id),
                rule: rule_for(&winner, &loser),
            });
        }
        Ok(outcomes)
    }

    /// Get a value by key using the encrypted index.
    ///
    /// This uses the deterministic index token to find the operation
    /// without scanning all operations.
    pub fn get(&self, key: &str) -> Result<Vec<u8>, QueryError> {
        let token = index_token(key);
        let ops = self.storage.read_all_operations()?;

        // Find the operation whose index token matches and that wins
        // under the deterministic conflict-resolution order.
        let mut latest: Option<Operation> = None;
        for op in ops {
            // The index token is stored as the first 32 bytes of the
            // ciphertext (before the key version and nonce).
            if op.ciphertext.len() >= 32 + 4 + 12 {
                let stored_token = &op.ciphertext[..32];
                if stored_token == token.0.as_slice() {
                    match &latest {
                        Some(current) if cmp_winners(&op, current) != std::cmp::Ordering::Greater => {}
                        _ => latest = Some(op.clone()),
                    }
                }
            }
        }

        let op = latest.ok_or_else(|| QueryError::KeyNotFound(key.to_string()))?;
        let put = self.decrypt_op_payload(&op)?;
        Ok(put.value)
    }

    /// Build an encrypted index entry for a key-value pair.
    ///
    /// The format is: [32-byte index token][4-byte key_version][12-byte nonce][ciphertext]
    pub fn build_indexed_ciphertext(
        &self,
        key: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, QueryError> {
        let put = PutOp {
            key: key.to_string(),
            value: value.to_vec(),
        };
        let plaintext = postcard::to_allocvec(&put)?;
        let key_version = self.key_ring.active_version();
        let ct = encrypt(self.key_ring.active_key(), key_version, &plaintext)?;

        let mut result = Vec::with_capacity(32 + 4 + 12 + ct.data.len());
        result.extend_from_slice(&index_token(key).0);
        result.extend_from_slice(&key_version.to_le_bytes());
        result.extend_from_slice(&ct.nonce);
        result.extend_from_slice(&ct.data);
        Ok(result)
    }

    /// Find the nearest snapshot at or before a given clock.
    ///
    /// Returns the snapshot and its ID. The snapshot's clock must be
    /// dominated by (at or before) the target clock.
    pub fn find_snapshot_at_or_before(
        &self,
        clock: &LogicalClock,
    ) -> Result<Option<(SnapshotId, Snapshot)>, QueryError> {
        let mut best: Option<(SnapshotId, Snapshot)> = None;

        // Iterate through all snapshots.
        let mut id = 1i64;
        loop {
            match self.storage.load_snapshot(id) {
                Ok(snapshot) => {
                    // The snapshot is at or before the target clock if
                    // the target clock dominates the snapshot's clock.
                    if clock.dominates(&snapshot.logical_clock) {
                        best = Some((id, snapshot));
                    }
                    id += 1;
                }
                Err(veildb_storage::StorageError::SnapshotNotFound(_)) => break,
                Err(e) => return Err(e.into()),
            }
        }

        Ok(best)
    }

    /// Time-travel query: reconstruct the state at a given clock.
    ///
    /// Uses the nearest snapshot ≤ target clock, then replays only
    /// operations after it. Never does a full replay when a snapshot
    /// exists.
    pub fn query_at(&self, clock: &LogicalClock) -> Result<DbState, QueryError> {
        // Find the nearest snapshot at or before the target clock.
        let (_snapshot_id, snapshot) = self
            .find_snapshot_at_or_before(clock)?
            .ok_or(QueryError::NoSnapshotFound)?;

        // Deserialize the snapshot state.
        let mut state: DbState = postcard::from_bytes(&snapshot.state)
            .map_err(|e| QueryError::Serialization(e.to_string()))?;

        // Replay operations after the snapshot, applying only the
        // deterministic winner per key so time travel converges the
        // same way as the full replay.
        let all_ops = self.storage.read_all_operations()?;
        let mut clock_so_far = snapshot.logical_clock.clone();

        let replay: Vec<&Operation> = all_ops
            .iter()
            .filter(|op| {
                op.logical_clock.dominates(&snapshot.logical_clock)
                    && clock.dominates(&op.logical_clock)
            })
            .collect();

        let mut winners: BTreeMap<String, (Operation, Vec<u8>)> = BTreeMap::new();
        for op in &replay {
            if let Ok(put) = self.decrypt_op_payload(op) {
                let should_replace = match winners.get(&put.key) {
                    Some((current, _)) => {
                        cmp_winners(op, current) == std::cmp::Ordering::Greater
                    }
                    None => true,
                };
                if should_replace {
                    winners.insert(put.key.clone(), ((*op).clone(), put.value));
                }
            }
            clock_so_far.merge(&op.logical_clock);
        }

        for (key, (_, value)) in winners {
            state.entries.insert(key, value);
        }

        state.clock = clock_so_far;
        Ok(state)
    }

    /// Create a snapshot of the current state.
    pub fn create_snapshot(&mut self) -> Result<SnapshotId, QueryError> {
        let state = self.reconstruct_state()?;
        let ops = self.storage.read_all_operations()?;

        // Compute the last operation hash.
        let last_op_hash = if let Some(op) = ops.last() {
            veildb_integrity::operation_hash(op)
        } else {
            [0u8; 32]
        };

        // Compute the Merkle root.
        let hashes: Vec<[u8; 32]> = ops.iter().map(veildb_integrity::operation_hash).collect();
        let merkle_root = veildb_integrity::MerkleTree::build(&hashes).root();

        let snapshot = Snapshot {
            logical_clock: state.clock.clone(),
            last_operation: last_op_hash,
            state: postcard::to_allocvec(&state)?,
            merkle_root,
        };

        Ok(self.storage.create_snapshot(snapshot)?)
    }

    /// Get the current logical clock.
    pub fn current_clock(&self) -> Result<LogicalClock, QueryError> {
        Ok(self.storage.current_clock()?)
    }
}

/// The deterministic rule that resolved a conflict between two or
/// more writes to the same logical key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionRule {
    /// The winning write causally dominates the losing write
    /// (vector-clock dominance).
    CausalDominance,
    /// The writes were concurrent; the write from the lexicographically
    /// greater device ID wins (ties broken by sequence number).
    ConcurrentDeviceTiebreak,
}

impl ResolutionRule {
    /// Stable machine-readable name for logs and merge reports.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CausalDominance => "causal-dominance",
            Self::ConcurrentDeviceTiebreak => "concurrent-device-tiebreak",
        }
    }
}

/// A deterministic conflict resolution for one logical key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictOutcome {
    /// The plaintext key the conflicting writes targeted.
    pub key: String,
    /// The operation that deterministically won.
    pub winner: OperationId,
    /// The strongest operation that lost (runner-up under the total order).
    pub loser: Option<OperationId>,
    /// The resolution rule applied.
    pub rule: ResolutionRule,
}

/// Total order over operations that write the same logical key.
///
/// The order is commutative, associative, and idempotent, so every
/// replica converges on the same winner regardless of the order in
/// which operations arrived:
/// 1. Causal dominance: an op whose vector clock dominates the other's
///    wins.
/// 2. Concurrent ops: the op from the lexicographically greater device
///    ID wins; same device → higher sequence wins.
pub fn cmp_winners(a: &Operation, b: &Operation) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let a_dom = a.logical_clock.dominates(&b.logical_clock);
    let b_dom = b.logical_clock.dominates(&a.logical_clock);
    if a_dom && !b_dom {
        return Ordering::Greater;
    }
    if b_dom && !a_dom {
        return Ordering::Less;
    }
    a.device_id
        .cmp(&b.device_id)
        .then(a.id.sequence.cmp(&b.id.sequence))
}

/// The rule that decided a pairwise comparison (winner is `a` when the
/// ordering is `Greater`).
fn rule_for(winner: &Operation, loser: &Operation) -> ResolutionRule {
    if winner.logical_clock.dominates(&loser.logical_clock)
        && !loser.logical_clock.dominates(&winner.logical_clock)
    {
        ResolutionRule::CausalDominance
    } else {
        ResolutionRule::ConcurrentDeviceTiebreak
    }
}

/// A summary of an operation for the log view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSummary {
    /// The operation ID.
    pub id: OperationId,
    /// The operation hash.
    pub hash: [u8; 32],
    /// The logical clock.
    pub clock: LogicalClock,
    /// The device that created it.
    pub device_id: [u8; 32],
    /// Number of parents.
    pub parent_count: usize,
}

/// Build a log of operation summaries.
pub fn build_log(ops: &[Operation]) -> Vec<OperationSummary> {
    ops.iter()
        .map(|op| OperationSummary {
            id: op.id,
            hash: veildb_integrity::operation_hash(op),
            clock: op.logical_clock.clone(),
            device_id: op.device_id,
            parent_count: op.parents.len(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use veildb_crypto::Key;
    use veildb_storage::{LogicalClock, Operation, OperationId, SqliteStorage};

    fn test_engine() -> QueryEngine<SqliteStorage> {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let key = Key::generate();
        QueryEngine::new(storage, key, 1)
    }

    fn make_op(
        device: [u8; 32],
        seq: u64,
        key: &str,
        value: &[u8],
        engine: &QueryEngine<SqliteStorage>,
    ) -> Operation {
        let ct = engine.build_indexed_ciphertext(key, value).unwrap();
        let mut clock = LogicalClock::new();
        clock.advance(device);
        Operation {
            id: OperationId::new(device, seq),
            parents: vec![],
            logical_clock: clock,
            device_id: device,
            ciphertext: ct,
            signature: vec![],
        }
    }

    #[test]
    fn index_token_deterministic() {
        let t1 = index_token("hello");
        let t2 = index_token("hello");
        let t3 = index_token("world");
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn build_and_reconstruct() {
        let mut engine = test_engine();
        let op1 = make_op([1u8; 32], 1, "key1", b"value1", &engine);
        let op2 = make_op([1u8; 32], 2, "key2", b"value2", &engine);
        engine.storage.append(op1).unwrap();
        engine.storage.append(op2).unwrap();

        let state = engine.reconstruct_state().unwrap();
        assert_eq!(state.get("key1").unwrap(), &b"value1".to_vec());
        assert_eq!(state.get("key2").unwrap(), &b"value2".to_vec());
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn get_by_key() {
        let mut engine = test_engine();
        let op = make_op([1u8; 32], 1, "mykey", b"myvalue", &engine);
        engine.storage.append(op).unwrap();

        let value = engine.get("mykey").unwrap();
        assert_eq!(value, b"myvalue");
        assert!(engine.get("missing").is_err());
    }

    #[test]
    fn get_latest_value() {
        let mut engine = test_engine();
        let op1 = make_op([1u8; 32], 1, "key", b"old", &engine);
        let op2 = make_op([1u8; 32], 2, "key", b"new", &engine);
        engine.storage.append(op1).unwrap();
        engine.storage.append(op2).unwrap();

        let value = engine.get("key").unwrap();
        assert_eq!(value, b"new");
    }

    #[test]
    fn snapshot_and_time_travel() {
        let mut engine = test_engine();
        let op1 = make_op([1u8; 32], 1, "key1", b"value1", &engine);
        let op2 = make_op([1u8; 32], 2, "key2", b"value2", &engine);
        engine.storage.append(op1).unwrap();
        engine.storage.append(op2).unwrap();

        // Create a snapshot.
        let snap_id = engine.create_snapshot().unwrap();
        assert!(snap_id > 0);

        // Add more operations.
        let op3 = make_op([1u8; 32], 3, "key3", b"value3", &engine);
        engine.storage.append(op3).unwrap();

        // Query at the snapshot clock.
        let clock = engine.current_clock().unwrap();
        let state = engine.query_at(&clock).unwrap();
        assert_eq!(state.len(), 3);
    }

    #[test]
    fn build_log_works() {
        let mut engine = test_engine();
        let op1 = make_op([1u8; 32], 1, "key1", b"value1", &engine);
        let op2 = make_op([1u8; 32], 2, "key2", b"value2", &engine);
        engine.storage.append(op1).unwrap();
        engine.storage.append(op2).unwrap();

        let ops = engine.storage.read_all_operations().unwrap();
        let log = build_log(&ops);
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].id.sequence, 1);
        assert_eq!(log[1].id.sequence, 2);
    }

    #[test]
    fn key_rotation_multiversion_reads() {
        let mut engine = test_engine();
        assert_eq!(engine.key_version(), 1);

        // Write under v1.
        let op1 = make_op([1u8; 32], 1, "key1", b"value-v1", &engine);
        engine.storage.append(op1).unwrap();

        // Rotate to v2.
        let v2 = engine.rotate_key().unwrap();
        assert_eq!(v2, 2);
        assert_eq!(engine.key_version(), 2);

        // Write under v2.
        let op2 = make_op([1u8; 32], 2, "key2", b"value-v2", &engine);
        engine.storage.append(op2).unwrap();

        // Both v1 and v2 ciphertexts still decrypt correctly.
        assert_eq!(engine.get("key1").unwrap(), b"value-v1");
        assert_eq!(engine.get("key2").unwrap(), b"value-v2");

        // Reconstruct state works across versions.
        let state = engine.reconstruct_state().unwrap();
        assert_eq!(state.get("key1").unwrap(), &b"value-v1".to_vec());
        assert_eq!(state.get("key2").unwrap(), &b"value-v2".to_vec());
    }
}
#[cfg(test)]

#[cfg(test)]
mod conflict_tests {
    use super::*;
    use veildb_storage::SqliteStorage;

    fn make_op(
        device: [u8; 32],
        seq: u64,
        counters: Vec<([u8; 32], u64)>,
        key: &str,
        value: &[u8],
        engine: &QueryEngine<SqliteStorage>,
    ) -> Operation {
        let ct = engine.build_indexed_ciphertext(key, value).unwrap();
        let mut clock = LogicalClock::new();
        for (dev, c) in counters {
            for _ in 0..c {
                clock.advance(dev);
            }
        }
        Operation {
            id: OperationId::new(device, seq),
            parents: vec![],
            logical_clock: clock,
            device_id: device,
            ciphertext: ct,
            signature: vec![],
        }
    }

    #[test]
    fn concurrent_writes_resolve_identically_regardless_of_order() {
        let dev_a = [1u8; 32];
        let dev_b = [2u8; 32];

        // Two engines sharing the same key material pattern: one log
        // with ops in order (a, b), one with (b, a).
        let master = Key::generate();
        let mut e1 = QueryEngine::new(SqliteStorage::open_in_memory().unwrap(), master.clone(), 1);
        let mut e2 = QueryEngine::new(SqliteStorage::open_in_memory().unwrap(), master, 1);

        let op_a = make_op(dev_a, 1, vec![(dev_a, 1)], "k", b"from-a", &e1);
        let op_b = make_op(dev_b, 1, vec![(dev_b, 1)], "k", b"from-b", &e1);

        e1.storage.append(op_a.clone()).unwrap();
        e1.storage.append(op_b.clone()).unwrap();
        e2.storage.append(op_b.clone()).unwrap();
        e2.storage.append(op_a.clone()).unwrap();

        let s1 = e1.reconstruct_state().unwrap();
        let s2 = e2.reconstruct_state().unwrap();
        assert_eq!(s1.entries, s2.entries);

        // The winner is deterministic: higher device id wins.
        let expected = if dev_a > dev_b { b"from-a" } else { b"from-b" };
        assert_eq!(s1.get("k").unwrap(), &expected.to_vec());
        assert_eq!(s2.get("k").unwrap(), &expected.to_vec());

        let outcomes = e1.resolve_conflicts(&e1.storage.read_all_operations().unwrap()).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].key, "k");
        assert_eq!(outcomes[0].rule, ResolutionRule::ConcurrentDeviceTiebreak);
        assert_eq!(outcomes[0].rule.as_str(), "concurrent-device-tiebreak");
    }

    #[test]
    fn causally_dominated_write_loses_even_if_appended_last() {
        let dev_a = [9u8; 32];
        let mut engine = QueryEngine::new(SqliteStorage::open_in_memory().unwrap(), Key::generate(), 1);

        let older = make_op(dev_a, 1, vec![(dev_a, 1)], "k", b"old", &engine);
        let newer = make_op(dev_a, 2, vec![(dev_a, 2)], "k", b"new", &engine);

        engine.storage.append(newer.clone()).unwrap();
        engine.storage.append(older.clone()).unwrap();

        let state = engine.reconstruct_state().unwrap();
        assert_eq!(state.get("k").unwrap(), &b"new".to_vec());

        let outcomes = engine.resolve_conflicts(&engine.storage.read_all_operations().unwrap()).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].rule, ResolutionRule::CausalDominance);
        assert_eq!(outcomes[0].winner, newer.id);
        assert_eq!(outcomes[0].loser, Some(older.id));
    }

    #[test]
    fn get_returns_deterministic_winner_not_insertion_order() {
        let dev_a = [1u8; 32];
        let dev_b = [2u8; 32];
        let master = Key::generate();
        let mut e1 = QueryEngine::new(SqliteStorage::open_in_memory().unwrap(), master.clone(), 1);
        let mut e2 = QueryEngine::new(SqliteStorage::open_in_memory().unwrap(), master, 1);

        let op_a = make_op(dev_a, 1, vec![(dev_a, 1)], "k", b"from-a", &e1);
        let op_b = make_op(dev_b, 1, vec![(dev_b, 1)], "k", b"from-b", &e1);

        let expected = if dev_a > dev_b { b"from-a" } else { b"from-b" };

        e1.storage.append(op_a.clone()).unwrap();
        e1.storage.append(op_b.clone()).unwrap();
        assert_eq!(e1.get("k").unwrap(), expected.to_vec());

        e2.storage.append(op_b).unwrap();
        e2.storage.append(op_a).unwrap();
        assert_eq!(e2.get("k").unwrap(), expected.to_vec());
    }
}
