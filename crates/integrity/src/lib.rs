//! VeilDB integrity layer.
//!
//! This crate provides BLAKE3 hashing, operation-hash calculation,
//! Merkle DAG construction (multi-parent, not a linear chain), proofs,
//! diffing, and tamper detection.
//!
//! It may use `storage` types (operation shape) but never touches
//! SQLite directly.

pub mod error;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use veildb_storage::{Operation, OperationId};

use error::IntegrityError;

/// Compute the canonical BLAKE3 hash of an operation.
///
/// The hash is over the canonical `postcard` serialization of
/// `(id, parents, logical_clock, device_id, ciphertext, signature)`.
pub fn operation_hash(op: &Operation) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&postcard::to_allocvec(&op.id).expect("serialize id"));
    hasher.update(&postcard::to_allocvec(&op.parents).expect("serialize parents"));
    hasher.update(&postcard::to_allocvec(&op.logical_clock).expect("serialize clock"));
    hasher.update(&op.device_id);
    hasher.update(&op.ciphertext);
    hasher.update(&op.signature);
    *hasher.finalize().as_bytes()
}

/// Compute the BLAKE3 hash of arbitrary data.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// A Merkle tree over a set of operation hashes.
///
/// The tree is built from the operation hashes as leaves. Internal
/// nodes are BLAKE3 hashes of the concatenation of their children.
/// The tree is balanced: leaves are padded with zero hashes to the
/// next power of two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleTree {
    /// The root hash of the tree.
    pub root: [u8; 32],
    /// All leaves (operation hashes), in sorted order.
    leaves: Vec<[u8; 32]>,
    /// Internal node hashes, indexed by (level, index).
    nodes: BTreeMap<(u32, usize), [u8; 32]>,
}

impl MerkleTree {
    /// Build a Merkle tree from a set of operation hashes.
    ///
    /// Leaves are sorted for determinism.
    pub fn build(operation_hashes: &[[u8; 32]]) -> Self {
        let mut leaves: Vec<[u8; 32]> = operation_hashes.to_vec();
        leaves.sort();

        // Pad to next power of two.
        let mut size = 1;
        while size < leaves.len() {
            size *= 2;
        }
        leaves.resize(size, [0u8; 32]);

        let mut nodes = BTreeMap::new();
        let mut level = 0u32;
        let mut current: Vec<[u8; 32]> = leaves.clone();

        // Store leaf level.
        for (i, leaf) in current.iter().enumerate() {
            nodes.insert((level, i), *leaf);
        }

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2);
            for chunk in current.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&[0u8; 32]);
                }
                let h = *hasher.finalize().as_bytes();
                next.push(h);
            }
            level += 1;
            for (i, h) in next.iter().enumerate() {
                nodes.insert((level, i), *h);
            }
            current = next;
        }

        let root = current[0];
        Self { root, leaves, nodes }
    }

    /// Build an empty Merkle tree.
    pub fn empty() -> Self {
        Self::build(&[])
    }

    /// Get the root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get all leaves.
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }

    /// Compute the difference between this tree and another.
    ///
    /// Returns the hashes present in `other` but not in `self`.
    /// This lets sync find missing operations without transferring
    /// the whole database.
    pub fn diff(&self, other: &MerkleTree) -> Vec<[u8; 32]> {
        let self_set: HashSet<[u8; 32]> = self.leaves.iter().copied().collect();
        other
            .leaves
            .iter()
            .copied()
            .filter(|h| !self_set.contains(h) && *h != [0u8; 32])
            .collect()
    }

    /// Generate a Merkle proof for a leaf.
    ///
    /// The proof is the list of sibling hashes needed to recompute
    /// the root from the leaf, along with the leaf's position.
    pub fn generate_proof(&self, leaf: &[u8; 32]) -> Result<MerkleProof, IntegrityError> {
        let pos = self
            .leaves
            .iter()
            .position(|l| l == leaf)
            .ok_or(IntegrityError::LeafNotFound)?;

        let mut siblings = Vec::new();
        let mut index = pos;
        let mut level = 0u32;
        let mut level_size = self.leaves.len();

        while level_size > 1 {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            let sibling = self
                .nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or([0u8; 32]);
            siblings.push(sibling);
            index /= 2;
            level += 1;
            level_size /= 2;
        }

        Ok(MerkleProof {
            leaf: *leaf,
            leaf_index: pos,
            siblings,
        })
    }

    /// Verify a Merkle proof against a root.
    pub fn verify_proof(root: &[u8; 32], proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;
        let mut index = proof.leaf_index;

        for sibling in &proof.siblings {
            let mut hasher = blake3::Hasher::new();
            // If index is even, current is on the left, sibling on right.
            if index % 2 == 0 {
                hasher.update(&current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current);
            }
            current = *hasher.finalize().as_bytes();
            index /= 2;
        }
        current == *root
    }
}

/// A Merkle proof for a single leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf hash being proven.
    pub leaf: [u8; 32],
    /// Index of the leaf in the sorted leaves array.
    pub leaf_index: usize,
    /// Sibling hashes from leaf to root.
    pub siblings: Vec<[u8; 32]>,
}

/// The result of an integrity verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// All operations verified.
    Verified,
    /// At least one operation failed verification.
    Tampered,
    /// Verification could not be completed.
    Unverified,
}

/// A report of integrity verification results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Overall status.
    pub status: IntegrityStatus,
    /// Number of operations verified.
    pub operations_checked: u64,
    /// Number of operations that failed.
    pub operations_failed: u64,
    /// Hashes of operations that failed verification.
    pub failed_hashes: Vec<[u8; 32]>,
    /// The computed Merkle root.
    pub merkle_root: [u8; 32],
}

/// Verify the integrity of a set of operations.
///
/// Recomputes each operation's hash and checks that all parent
/// references exist within the set. Returns a report.
///
/// NOTE: this checks structural integrity only. For tamper detection
/// that actually catches modified *content* (a re-hash of tampered
/// bytes still matches itself), use [`verify_operations_signed`].
pub fn verify_operations(operations: &[Operation]) -> IntegrityReport {
    verify_operations_inner(operations, None)
}

/// Verify integrity **including Ed25519 signatures**.
///
/// Like [`verify_operations`], but additionally re-checks every
/// operation's signature against the signer's stored public key using
/// the same recompute-hash-with-empty-signature scheme as sync step 9.
/// A tampered operation (even a tip with no children) no longer
/// re-hashes to a value its signature covers, so local
/// `verify_integrity` detects it — as the README claims.
///
/// `public_keys` maps `device_id → Ed25519 public key`; operations
/// from unknown devices count as failed (their signature cannot be
/// checked, and zero-trust means "unverifiable ≠ verified").
pub fn verify_operations_signed(
    operations: &[Operation],
    public_keys: &HashMap<[u8; 32], [u8; 32]>,
) -> IntegrityReport {
    verify_operations_inner(operations, Some(public_keys))
}

fn verify_operations_inner(
    operations: &[Operation],
    public_keys: Option<&HashMap<[u8; 32], [u8; 32]>>,
) -> IntegrityReport {
    let mut failed = 0u64;
    let mut failed_hashes = Vec::new();

    // Build a set of all operation hashes for parent checking.
    let hash_map: HashMap<OperationId, [u8; 32]> = operations
        .iter()
        .map(|op| (op.id, operation_hash(op)))
        .collect();

    let all_hashes: HashSet<[u8; 32]> = hash_map.values().copied().collect();

    for op in operations {
        let h = operation_hash(op);
        let mut bad = false;

        // Check parents exist.
        for parent in &op.parents {
            if !all_hashes.contains(parent) {
                bad = true;
                break;
            }
        }

        // Check the Ed25519 signature (when keys are available).
        if !bad {
            if let Some(keys) = public_keys {
                match keys.get(&op.device_id) {
                    None => bad = true,
                    Some(public_key) => {
                        // The signature covers the hash computed with an
                        // EMPTY signature field (see core's put path and
                        // sync step 9).
                        let mut unsigned = op.clone();
                        unsigned.signature = Vec::new();
                        let unsigned_hash = operation_hash(&unsigned);
                        if veildb_crypto::verify_signature(
                            public_key,
                            &unsigned_hash,
                            &op.signature,
                        )
                        .is_err()
                        {
                            bad = true;
                        }
                    }
                }
            }
        }

        if bad {
            failed += 1;
            failed_hashes.push(h);
        }
    }

    let merkle_root = MerkleTree::build(&hash_map.values().copied().collect::<Vec<_>>()).root();

    let status = if failed == 0 {
        IntegrityStatus::Verified
    } else {
        IntegrityStatus::Tampered
    };

    IntegrityReport {
        status,
        operations_checked: operations.len() as u64,
        operations_failed: failed,
        failed_hashes,
        merkle_root,
    }
}

/// Validate the operation graph structure.
///
/// Checks that:
/// - The graph has no cycles.
/// - Every parent reference resolves to an existing operation.
/// - Each device's sequence numbers are contiguous starting from 1.
///
/// Cycle detection is **iterative** (explicit stack, gray/black
/// coloring): chain depth equals the number of writes, so a recursive
/// DFS would overflow the stack on logs of a few thousand operations
/// (sync step 10 and `verify` would crash).
pub fn validate_graph(operations: &[Operation]) -> Result<(), IntegrityError> {
    // Build hash → operation map.
    let hash_to_op: HashMap<[u8; 32], &Operation> = operations
        .iter()
        .map(|op| (operation_hash(op), op))
        .collect();

    // Iterative DFS with explicit stack. Frames are (hash,
    // next_parent_index) — exactly the state a recursive call would
    // keep, but on the heap.
    let mut visited: HashSet<[u8; 32]> = HashSet::new(); // black
    let mut in_stack: HashSet<[u8; 32]> = HashSet::new(); // gray

    for op in operations {
        let start = operation_hash(op);
        if visited.contains(&start) {
            continue;
        }

        in_stack.insert(start);
        let mut stack: Vec<([u8; 32], usize)> = vec![(start, 0)];

        while let Some((hash, next_parent)) = stack.pop() {
            let parents: Vec<[u8; 32]> = match hash_to_op.get(&hash) {
                Some(o) => o.parents.clone(),
                None => {
                    // Only reachable for the start node if it vanished;
                    // parents are validated before being pushed.
                    visited.insert(hash);
                    in_stack.remove(&hash);
                    continue;
                }
            };

            if next_parent < parents.len() {
                let parent = parents[next_parent];
                // Resume this frame after the child returns.
                stack.push((hash, next_parent + 1));

                if !hash_to_op.contains_key(&parent) {
                    return Err(IntegrityError::MissingParent(parent));
                }
                if in_stack.contains(&parent) {
                    return Err(IntegrityError::GraphCycle);
                }
                if !visited.contains(&parent) {
                    in_stack.insert(parent);
                    stack.push((parent, 0));
                }
            } else {
                // All parents expanded: mark black.
                in_stack.remove(&hash);
                visited.insert(hash);
            }
        }
    }

    // Check per-device sequence contiguity.
    let mut device_seqs: HashMap<[u8; 32], BTreeSet<u64>> = HashMap::new();
    for op in operations {
        device_seqs
            .entry(op.id.device_id)
            .or_default()
            .insert(op.id.sequence);
    }

    for (device, seqs) in &device_seqs {
        let expected: BTreeSet<u64> = (1..=seqs.len() as u64).collect();
        if *seqs != expected {
            return Err(IntegrityError::OperationHashMismatch(OperationId::new(
                *device,
                seqs.len() as u64,
            )));
        }
    }

    Ok(())
}

/// Compute the set of operations reachable from a set of tip hashes.
///
/// This is used to determine which operations are ancestors of the
/// current state (for snapshotting and compaction).
pub fn reachable_operations(
    tips: &[[u8; 32]],
    hash_to_op: &HashMap<[u8; 32], Operation>,
) -> BTreeSet<[u8; 32]> {
    let mut reachable = BTreeSet::new();
    let mut stack: Vec<[u8; 32]> = tips.to_vec();

    while let Some(h) = stack.pop() {
        if reachable.contains(&h) {
            continue;
        }
        reachable.insert(h);
        if let Some(op) = hash_to_op.get(&h) {
            for parent in &op.parents {
                if !reachable.contains(parent) {
                    stack.push(*parent);
                }
            }
        }
    }

    reachable
}

#[cfg(test)]
mod tests {
    use super::*;
    use veildb_storage::LogicalClock;

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
    fn operation_hash_deterministic() {
        let op = test_op([1u8; 32], 1, vec![]);
        let h1 = operation_hash(&op);
        let h2 = operation_hash(&op);
        assert_eq!(h1, h2);
    }

    #[test]
    fn operation_hash_changes_with_content() {
        let op1 = test_op([1u8; 32], 1, vec![]);
        let mut op2 = op1.clone();
        op2.ciphertext = vec![9];
        assert_ne!(operation_hash(&op1), operation_hash(&op2));
    }

    #[test]
    fn merkle_build_and_root() {
        let tree = MerkleTree::build(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
        assert_eq!(tree.root().len(), 32);
        assert_eq!(tree.leaves().len(), 4); // padded to power of 2
    }

    #[test]
    fn merkle_deterministic() {
        let hashes = [[3u8; 32], [1u8; 32], [2u8; 32]];
        let t1 = MerkleTree::build(&hashes);
        let t2 = MerkleTree::build(&hashes);
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn merkle_diff() {
        let t1 = MerkleTree::build(&[[1u8; 32], [2u8; 32]]);
        let t2 = MerkleTree::build(&[[1u8; 32], [2u8; 32], [3u8; 32]]);
        let diff = t1.diff(&t2);
        assert_eq!(diff, vec![[3u8; 32]]);
    }

    #[test]
    fn merkle_proof_roundtrip() {
        let hashes = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let tree = MerkleTree::build(&hashes);
        let proof = tree.generate_proof(&[2u8; 32]).unwrap();
        assert!(MerkleTree::verify_proof(&tree.root(), &proof));
    }

    #[test]
    fn merkle_proof_wrong_root_fails() {
        let hashes = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let tree = MerkleTree::build(&hashes);
        let proof = tree.generate_proof(&[2u8; 32]).unwrap();
        let wrong_root = [0xFFu8; 32];
        assert!(!MerkleTree::verify_proof(&wrong_root, &proof));
    }

    #[test]
    fn verify_operations_ok() {
        let op1 = test_op([1u8; 32], 1, vec![]);
        let h1 = operation_hash(&op1);
        let op2 = test_op([1u8; 32], 2, vec![h1]);
        let report = verify_operations(&[op1, op2]);
        assert_eq!(report.status, IntegrityStatus::Verified);
        assert_eq!(report.operations_failed, 0);
    }

    #[test]
    fn verify_operations_missing_parent() {
        let op1 = test_op([1u8; 32], 1, vec![]);
        let op2 = test_op([1u8; 32], 2, vec![[0xAB; 32]]); // missing parent
        let report = verify_operations(&[op1, op2]);
        assert_eq!(report.status, IntegrityStatus::Tampered);
        assert_eq!(report.operations_failed, 1);
    }

    #[test]
    fn validate_graph_ok() {
        let op1 = test_op([1u8; 32], 1, vec![]);
        let h1 = operation_hash(&op1);
        let op2 = test_op([1u8; 32], 2, vec![h1]);
        validate_graph(&[op1, op2]).unwrap();
    }

    #[test]
    fn validate_graph_cycle() {
        // Create a cycle: op1 → op2 → op1
        let op1 = test_op([1u8; 32], 1, vec![]);
        let h1 = operation_hash(&op1);
        let op2 = test_op([1u8; 32], 2, vec![h1]);
        let h2 = operation_hash(&op2);
        let mut op1_cycle = op1.clone();
        op1_cycle.parents = vec![h2];
        let result = validate_graph(&[op1_cycle, op2]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_graph_missing_parent() {
        let op1 = test_op([1u8; 32], 1, vec![]);
        let op2 = test_op([1u8; 32], 2, vec![[0xAB; 32]]);
        let result = validate_graph(&[op1, op2]);
        assert!(matches!(result, Err(IntegrityError::MissingParent(_))));
    }

    #[test]
    fn reachable_operations_works() {
        let op1 = test_op([1u8; 32], 1, vec![]);
        let h1 = operation_hash(&op1);
        let op2 = test_op([1u8; 32], 2, vec![h1]);
        let h2 = operation_hash(&op2);
        let op3 = test_op([2u8; 32], 1, vec![]);
        let h3 = operation_hash(&op3);

        let map: HashMap<[u8; 32], Operation> = vec![
            (h1, op1),
            (h2, op2),
            (h3, op3),
        ]
        .into_iter()
        .collect();

        let reachable = reachable_operations(&[h2], &map);
        assert!(reachable.contains(&h1));
        assert!(reachable.contains(&h2));
        assert!(!reachable.contains(&h3));
    }
}