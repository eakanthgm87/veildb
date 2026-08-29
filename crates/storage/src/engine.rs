//! SQLite-backed storage engine.
//!
//! This is the physical persistence layer for VeilDB. It manages the
//! SQLite database lifecycle, migrations, and all CRUD operations for
//! operations, snapshots, devices, and metadata.
//!
//! The storage layer never decrypts data, generates keys, verifies
//! signatures, CRDT-merges, or touches the network.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::StorageError;
use crate::types::{
    DeviceEntry, LogicalClock, MergeLogEntry, Operation, OperationId, Snapshot, SnapshotId,
};

/// The current schema version.
pub const SCHEMA_VERSION: i32 = 2;

/// The storage engine trait.
///
/// This is the only interface other crates use to interact with
/// persistence. The SQLite implementation is an internal detail.
pub trait StorageEngine {
    /// Append a new operation to the log.
    ///
    /// Returns the BLAKE3 hash of the operation on success.
    fn append(&mut self, operation: Operation) -> Result<[u8; 32], StorageError>;

    /// Read operations by their IDs.
    fn read_operations(&self, ids: &[OperationId]) -> Result<Vec<Operation>, StorageError>;

    /// Read all operations in the log.
    fn read_all_operations(&self) -> Result<Vec<Operation>, StorageError>;

    /// Get the hash of the most recently appended operation.
    fn latest_operation_hash(&self) -> Result<Option<[u8; 32]>, StorageError>;

    /// Create a new snapshot.
    fn create_snapshot(&mut self, snapshot: Snapshot) -> Result<SnapshotId, StorageError>;

    /// Load a snapshot by ID.
    fn load_snapshot(&self, id: SnapshotId) -> Result<Snapshot, StorageError>;

    /// Compact the operation log up to and including the given snapshot.
    fn compact(&mut self, snapshot: SnapshotId) -> Result<(), StorageError>;

    /// Get the latest snapshot ID, if any.
    fn latest_snapshot_id(&self) -> Result<Option<SnapshotId>, StorageError>;

    /// Get the latest snapshot, if any.
    fn latest_snapshot(&self) -> Result<Option<Snapshot>, StorageError>;

    /// Store a device entry.
    fn store_device(&mut self, device: DeviceEntry) -> Result<(), StorageError>;

    /// Load a device entry by ID.
    fn load_device(&self, device_id: &[u8; 32]) -> Result<Option<DeviceEntry>, StorageError>;

    /// List all device entries.
    fn list_devices(&self) -> Result<Vec<DeviceEntry>, StorageError>;

    /// Update a device's trusted status.
    fn set_device_trusted(
        &mut self,
        device_id: &[u8; 32],
        trusted: bool,
    ) -> Result<(), StorageError>;

    /// Store a metadata key-value pair.
    fn set_metadata(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Load a metadata value by key.
    fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Delete a metadata entry.
    fn delete_metadata(&mut self, key: &str) -> Result<(), StorageError>;

    /// Get the total number of operations in the log.
    fn operation_count(&self) -> Result<u64, StorageError>;

    /// Get the current logical clock (merged across all operations).
    fn current_clock(&self) -> Result<LogicalClock, StorageError>;

    /// Check if the database is empty (no operations).
    fn is_empty(&self) -> Result<bool, StorageError>;

    /// Dev-only: corrupt an operation's ciphertext in the local store.
    ///
    /// This is ONLY available in debug builds. It flips bytes in the
    /// operation's ciphertext to simulate tampering.
    #[cfg(debug_assertions)]
    fn corrupt_operation(
        &mut self,
        device_id: &[u8; 32],
        sequence: u64,
    ) -> Result<(), StorageError>;

    /// Record a deterministic conflict resolution in the merge log.
    ///
    /// Idempotent: recording the same (key, winner, loser) triple
    /// twice is a no-op.
    fn record_merge_entry(
        &mut self,
        key: &str,
        winner: OperationId,
        loser: Option<OperationId>,
        rule: &str,
    ) -> Result<(), StorageError>;

    /// List all merge-log entries, oldest first.
    fn list_merge_entries(&self) -> Result<Vec<MergeLogEntry>, StorageError>;

    /// Check whether a merge-log entry already exists for the given
    /// (key, winner, loser) triple.
    fn merge_entry_exists(
        &self,
        key: &str,
        winner: &OperationId,
        loser: Option<&OperationId>,
    ) -> Result<bool, StorageError>;
}

/// SQLite-backed implementation of [`StorageEngine`].
pub struct SqliteStorage {
    conn: Connection,
}

impl SqliteStorage {
    /// Open (or create) a database at the given path.
    ///
    /// The parent directory must exist. WAL mode is enabled and
    /// `synchronous=NORMAL` is set for crash safety with good
    /// performance.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        Self::init_connection(conn)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::init_connection(conn)
    }

    fn init_connection(conn: Connection) -> Result<Self, StorageError> {
        // WAL mode for crash safety and concurrent readers.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // NORMAL synchronous: fsync on checkpoint, not every commit.
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let mut storage = Self { conn };
        storage.migrate()?;
        Ok(storage)
    }

    fn migrate(&mut self) -> Result<(), StorageError> {
        // Check if schema_version table exists.
        let table_exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type='table' AND name='schema_version'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )?;

        let current: i32 = if table_exists {
            self.conn
                .query_row(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                    [],
                    |row| row.get::<_, i32>(0),
                )
                .optional()?
                .unwrap_or(0)
        } else {
            0
        };

        if current > SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchemaVersion(current));
        }

        if current < 1 {
            self.migrate_to_v1()?;
        }

        if current < 2 {
            self.migrate_to_v2()?;
        }

        Ok(())
    }

    fn migrate_to_v1(&mut self) -> Result<(), StorageError> {
        let tx = self.conn.transaction()?;

        tx.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL
            );
            INSERT INTO schema_version (version) VALUES (1);

            CREATE TABLE IF NOT EXISTS operations (
                operation_id       BLOB PRIMARY KEY,
                device_id          BLOB NOT NULL,
                sequence_number    INTEGER NOT NULL,
                logical_clock      BLOB NOT NULL,
                parents            BLOB NOT NULL,
                operation_hash     BLOB NOT NULL,
                ciphertext         BLOB NOT NULL,
                signature          BLOB NOT NULL,
                UNIQUE(device_id, sequence_number)
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                logical_clock    BLOB NOT NULL,
                last_operation    BLOB NOT NULL,
                state              BLOB NOT NULL,
                merkle_root         BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                device_id           BLOB PRIMARY KEY,
                public_key           BLOB NOT NULL,
                trusted               INTEGER NOT NULL,
                approved_by            BLOB,
                approval_signature      BLOB,
                created_at              INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS metadata (
                key    TEXT PRIMARY KEY,
                value  BLOB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_operations_device_seq
                ON operations(device_id, sequence_number);
            "#,
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Migrate from schema v1 to v2: add the merge log table.
    fn migrate_to_v2(&mut self) -> Result<(), StorageError> {
        let tx = self.conn.transaction()?;

        tx.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS merge_log (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                key            TEXT NOT NULL,
                winner_device  BLOB NOT NULL,
                winner_seq     INTEGER NOT NULL,
                loser_device   BLOB,
                loser_seq      INTEGER,
                rule           TEXT NOT NULL,
                created_at     INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_merge_log_key
                ON merge_log(key);
            "#,
        )?;

        tx.execute(
            "INSERT INTO schema_version (version) VALUES (2)",
            [],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Compute the BLAKE3 hash of an operation.
    ///
    /// The hash is over the canonical `postcard` serialization of
    /// (id, parents, logical_clock, device_id, ciphertext, signature).
    /// This matches the `integrity` crate's definition.
    fn operation_hash(op: &Operation) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&postcard::to_allocvec(&op.id).expect("serialize id"));
        hasher.update(&postcard::to_allocvec(&op.parents).expect("serialize parents"));
        hasher.update(&postcard::to_allocvec(&op.logical_clock).expect("serialize clock"));
        hasher.update(&op.device_id);
        hasher.update(&op.ciphertext);
        hasher.update(&op.signature);
        *hasher.finalize().as_bytes()
    }

    /// Read a single operation's columns by raw ID bytes.
    fn read_operation_row(&self, id_bytes: &[u8]) -> Result<Option<Operation>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT logical_clock, parents, ciphertext, signature,
                        device_id, sequence_number
                 FROM operations WHERE operation_id = ?1",
                params![id_bytes],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;

        Ok(row.map(|r| {
            let mut device = [0u8; 32];
            device.copy_from_slice(&r.4);
            let id = OperationId::new(device, r.5 as u64);
            Operation {
                id,
                parents: postcard::from_bytes(&r.1).unwrap_or_default(),
                logical_clock: postcard::from_bytes(&r.0).unwrap_or_default(),
                device_id: device,
                ciphertext: r.2,
                signature: r.3,
            }
        }))
    }
}

impl StorageEngine for SqliteStorage {
    fn append(&mut self, operation: Operation) -> Result<[u8; 32], StorageError> {
        let hash = Self::operation_hash(&operation);

        let tx = self.conn.transaction()?;

        // Check for duplicate.
        let id_bytes = postcard::to_allocvec(&operation.id)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id = ?1)",
            params![id_bytes],
            |row| row.get::<_, bool>(0),
        )?;

        if exists {
            return Err(StorageError::DuplicateOperation(operation.id));
        }

        let clock_bytes = postcard::to_allocvec(&operation.logical_clock)?;
        let parents_bytes = postcard::to_allocvec(&operation.parents)?;

        tx.execute(
            "INSERT INTO operations
                (operation_id, device_id, sequence_number, logical_clock,
                 parents, operation_hash, ciphertext, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id_bytes,
                operation.id.device_id.to_vec(),
                operation.id.sequence as i64,
                clock_bytes,
                parents_bytes,
                hash.to_vec(),
                operation.ciphertext,
                operation.signature,
            ],
        )?;

        tx.commit()?;
        Ok(hash)
    }

    fn read_operations(&self, ids: &[OperationId]) -> Result<Vec<Operation>, StorageError> {
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            let id_bytes = postcard::to_allocvec(id)?;
            if let Some(op) = self.read_operation_row(&id_bytes)? {
                result.push(op);
            }
        }
        Ok(result)
    }

    fn read_all_operations(&self) -> Result<Vec<Operation>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT logical_clock, parents, ciphertext, signature,
                    device_id, sequence_number
             FROM operations ORDER BY device_id, sequence_number",
        )?;

        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let r = row?;
            let mut device = [0u8; 32];
            device.copy_from_slice(&r.4);
            let id = OperationId::new(device, r.5 as u64);
            result.push(Operation {
                id,
                parents: postcard::from_bytes(&r.1).unwrap_or_default(),
                logical_clock: postcard::from_bytes(&r.0).unwrap_or_default(),
                device_id: device,
                ciphertext: r.2,
                signature: r.3,
            });
        }
        Ok(result)
    }

    fn latest_operation_hash(&self) -> Result<Option<[u8; 32]>, StorageError> {
        let hash: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT operation_hash FROM operations
                 ORDER BY device_id DESC, sequence_number DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        Ok(hash.map(|h| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h);
            arr
        }))
    }

    fn create_snapshot(&mut self, snapshot: Snapshot) -> Result<SnapshotId, StorageError> {
        let clock_bytes = postcard::to_allocvec(&snapshot.logical_clock)?;

        self.conn.execute(
            "INSERT INTO snapshots
                (logical_clock, last_operation, state, merkle_root)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                clock_bytes,
                snapshot.last_operation.to_vec(),
                snapshot.state,
                snapshot.merkle_root.to_vec(),
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    fn load_snapshot(&self, id: SnapshotId) -> Result<Snapshot, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT logical_clock, last_operation, state, merkle_root
                 FROM snapshots WHERE snapshot_id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StorageError::SnapshotNotFound(id))?;

        let logical_clock: LogicalClock = postcard::from_bytes(&row.0)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let mut last_operation = [0u8; 32];
        last_operation.copy_from_slice(&row.1);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&row.3);

        Ok(Snapshot {
            logical_clock,
            last_operation,
            state: row.2,
            merkle_root,
        })
    }

    fn compact(&mut self, snapshot: SnapshotId) -> Result<(), StorageError> {
        let _snapshot = self.load_snapshot(snapshot)?;

        let tx = self.conn.transaction()?;
        // Delete all operations. The snapshot preserves state for
        // time-travel queries; operations after the snapshot are gone
        // which is acceptable post-compaction.
        tx.execute("DELETE FROM operations", [])?;
        tx.commit()?;
        Ok(())
    }

    fn latest_snapshot_id(&self) -> Result<Option<SnapshotId>, StorageError> {
        let mut stmt = self.conn.prepare("SELECT MAX(snapshot_id) FROM snapshots")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let id: Option<i64> = row.get(0)?;
            Ok(id)
        } else {
            Ok(None)
        }
    }

    fn latest_snapshot(&self) -> Result<Option<Snapshot>, StorageError> {
        match self.latest_snapshot_id()? {
            Some(id) => Ok(Some(self.load_snapshot(id)?)),
            None => Ok(None),
        }
    }

    fn store_device(&mut self, device: DeviceEntry) -> Result<(), StorageError> {
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = ?1)",
            params![device.device_id.to_vec()],
            |row| row.get::<_, bool>(0),
        )?;

        if exists {
            return Err(StorageError::DuplicateDevice(device.device_id));
        }

        self.conn.execute(
            "INSERT INTO devices
                (device_id, public_key, trusted, approved_by, approval_signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                device.device_id.to_vec(),
                device.public_key,
                device.trusted as i64,
                device.approved_by.map(|a| a.to_vec()),
                device.approval_signature,
                device.created_at,
            ],
        )?;
        Ok(())
    }

    fn load_device(&self, device_id: &[u8; 32]) -> Result<Option<DeviceEntry>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT device_id, public_key, trusted, approved_by, approval_signature, created_at
                 FROM devices WHERE device_id = ?1",
                params![device_id.to_vec()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()?;

        Ok(row.map(|r| {
            let mut id = [0u8; 32];
            id.copy_from_slice(&r.0);
            DeviceEntry {
                device_id: id,
                public_key: r.1,
                trusted: r.2 != 0,
                approved_by: r.3.map(|a| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&a);
                    arr
                }),
                approval_signature: r.4,
                created_at: r.5,
            }
        }))
    }

    fn list_devices(&self) -> Result<Vec<DeviceEntry>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, public_key, trusted, approved_by, approval_signature, created_at
             FROM devices ORDER BY created_at",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;

        let mut result = Vec::new();
        for row in rows {
            let r = row?;
            let mut id = [0u8; 32];
            id.copy_from_slice(&r.0);
            result.push(DeviceEntry {
                device_id: id,
                public_key: r.1,
                trusted: r.2 != 0,
                approved_by: r.3.map(|a| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&a);
                    arr
                }),
                approval_signature: r.4,
                created_at: r.5,
            });
        }
        Ok(result)
    }

    fn set_device_trusted(
        &mut self,
        device_id: &[u8; 32],
        trusted: bool,
    ) -> Result<(), StorageError> {
        let affected = self.conn.execute(
            "UPDATE devices SET trusted = ?1 WHERE device_id = ?2",
            params![trusted as i64, device_id.to_vec()],
        )?;
        if affected == 0 {
            return Err(StorageError::DeviceNotFound(*device_id));
        }
        Ok(())
    }

    fn record_merge_entry(
        &mut self,
        key: &str,
        winner: OperationId,
        loser: Option<OperationId>,
        rule: &str,
    ) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO merge_log
                (key, winner_device, winner_seq, loser_device, loser_seq, rule, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                key,
                winner.device_id.to_vec(),
                winner.sequence as i64,
                loser.map(|l| l.device_id.to_vec()),
                loser.map(|l| l.sequence as i64),
                rule,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            ],
        )?;
        Ok(())
    }

    fn list_merge_entries(&self) -> Result<Vec<MergeLogEntry>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, key, winner_device, winner_seq, loser_device, loser_seq, rule, created_at
             FROM merge_log ORDER BY id",
        )?;

        let rows = stmt.query_map([], |row| {
            let winner_device: Vec<u8> = row.get(2)?;
            let loser_device: Option<Vec<u8>> = row.get(4)?;
            let loser_seq: Option<i64> = row.get(5)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                winner_device,
                row.get::<_, i64>(3)?,
                loser_device,
                loser_seq,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })?;

        let mut result = Vec::new();
        for r in rows {
            let r = r?;
            let mut winner_dev = [0u8; 32];
            winner_dev.copy_from_slice(&r.2[..32.min(r.2.len())]);
            let loser = r.4.and_then(|d| {
                if d.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&d);
                    r.5.map(|s| OperationId::new(arr, s as u64))
                } else {
                    None
                }
            });
            result.push(MergeLogEntry {
                id: r.0,
                key: r.1,
                winner: OperationId::new(winner_dev, r.3 as u64),
                loser,
                rule: r.6,
                created_at: r.7,
            });
        }
        Ok(result)
    }

    fn merge_entry_exists(
        &self,
        key: &str,
        winner: &OperationId,
        loser: Option<&OperationId>,
    ) -> Result<bool, StorageError> {
        let (loser_dev, loser_seq): (Option<Vec<u8>>, Option<i64>) = match loser {
            Some(l) => (Some(l.device_id.to_vec()), Some(l.sequence as i64)),
            None => (None, None),
        };
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM merge_log
                 WHERE key = ?1 AND winner_device = ?2 AND winner_seq = ?3
                   AND loser_device IS ?4 AND loser_seq IS ?5
                 LIMIT 1",
                params![
                    key,
                    winner.device_id.to_vec(),
                    winner.sequence as i64,
                    loser_dev,
                    loser_seq
                ],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    fn set_metadata(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.conn.execute(
            "INSERT INTO metadata (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let value: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    fn delete_metadata(&mut self, key: &str) -> Result<(), StorageError> {
        self.conn
            .execute("DELETE FROM metadata WHERE key = ?1", params![key])?;
        Ok(())
    }

    fn operation_count(&self) -> Result<u64, StorageError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    fn current_clock(&self) -> Result<LogicalClock, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, MAX(sequence_number) FROM operations GROUP BY device_id",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;

        let mut clock = LogicalClock::new();
        for row in rows {
            let (device_id, seq) = row?;
            let mut id = [0u8; 32];
            id.copy_from_slice(&device_id);
            clock.entries.push((id, seq as u64));
        }
        clock.entries.sort();
        Ok(clock)
    }

    fn is_empty(&self) -> Result<bool, StorageError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM operations", [], |row| row.get(0))?;
        Ok(count == 0)
    }

    #[cfg(debug_assertions)]
    fn corrupt_operation(
        &mut self,
        device_id: &[u8; 32],
        sequence: u64,
    ) -> Result<(), StorageError> {
        // Read the current ciphertext.
        let id = OperationId::new(*device_id, sequence);
        let id_bytes = postcard::to_allocvec(&id)?;
        let row = self
            .conn
            .query_row(
                "SELECT ciphertext FROM operations WHERE operation_id = ?1",
                params![id_bytes],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;

        let ciphertext = row.ok_or(StorageError::OperationNotFound(id))?;

        // Flip a byte in the ciphertext.
        let mut corrupted = ciphertext;
        if !corrupted.is_empty() {
            let idx = corrupted.len() / 2;
            corrupted[idx] ^= 0xFF;
        }

        // Update the ciphertext and recompute the operation hash.
        let affected = self.conn.execute(
            "UPDATE operations SET ciphertext = ?1 WHERE operation_id = ?2",
            params![corrupted, id_bytes],
        )?;
        if affected == 0 {
            return Err(StorageError::OperationNotFound(id));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_operation(device_id: [u8; 32], seq: u64) -> Operation {
        Operation {
            id: OperationId::new(device_id, seq),
            parents: vec![],
            logical_clock: LogicalClock::new(),
            device_id,
            ciphertext: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        }
    }

    #[test]
    fn append_and_read() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let op = test_operation([1u8; 32], 1);
        let hash = storage.append(op.clone()).unwrap();
        assert_eq!(hash.len(), 32);

        let ops = storage.read_operations(&[op.id]).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].id, op.id);
        assert_eq!(ops[0].ciphertext, op.ciphertext);
    }

    #[test]
    fn duplicate_detection() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let op = test_operation([1u8; 32], 1);
        storage.append(op.clone()).unwrap();
        let err = storage.append(op).unwrap_err();
        assert!(matches!(err, StorageError::DuplicateOperation(_)));
    }

    #[test]
    fn read_all() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        storage.append(test_operation([1u8; 32], 1)).unwrap();
        storage.append(test_operation([1u8; 32], 2)).unwrap();
        storage.append(test_operation([2u8; 32], 1)).unwrap();

        let ops = storage.read_all_operations().unwrap();
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn snapshot_roundtrip() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let snapshot = Snapshot {
            logical_clock: LogicalClock::new(),
            last_operation: [9u8; 32],
            state: vec![1, 2, 3, 4],
            merkle_root: [8u8; 32],
        };
        let id = storage.create_snapshot(snapshot.clone()).unwrap();
        let loaded = storage.load_snapshot(id).unwrap();
        assert_eq!(loaded.state, snapshot.state);
        assert_eq!(loaded.merkle_root, snapshot.merkle_root);
    }

    #[test]
    fn device_crud() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        let device = DeviceEntry {
            device_id: [1u8; 32],
            public_key: vec![1, 2, 3],
            trusted: true,
            approved_by: None,
            approval_signature: None,
            created_at: 123,
        };
        storage.store_device(device.clone()).unwrap();
        let loaded = storage.load_device(&[1u8; 32]).unwrap().unwrap();
        assert_eq!(loaded.device_id, device.device_id);
        assert!(loaded.trusted);

        storage.set_device_trusted(&[1u8; 32], false).unwrap();
        let loaded = storage.load_device(&[1u8; 32]).unwrap().unwrap();
        assert!(!loaded.trusted);

        let devices = storage.list_devices().unwrap();
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn metadata_roundtrip() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        storage.set_metadata("key1", b"value1").unwrap();
        storage.set_metadata("key1", b"value2").unwrap();
        let value = storage.get_metadata("key1").unwrap().unwrap();
        assert_eq!(value, b"value2");
    }

    #[test]
    fn operation_count_and_clock() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        assert!(storage.is_empty().unwrap());

        let mut op1 = test_operation([1u8; 32], 1);
        op1.logical_clock.advance([1u8; 32]);
        storage.append(op1).unwrap();

        let mut op2 = test_operation([1u8; 32], 2);
        op2.logical_clock.advance([1u8; 32]);
        storage.append(op2).unwrap();

        let mut op3 = test_operation([2u8; 32], 1);
        op3.logical_clock.advance([2u8; 32]);
        storage.append(op3).unwrap();

        assert_eq!(storage.operation_count().unwrap(), 3);
        assert!(!storage.is_empty().unwrap());

        let clock = storage.current_clock().unwrap();
        assert_eq!(clock.entries.len(), 2);
    }

    #[test]
    fn latest_operation_hash() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        assert!(storage.latest_operation_hash().unwrap().is_none());

        let op = test_operation([1u8; 32], 1);
        let hash = storage.append(op).unwrap();
        assert_eq!(storage.latest_operation_hash().unwrap(), Some(hash));
    }

    #[test]
    fn compact_removes_operations() {
        let mut storage = SqliteStorage::open_in_memory().unwrap();
        storage.append(test_operation([1u8; 32], 1)).unwrap();
        storage.append(test_operation([1u8; 32], 2)).unwrap();

        let snapshot = Snapshot {
            logical_clock: LogicalClock::new(),
            last_operation: [0u8; 32],
            state: vec![],
            merkle_root: [0u8; 32],
        };
        let id = storage.create_snapshot(snapshot).unwrap();
        storage.compact(id).unwrap();

        assert!(storage.is_empty().unwrap());
    }
}