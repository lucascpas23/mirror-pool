#![forbid(unsafe_code)]
//! SQLite WAL persistence with transactional, restart-safe cohort operations.

use std::path::Path;

use mirror_pool_core::{Digest32, Round};
use mirror_pool_crypto::JoinTicket;
use mirror_pool_merkle::{CohortProof, MerkleCohort};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

const MIGRATION_1: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pools(pool_id BLOB PRIMARY KEY CHECK(length(pool_id)=32), config_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rounds(pool_id BLOB NOT NULL, round_id INTEGER NOT NULL, round_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(pool_id, round_id), FOREIGN KEY(pool_id) REFERENCES pools(pool_id));
CREATE INDEX IF NOT EXISTS rounds_active_idx ON rounds(state, updated_at);
CREATE TABLE IF NOT EXISTS join_tickets(pool_id BLOB NOT NULL, round_id INTEGER NOT NULL, commitment BLOB NOT NULL UNIQUE CHECK(length(commitment)=32), coordination_key BLOB NOT NULL, ticket_json TEXT NOT NULL, accepted_at TEXT NOT NULL, UNIQUE(pool_id, round_id, coordination_key));
CREATE INDEX IF NOT EXISTS tickets_round_idx ON join_tickets(pool_id, round_id, commitment);
CREATE TABLE IF NOT EXISTS cohort_roots(pool_id BLOB NOT NULL, round_id INTEGER NOT NULL, root BLOB NOT NULL CHECK(length(root)=32), cohort_size INTEGER NOT NULL, published_at TEXT NOT NULL, PRIMARY KEY(pool_id, round_id));
CREATE TABLE IF NOT EXISTS cohort_proofs(pool_id BLOB NOT NULL, round_id INTEGER NOT NULL, commitment BLOB NOT NULL, proof_json TEXT NOT NULL, PRIMARY KEY(pool_id, round_id, commitment));
CREATE TABLE IF NOT EXISTS release_schedules(pool_id BLOB NOT NULL, round_id INTEGER NOT NULL, release_slot INTEGER NOT NULL, window_end_slot INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(pool_id, round_id));
CREATE TABLE IF NOT EXISTS receipts(pool_id BLOB NOT NULL, round_id INTEGER NOT NULL, receipt_hash BLOB NOT NULL UNIQUE, receipt_json TEXT NOT NULL, observed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS coordinator_leases(lease_name TEXT PRIMARY KEY, holder_id TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS configuration_snapshots(hash BLOB PRIMARY KEY, config_json TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS immutable_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, pool_id BLOB, round_id INTEGER, event_type TEXT NOT NULL, payload_hash BLOB NOT NULL, occurred_at TEXT NOT NULL);
"#;

/// Coordinator durable store. It never persists participant or ticket private keys.
pub struct Store {
    connection: Connection,
}

impl Store {
    /// Open a database and enforce WAL, foreign keys and bounded busy waiting.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5_000)?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    /// Open an in-memory database for deterministic tests.
    pub fn memory() -> Result<Self, StoreError> {
        let connection = Connection::open_in_memory()?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute_batch(MIGRATION_1)?;
        transaction.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?1)",
            [chrono::Utc::now().to_rfc3339()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Store a validated pool configuration snapshot.
    pub fn insert_pool(&mut self, pool: &mirror_pool_core::PoolConfig) -> Result<(), StoreError> {
        let json = serde_json::to_string(pool)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO pools(pool_id, config_json, created_at) VALUES(?1, ?2, ?3)",
            params![
                pool.pool_id.0.as_slice(),
                json,
                chrono::Utc::now().to_rfc3339()
            ],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO configuration_snapshots(hash, config_json, created_at) VALUES(?1, ?2, ?3)",
            params![pool.configuration_hash.0.as_slice(), serde_json::to_string(pool)?, chrono::Utc::now().to_rfc3339()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Insert or replace mutable round state before completion.
    pub fn put_round(&mut self, round: &Round) -> Result<(), StoreError> {
        let state = format!("{:?}", round.state).to_lowercase();
        self.connection.execute(
            "INSERT INTO rounds(pool_id, round_id, round_json, state, updated_at) VALUES(?1, ?2, ?3, ?4, ?5) ON CONFLICT(pool_id, round_id) DO UPDATE SET round_json=excluded.round_json, state=excluded.state, updated_at=excluded.updated_at",
            params![round.pool_id.0.as_slice(), as_i64(round.round_id)?, serde_json::to_string(round)?, state, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Fetch a round.
    pub fn round(&self, pool: Digest32, round_id: u64) -> Result<Option<Round>, StoreError> {
        let json: Option<String> = self
            .connection
            .query_row(
                "SELECT round_json FROM rounds WHERE pool_id=?1 AND round_id=?2",
                params![pool.0.as_slice(), as_i64(round_id)?],
                |row| row.get(0),
            )
            .optional()?;
        json.map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }

    /// Accept one public ticket atomically. Database uniqueness rejects key and commitment reuse.
    pub fn accept_ticket(&mut self, ticket: &JoinTicket) -> Result<Digest32, StoreError> {
        let commitment = ticket.commitment().map_err(|_| StoreError::InvalidTicket)?;
        let transaction = self.connection.transaction()?;
        let result = transaction.execute(
            "INSERT INTO join_tickets(pool_id, round_id, commitment, coordination_key, ticket_json, accepted_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![ticket.pool_id.0.as_slice(), as_i64(ticket.round_id)?, commitment.0.as_slice(), ticket.coordination_public_key.as_slice(), serde_json::to_string(ticket)?, chrono::Utc::now().to_rfc3339()],
        );
        match result {
            Ok(_) => {
                event(
                    &transaction,
                    Some(ticket.pool_id),
                    Some(ticket.round_id),
                    "ticket_accepted",
                    commitment,
                )?;
                transaction.commit()?;
                Ok(commitment)
            }
            Err(error)
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) =>
            {
                Err(StoreError::DuplicateTicket)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Deterministically build and persist an immutable root and every proof in one transaction.
    pub fn seal_cohort(
        &mut self,
        pool: Digest32,
        round_id: u64,
        minimum: u32,
    ) -> Result<(Digest32, u32), StoreError> {
        if let Some(existing) = self.root(pool, round_id)? {
            return Ok(existing);
        }
        let transaction = self.connection.transaction()?;
        let leaves = {
            let mut statement = transaction.prepare("SELECT commitment FROM join_tickets WHERE pool_id=?1 AND round_id=?2 ORDER BY commitment")?;
            let rows = statement
                .query_map(params![pool.0.as_slice(), as_i64(round_id)?], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?;
            let mut leaves = Vec::new();
            for row in rows {
                leaves.push(digest(row?)?);
            }
            leaves
        };
        let count = u32::try_from(leaves.len()).map_err(|_| StoreError::CountOverflow)?;
        if count < minimum {
            return Err(StoreError::ThresholdNotReached);
        }
        let tree = MerkleCohort::build(leaves.clone()).map_err(|_| StoreError::Merkle)?;
        let root = tree.root().map_err(|_| StoreError::Merkle)?;
        transaction.execute("INSERT INTO cohort_roots(pool_id, round_id, root, cohort_size, published_at) VALUES(?1, ?2, ?3, ?4, ?5)", params![pool.0.as_slice(), as_i64(round_id)?, root.0.as_slice(), i64::from(count), chrono::Utc::now().to_rfc3339()])?;
        for leaf in leaves {
            let proof = tree.proof(leaf, round_id).map_err(|_| StoreError::Merkle)?;
            transaction.execute("INSERT INTO cohort_proofs(pool_id, round_id, commitment, proof_json) VALUES(?1, ?2, ?3, ?4)", params![pool.0.as_slice(), as_i64(round_id)?, leaf.0.as_slice(), serde_json::to_string(&proof)?])?;
        }
        event(
            &transaction,
            Some(pool),
            Some(round_id),
            "cohort_sealed",
            root,
        )?;
        transaction.commit()?;
        Ok((root, count))
    }

    /// Read the immutable root and count.
    pub fn root(
        &self,
        pool: Digest32,
        round_id: u64,
    ) -> Result<Option<(Digest32, u32)>, StoreError> {
        self.connection
            .query_row(
                "SELECT root, cohort_size FROM cohort_roots WHERE pool_id=?1 AND round_id=?2",
                params![pool.0.as_slice(), as_i64(round_id)?],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u32>(1)?)),
            )
            .optional()?
            .map(|(bytes, count)| Ok((digest(bytes)?, count)))
            .transpose()
    }

    /// Read a persisted inclusion proof.
    pub fn proof(
        &self,
        pool: Digest32,
        round_id: u64,
        commitment: Digest32,
    ) -> Result<Option<CohortProof>, StoreError> {
        let json: Option<String> = self.connection.query_row("SELECT proof_json FROM cohort_proofs WHERE pool_id=?1 AND round_id=?2 AND commitment=?3", params![pool.0.as_slice(), as_i64(round_id)?, commitment.0.as_slice()], |row| row.get(0)).optional()?;
        json.map(|value| serde_json::from_str(&value).map_err(StoreError::from))
            .transpose()
    }

    /// Schedule release exactly once; identical retries are idempotent and conflicts fail.
    pub fn schedule_release(
        &mut self,
        pool: Digest32,
        round_id: u64,
        release: u64,
        end: u64,
    ) -> Result<(), StoreError> {
        let existing: Option<(u64, u64)> = self.connection.query_row("SELECT release_slot, window_end_slot FROM release_schedules WHERE pool_id=?1 AND round_id=?2", params![pool.0.as_slice(), as_i64(round_id)?], |row| Ok((row.get(0)?, row.get(1)?))).optional()?;
        if let Some(value) = existing {
            return if value == (release, end) {
                Ok(())
            } else {
                Err(StoreError::ConflictingSchedule)
            };
        }
        self.connection.execute("INSERT INTO release_schedules(pool_id, round_id, release_slot, window_end_slot, created_at) VALUES(?1, ?2, ?3, ?4, ?5)", params![pool.0.as_slice(), as_i64(round_id)?, as_i64(release)?, as_i64(end)?, chrono::Utc::now().to_rfc3339()])?;
        Ok(())
    }

    /// Count accepted tickets for observability.
    pub fn ticket_count(&self, pool: Digest32, round_id: u64) -> Result<u32, StoreError> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM join_tickets WHERE pool_id=?1 AND round_id=?2",
                params![pool.0.as_slice(), as_i64(round_id)?],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }
}

fn as_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::CountOverflow)
}
fn digest(bytes: Vec<u8>) -> Result<Digest32, StoreError> {
    bytes
        .try_into()
        .map(Digest32)
        .map_err(|_| StoreError::CorruptDatabase)
}
fn event(
    tx: &rusqlite::Transaction<'_>,
    pool: Option<Digest32>,
    round: Option<u64>,
    kind: &str,
    payload: Digest32,
) -> Result<(), StoreError> {
    tx.execute("INSERT INTO immutable_events(pool_id, round_id, event_type, payload_hash, occurred_at) VALUES(?1, ?2, ?3, ?4, ?5)", params![pool.map(|p| p.0.to_vec()), round.map(as_i64).transpose()?, kind, payload.0.as_slice(), chrono::Utc::now().to_rfc3339()])?;
    Ok(())
}

/// Durable store failures.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("ticket validation failed")]
    InvalidTicket,
    #[error("duplicate ticket key or commitment")]
    DuplicateTicket,
    #[error("cohort threshold not reached")]
    ThresholdNotReached,
    #[error("Merkle construction failed")]
    Merkle,
    #[error("conflicting release schedule")]
    ConflictingSchedule,
    #[error("integer is outside the persistent range")]
    CountOverflow,
    #[error("database contains invalid bounded data")]
    CorruptDatabase,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mirror_pool_crypto::JoinTicket;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    fn ticket(index: u8) -> JoinTicket {
        let mut rng = ChaCha20Rng::from_seed([index; 32]);
        JoinTicket::create(
            &mut rng,
            &SigningKey::from_bytes(&[index.saturating_add(1); 32]),
            Digest32([1; 32]),
            1,
            Digest32([2; 32]),
            100,
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .0
    }

    #[test]
    fn duplicate_ticket_and_conflicting_schedule_fail() {
        let mut store = Store::memory().unwrap_or_else(|error| panic!("{error}"));
        let ticket = ticket(1);
        assert!(store.accept_ticket(&ticket).is_ok());
        assert!(matches!(
            store.accept_ticket(&ticket),
            Err(StoreError::DuplicateTicket)
        ));
        assert!(store.schedule_release(Digest32([1; 32]), 1, 10, 20).is_ok());
        assert!(matches!(
            store.schedule_release(Digest32([1; 32]), 1, 11, 20),
            Err(StoreError::ConflictingSchedule)
        ));
    }

    #[test]
    fn sealing_is_deterministic_and_restart_idempotent() {
        let mut store = Store::memory().unwrap_or_else(|error| panic!("{error}"));
        for index in 1..=5 {
            assert!(store.accept_ticket(&ticket(index)).is_ok());
        }
        let first = store
            .seal_cohort(Digest32([1; 32]), 1, 3)
            .unwrap_or_else(|error| panic!("{error}"));
        let second = store
            .seal_cohort(Digest32([1; 32]), 1, 3)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first, second);
        let commitment = ticket(1).commitment().unwrap_or_default();
        let proof = store
            .proof(Digest32([1; 32]), 1, commitment)
            .unwrap_or_default()
            .unwrap_or_else(|| panic!("proof missing"));
        assert_eq!(proof.verify(first.0, 1), Ok(()));
    }

    #[test]
    fn on_disk_restart_preserves_root_and_rejects_conflicting_release() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let path = directory.path().join("coordinator.db");
        let root = {
            let mut store = Store::open(&path).unwrap_or_else(|error| panic!("{error}"));
            for index in 1..=4 {
                assert!(store.accept_ticket(&ticket(index)).is_ok());
            }
            let root = store
                .seal_cohort(Digest32([1; 32]), 1, 3)
                .unwrap_or_else(|error| panic!("{error}"));
            assert!(store.schedule_release(Digest32([1; 32]), 1, 20, 24).is_ok());
            root
        };
        let mut restarted = Store::open(&path).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            restarted
                .seal_cohort(Digest32([1; 32]), 1, 3)
                .unwrap_or_else(|error| panic!("{error}")),
            root
        );
        assert!(matches!(
            restarted.schedule_release(Digest32([1; 32]), 1, 21, 24),
            Err(StoreError::ConflictingSchedule)
        ));
    }
}
