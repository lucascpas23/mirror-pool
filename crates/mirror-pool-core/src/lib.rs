#![forbid(unsafe_code)]
//! Protocol domain types and fail-closed state transitions.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current wire schema version.
pub const SCHEMA_VERSION: u16 = 1;

/// Fixed-size identifier used for pools, templates and commitments.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Digest32(pub [u8; 32]);

impl Digest32 {
    /// Hash domain-separated bytes.
    #[must_use]
    pub fn hash(domain: &[u8], bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"mirror-pool/v1/");
        hasher.update(domain);
        hasher.update(&[0]);
        hasher.update(bytes);
        Self(*hasher.finalize().as_bytes())
    }

    /// Lowercase hexadecimal representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Implemented privacy coordination backends.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBackend {
    /// Public one-time-key registry baseline.
    TransparentRegistry,
    /// Opaque off-chain tickets aggregated into a Merkle root.
    MerkleCohort,
}

/// Authority policy for pool administration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernancePolicy {
    /// A single public-key authority controls administrative transitions.
    SingleAuthority { authority: [u8; 32] },
}

/// Whether and how completion may be reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionPolicy {
    Disabled,
    RedactedReceipt,
    PublicObservationOnly,
}

/// Supported Solana cluster policies.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cluster {
    Localnet,
    Devnet,
    Testnet,
    MainnetBeta,
}

/// Validated immutable policy for a coordination pool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PoolConfig {
    pub pool_id: Digest32,
    pub version: u16,
    pub governance: GovernancePolicy,
    pub action_template_hash: Digest32,
    pub min_participants: u32,
    pub max_participants: u32,
    pub registration_duration_slots: u64,
    pub min_release_delay_slots: u64,
    pub max_release_delay_slots: u64,
    pub execution_window_slots: u64,
    pub max_timing_dispersion_slots: u64,
    pub privacy_backend: PrivacyBackend,
    pub allowed_clusters: BTreeSet<Cluster>,
    pub allowed_program_ids: BTreeSet<[u8; 32]>,
    pub completion_policy: CompletionPolicy,
    pub created_at_unix: i64,
    pub configuration_hash: Digest32,
}

impl PoolConfig {
    /// Recompute the configuration hash with the hash field zeroed.
    pub fn compute_hash(&self) -> Result<Digest32, ProtocolError> {
        let mut canonical = self.clone();
        canonical.configuration_hash = Digest32::default();
        let bytes = serde_json::to_vec(&canonical).map_err(|_| ProtocolError::Serialization)?;
        Ok(Digest32::hash(b"pool-config", &bytes))
    }

    /// Validate all timing, size, cluster and integrity constraints.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != SCHEMA_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.min_participants < 2 || self.min_participants > self.max_participants {
            return Err(ProtocolError::InvalidParticipantBounds);
        }
        if self.max_participants > 100_000 {
            return Err(ProtocolError::InvalidParticipantBounds);
        }
        if self.registration_duration_slots == 0
            || self.execution_window_slots == 0
            || self.min_release_delay_slots > self.max_release_delay_slots
            || self.max_timing_dispersion_slots > self.execution_window_slots
        {
            return Err(ProtocolError::InvalidTimingBounds);
        }
        if self.allowed_clusters.is_empty() || self.allowed_program_ids.is_empty() {
            return Err(ProtocolError::EmptyAllowlist);
        }
        if self.compute_hash()? != self.configuration_hash {
            return Err(ProtocolError::ConfigurationHashMismatch);
        }
        Ok(())
    }
}

/// Explicit round lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundState {
    Draft,
    Registration,
    ThresholdReached,
    Sealed,
    ReleaseScheduled,
    ExecutionWindow,
    Finalizing,
    Completed,
    Cancelled,
    Expired,
}

impl RoundState {
    /// Whether transition to `next` is permitted by the protocol graph.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Draft, Self::Registration)
                | (Self::Draft, Self::Cancelled)
                | (Self::Registration, Self::ThresholdReached)
                | (Self::Registration, Self::Cancelled)
                | (Self::Registration, Self::Expired)
                | (Self::ThresholdReached, Self::Sealed)
                | (Self::ThresholdReached, Self::Cancelled)
                | (Self::ThresholdReached, Self::Expired)
                | (Self::Sealed, Self::ReleaseScheduled)
                | (Self::Sealed, Self::Cancelled)
                | (Self::ReleaseScheduled, Self::ExecutionWindow)
                | (Self::ReleaseScheduled, Self::Cancelled)
                | (Self::ReleaseScheduled, Self::Expired)
                | (Self::ExecutionWindow, Self::Finalizing)
                | (Self::ExecutionWindow, Self::Cancelled)
                | (Self::Finalizing, Self::Completed)
                | (Self::Finalizing, Self::Cancelled)
        )
    }
}

/// Public coordination state for one pool round.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Round {
    pub pool_id: Digest32,
    pub round_id: u64,
    pub state: RoundState,
    pub registration_start_slot: u64,
    pub registration_deadline_slot: u64,
    pub release_slot: Option<u64>,
    pub execution_window_start: Option<u64>,
    pub execution_window_end: Option<u64>,
    pub expected_cohort_size: u32,
    pub accepted_cohort_size: u32,
    pub cohort_merkle_root: Option<Digest32>,
    pub action_template_hash: Digest32,
    pub privacy_backend: PrivacyBackend,
    pub cancellation_reason: Option<String>,
    pub final_metrics_hash: Option<Digest32>,
}

impl Round {
    /// Apply a permitted lifecycle transition.
    pub fn transition(&mut self, next: RoundState) -> Result<(), ProtocolError> {
        if !self.state.can_transition_to(next) {
            return Err(ProtocolError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }

    /// Record a registration while enforcing time, state and count constraints.
    pub fn register(&mut self, current_slot: u64, max: u32) -> Result<(), ProtocolError> {
        if !matches!(
            self.state,
            RoundState::Registration | RoundState::ThresholdReached
        ) {
            return Err(ProtocolError::RegistrationClosed);
        }
        if current_slot >= self.registration_deadline_slot {
            return Err(ProtocolError::RegistrationClosed);
        }
        if self.accepted_cohort_size >= max {
            return Err(ProtocolError::CohortFull);
        }
        self.accepted_cohort_size = self
            .accepted_cohort_size
            .checked_add(1)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Seal the cohort root exactly once after threshold is reached.
    pub fn seal(&mut self, root: Digest32, minimum: u32) -> Result<(), ProtocolError> {
        if self.state != RoundState::ThresholdReached || self.accepted_cohort_size < minimum {
            return Err(ProtocolError::PrematureSeal);
        }
        if self.cohort_merkle_root.is_some() {
            return Err(ProtocolError::RootImmutable);
        }
        self.cohort_merkle_root = Some(root);
        self.transition(RoundState::Sealed)
    }

    /// Announce an immutable bounded execution window.
    pub fn schedule_release(
        &mut self,
        current_slot: u64,
        release_slot: u64,
        config: &PoolConfig,
    ) -> Result<(), ProtocolError> {
        if self.state != RoundState::Sealed || self.release_slot.is_some() {
            return Err(ProtocolError::ReleaseImmutable);
        }
        let delay = release_slot
            .checked_sub(current_slot)
            .ok_or(ProtocolError::InvalidReleaseDelay)?;
        if delay < config.min_release_delay_slots || delay > config.max_release_delay_slots {
            return Err(ProtocolError::InvalidReleaseDelay);
        }
        let end = release_slot
            .checked_add(config.execution_window_slots)
            .ok_or(ProtocolError::ArithmeticOverflow)?;
        self.release_slot = Some(release_slot);
        self.execution_window_start = Some(release_slot);
        self.execution_window_end = Some(end);
        self.transition(RoundState::ReleaseScheduled)
    }
}

/// Action risk category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyClassification {
    LocalOnly,
    LowRisk,
    Prohibited,
}

/// Canonical shape policy for participant-owned actions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionTemplate {
    pub template_id: Digest32,
    pub version: u16,
    pub action_category: String,
    pub required_program_ids: Vec<[u8; 32]>,
    pub instruction_count: u8,
    pub value_bucket: Option<(u64, u64)>,
    pub compute_unit_bucket: Option<(u32, u32)>,
    pub maximum_transaction_size: u16,
    pub maximum_priority_fee: u64,
    pub safety_classification: SafetyClassification,
    pub redacted_features: Vec<String>,
}

/// Redacted public execution observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub round_id: u64,
    pub transaction_signature: String,
    pub observed_slot: u64,
    pub action_template_id: Digest32,
    pub execution_classification: String,
    pub redacted_feature_fingerprint: Digest32,
    pub verification_status: ReceiptStatus,
}

/// Receipt verification state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Unverified,
    Observed,
    Rejected,
}

/// Typed protocol validation failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("unsupported schema version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid participant bounds")]
    InvalidParticipantBounds,
    #[error("invalid timing bounds")]
    InvalidTimingBounds,
    #[error("required allowlist is empty")]
    EmptyAllowlist,
    #[error("configuration hash mismatch")]
    ConfigurationHashMismatch,
    #[error("canonical serialization failed")]
    Serialization,
    #[error("invalid transition from {from:?} to {to:?}")]
    InvalidTransition { from: RoundState, to: RoundState },
    #[error("registration is closed")]
    RegistrationClosed,
    #[error("cohort is full")]
    CohortFull,
    #[error("checked arithmetic overflow")]
    ArithmeticOverflow,
    #[error("round cannot be sealed")]
    PrematureSeal,
    #[error("sealed Merkle root is immutable")]
    RootImmutable,
    #[error("release schedule is immutable")]
    ReleaseImmutable,
    #[error("release delay violates pool policy")]
    InvalidReleaseDelay,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_declared_valid_transitions_are_accepted() {
        let valid = [
            (RoundState::Draft, RoundState::Registration),
            (RoundState::Registration, RoundState::ThresholdReached),
            (RoundState::ThresholdReached, RoundState::Sealed),
            (RoundState::Sealed, RoundState::ReleaseScheduled),
            (RoundState::ReleaseScheduled, RoundState::ExecutionWindow),
            (RoundState::ExecutionWindow, RoundState::Finalizing),
            (RoundState::Finalizing, RoundState::Completed),
        ];
        for (from, to) in valid {
            assert!(from.can_transition_to(to));
        }
    }

    #[test]
    fn terminal_states_reject_every_transition() {
        for terminal in [
            RoundState::Completed,
            RoundState::Cancelled,
            RoundState::Expired,
        ] {
            for candidate in [
                RoundState::Draft,
                RoundState::Registration,
                RoundState::ThresholdReached,
                RoundState::Sealed,
                RoundState::ReleaseScheduled,
                RoundState::ExecutionWindow,
                RoundState::Finalizing,
                RoundState::Completed,
                RoundState::Cancelled,
                RoundState::Expired,
            ] {
                assert!(!terminal.can_transition_to(candidate));
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn digest_is_deterministic(input in proptest::collection::vec(proptest::num::u8::ANY, 0..2048)) {
            proptest::prop_assert_eq!(Digest32::hash(b"test", &input), Digest32::hash(b"test", &input));
        }
    }
}
