#![forbid(unsafe_code)]
//! Signed opaque coordination tickets. These do not hide network metadata or activity wallets.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mirror_pool_core::{Digest32, SCHEMA_VERSION};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public signed request to join a cohort. It deliberately contains no activity-wallet key.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct JoinTicket {
    pub schema_version: u16,
    pub pool_id: Digest32,
    pub round_id: u64,
    pub action_template_hash: Digest32,
    pub coordination_public_key: [u8; 32],
    pub nonce_commitment: Digest32,
    pub expiry_slot: u64,
    pub signature: Vec<u8>,
}

impl fmt::Debug for JoinTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinTicket")
            .field("schema_version", &self.schema_version)
            .field("pool_id", &self.pool_id)
            .field("round_id", &self.round_id)
            .field("action_template_hash", &self.action_template_hash)
            .field("coordination_key_id", &self.key_id())
            .field("nonce_commitment", &self.nonce_commitment)
            .field("expiry_slot", &self.expiry_slot)
            .field("signature", &"[REDACTED]")
            .finish()
    }
}

impl JoinTicket {
    /// Create and sign a ticket with a fresh secret nonce.
    pub fn create<R: CryptoRng + RngCore>(
        rng: &mut R,
        signing_key: &SigningKey,
        pool_id: Digest32,
        round_id: u64,
        template_hash: Digest32,
        expiry_slot: u64,
    ) -> Result<(Self, SecretNonce), TicketError> {
        let mut nonce = SecretNonce([0; 32]);
        rng.fill_bytes(&mut nonce.0);
        let mut ticket = Self {
            schema_version: SCHEMA_VERSION,
            pool_id,
            round_id,
            action_template_hash: template_hash,
            coordination_public_key: signing_key.verifying_key().to_bytes(),
            nonce_commitment: Digest32::hash(b"ticket-nonce", &nonce.0),
            expiry_slot,
            signature: Vec::new(),
        };
        let signature = signing_key.sign(&ticket.signing_bytes()?);
        ticket.signature = signature.to_bytes().to_vec();
        Ok((ticket, nonce))
    }

    /// Verify schema, binding, expiry and signature.
    pub fn verify(&self, current_slot: u64, expected: &TicketBinding) -> Result<(), TicketError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(TicketError::UnsupportedVersion);
        }
        if self.pool_id != expected.pool_id {
            return Err(TicketError::WrongPool);
        }
        if self.round_id != expected.round_id {
            return Err(TicketError::WrongRound);
        }
        if self.action_template_hash != expected.action_template_hash {
            return Err(TicketError::WrongTemplate);
        }
        if current_slot >= self.expiry_slot {
            return Err(TicketError::Expired);
        }
        let public_key = VerifyingKey::from_bytes(&self.coordination_public_key)
            .map_err(|_| TicketError::InvalidPublicKey)?;
        let signature_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| TicketError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        public_key
            .verify(&self.signing_bytes()?, &signature)
            .map_err(|_| TicketError::InvalidSignature)
    }

    /// Stable identity for ticket deduplication.
    pub fn commitment(&self) -> Result<Digest32, TicketError> {
        Ok(Digest32::hash(b"join-ticket", &self.canonical_bytes()?))
    }

    /// Redacted identifier for observability.
    #[must_use]
    pub fn key_id(&self) -> String {
        let digest = Digest32::hash(b"coordination-key-id", &self.coordination_public_key);
        digest.to_hex()[..12].to_owned()
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, TicketError> {
        let unsigned = UnsignedTicket {
            schema_version: self.schema_version,
            pool_id: self.pool_id,
            round_id: self.round_id,
            action_template_hash: self.action_template_hash,
            coordination_public_key: self.coordination_public_key,
            nonce_commitment: self.nonce_commitment,
            expiry_slot: self.expiry_slot,
        };
        serde_json::to_vec(&unsigned).map_err(|_| TicketError::Serialization)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, TicketError> {
        serde_json::to_vec(self).map_err(|_| TicketError::Serialization)
    }
}

#[derive(Serialize)]
struct UnsignedTicket {
    schema_version: u16,
    pool_id: Digest32,
    round_id: u64,
    action_template_hash: Digest32,
    coordination_public_key: [u8; 32],
    nonce_commitment: Digest32,
    expiry_slot: u64,
}

/// Expected immutable context for ticket verification.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct TicketBinding {
    pub pool_id: Digest32,
    pub round_id: u64,
    pub action_template_hash: Digest32,
}

/// Participant-held nonce used for private release-offset derivation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretNonce(pub [u8; 32]);

impl fmt::Debug for SecretNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretNonce([REDACTED])")
    }
}

/// A one-time coordination signing key with secret-safe formatting.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CoordinationSecret(pub [u8; 32]);

impl CoordinationSecret {
    /// Generate from the operating-system random source.
    pub fn generate() -> Self {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        Self(key.to_bytes())
    }

    /// Borrow as an Ed25519 signing key.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for CoordinationSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CoordinationSecret([REDACTED])")
    }
}

/// Ticket validation failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum TicketError {
    #[error("unsupported ticket schema")]
    UnsupportedVersion,
    #[error("ticket is for a different pool")]
    WrongPool,
    #[error("ticket is for a different round")]
    WrongRound,
    #[error("ticket is for a different action template")]
    WrongTemplate,
    #[error("ticket has expired")]
    Expired,
    #[error("invalid coordination public key")]
    InvalidPublicKey,
    #[error("invalid ticket signature")]
    InvalidSignature,
    #[error("ticket serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    fn fixture() -> (JoinTicket, TicketBinding) {
        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let secret = SigningKey::from_bytes(&[9; 32]);
        let binding = TicketBinding {
            pool_id: Digest32([1; 32]),
            round_id: 3,
            action_template_hash: Digest32([2; 32]),
        };
        let (ticket, _) = JoinTicket::create(
            &mut rng,
            &secret,
            binding.pool_id,
            binding.round_id,
            binding.action_template_hash,
            100,
        )
        .unwrap_or_else(|error| panic!("fixture failed: {error}"));
        (ticket, binding)
    }

    #[test]
    fn signed_ticket_verifies() {
        let (ticket, binding) = fixture();
        assert_eq!(ticket.verify(99, &binding), Ok(()));
    }

    #[test]
    fn mutations_and_expiry_are_rejected() {
        let (mut ticket, binding) = fixture();
        ticket.expiry_slot += 1;
        assert_eq!(
            ticket.verify(99, &binding),
            Err(TicketError::InvalidSignature)
        );
        let (ticket, binding) = fixture();
        assert_eq!(ticket.verify(100, &binding), Err(TicketError::Expired));
    }

    #[test]
    fn secrets_are_redacted() {
        assert_eq!(
            format!("{:?}", CoordinationSecret([42; 32])),
            "CoordinationSecret([REDACTED])"
        );
        let (ticket, _) = fixture();
        use base64::Engine as _;
        assert!(
            !format!("{ticket:?}")
                .contains(&base64::engine::general_purpose::STANDARD.encode([9; 32]))
        );
    }
}
