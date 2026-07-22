#![forbid(unsafe_code)]
//! Typed participant SDK. Signing material remains caller-owned.

use borsh::BorshSerialize;
use ed25519_dalek::SigningKey;
use mirror_pool_actions::{PreparedAction, SafetyPolicy};
use mirror_pool_core::{Digest32, PoolConfig, Round};
use mirror_pool_crypto::{JoinTicket, SecretNonce, TicketBinding};
use mirror_pool_merkle::{CohortProof, MerkleCohort};
use mirror_pool_program::{Backend, CoordinationInstruction};
use rand::{CryptoRng, RngCore};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::read_keypair_file;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::{path::Path, str::FromStr as _};
use thiserror::Error;
use url::Url;

/// Public, non-sensitive RPC health information used by `doctor` and round creation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RpcInspection {
    pub identity: String,
    pub genesis_hash: String,
    pub software_version: String,
    pub slot: u64,
}

/// Inspect a Solana RPC endpoint at confirmed commitment.
pub fn inspect_rpc(rpc_url: &Url) -> Result<RpcInspection, ClientError> {
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let version = rpc.get_version().map_err(|_| ClientError::Rpc)?;
    Ok(RpcInspection {
        identity: rpc
            .get_identity()
            .map_err(|_| ClientError::Rpc)?
            .to_string(),
        genesis_hash: rpc
            .get_genesis_hash()
            .map_err(|_| ClientError::Rpc)?
            .to_string(),
        software_version: version.solana_core,
        slot: rpc.get_slot().map_err(|_| ClientError::Rpc)?,
    })
}

/// Derive the pool PDA.
#[must_use]
pub fn derive_pool_address(program_id: &Pubkey, pool_id: Digest32) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"pool", &pool_id.0], program_id)
}
/// Derive a sequential round PDA.
#[must_use]
pub fn derive_round_address(program_id: &Pubkey, pool: &Pubkey, round_id: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"round", pool.as_ref(), &round_id.to_le_bytes()],
        program_id,
    )
}
/// Create a ticket without an activity-wallet identifier.
pub fn create_join_ticket<R: CryptoRng + RngCore>(
    rng: &mut R,
    signing_key: &SigningKey,
    binding: TicketBinding,
    expiry_slot: u64,
) -> Result<(JoinTicket, SecretNonce), ClientError> {
    JoinTicket::create(
        rng,
        signing_key,
        binding.pool_id,
        binding.round_id,
        binding.action_template_hash,
        expiry_slot,
    )
    .map_err(|_| ClientError::Ticket)
}
/// Verify a signed ticket.
pub fn verify_join_ticket(
    ticket: &JoinTicket,
    slot: u64,
    binding: &TicketBinding,
) -> Result<(), ClientError> {
    ticket
        .verify(slot, binding)
        .map_err(|_| ClientError::Ticket)
}
/// Build a deterministic cohort.
pub fn build_merkle_cohort(tickets: &[JoinTicket]) -> Result<MerkleCohort, ClientError> {
    let leaves = tickets
        .iter()
        .map(JoinTicket::commitment)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ClientError::Ticket)?;
    MerkleCohort::build(leaves).map_err(|_| ClientError::Merkle)
}
/// Generate an inclusion proof.
pub fn generate_cohort_proof(
    cohort: &MerkleCohort,
    ticket: &JoinTicket,
    round: u64,
) -> Result<CohortProof, ClientError> {
    cohort
        .proof(ticket.commitment().map_err(|_| ClientError::Ticket)?, round)
        .map_err(|_| ClientError::Merkle)
}
/// Verify an inclusion proof.
pub fn verify_cohort_proof(
    proof: &CohortProof,
    root: Digest32,
    round: u64,
) -> Result<(), ClientError> {
    proof.verify(root, round).map_err(|_| ClientError::Merkle)
}
/// Verify fetched state against participant intent.
pub fn verify_round_configuration(pool: &PoolConfig, round: &Round) -> Result<(), ClientError> {
    pool.validate().map_err(|_| ClientError::Configuration)?;
    if pool.pool_id != round.pool_id
        || pool.action_template_hash != round.action_template_hash
        || pool.privacy_backend != round.privacy_backend
    {
        return Err(ClientError::Configuration);
    }
    Ok(())
}

/// Result of a participant-owned loopback Memo transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalExecutionReceipt {
    pub signature: String,
    pub observed_slot: u64,
    pub estimated_fee_lamports: u64,
}

/// Simulate, safety-check, sign locally, submit, and confirm one canonical Memo action.
pub fn execute_local_memo(
    action: &PreparedAction,
    wallet: &Path,
    rpc_url: &Url,
    window_start: u64,
    window_end: u64,
    explicit_confirmation: bool,
    sending_enabled: bool,
) -> Result<LocalExecutionReceipt, ClientError> {
    if !explicit_confirmation || !sending_enabled {
        return Err(ClientError::ExecutionDisabled);
    }
    if action.template_id != "memo-v1" {
        return Err(ClientError::UnsupportedAction);
    }
    let memo_program = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
        .map_err(|_| ClientError::InvalidProgram)?;
    if action.program_ids != vec![memo_program.to_bytes()] {
        return Err(ClientError::InvalidProgram);
    }
    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let slot = rpc.get_slot().map_err(|_| ClientError::Rpc)?;
    if slot < window_start || slot > window_end {
        return Err(ClientError::OutsideExecutionWindow);
    }
    let policy = SafetyPolicy {
        dry_run: false,
        sending_enabled: true,
        allowed_program_ids: vec![memo_program.to_bytes()],
        allowed_templates: vec!["memo-v1".to_owned()],
        ..SafetyPolicy::default()
    };
    policy
        .validate(action, rpc_url, false, false, 0, false)
        .map_err(|_| ClientError::SafetyPolicy)?;
    let keypair = read_keypair_file(wallet).map_err(|_| ClientError::Wallet)?;
    let instruction = Instruction::new_with_bytes(memo_program, &action.payload, Vec::new());
    let blockhash = rpc.get_latest_blockhash().map_err(|_| ClientError::Rpc)?;
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&keypair.pubkey()),
        &[&keypair],
        blockhash,
    );
    let simulated = rpc
        .simulate_transaction(&transaction)
        .map_err(|_| ClientError::Rpc)?;
    let estimated_fee_lamports = rpc
        .get_fee_for_message(&transaction.message)
        .map_err(|_| ClientError::Rpc)?;
    policy
        .validate(
            action,
            rpc_url,
            true,
            simulated.value.err.is_none(),
            estimated_fee_lamports,
            true,
        )
        .map_err(|_| ClientError::SafetyPolicy)?;
    let signature = rpc
        .send_and_confirm_transaction(&transaction)
        .map_err(|_| ClientError::Rpc)?;
    Ok(LocalExecutionReceipt {
        signature: signature.to_string(),
        observed_slot: slot,
        estimated_fee_lamports,
    })
}

/// Build pool initialization and derive its PDA.
#[allow(clippy::too_many_arguments)]
pub fn initialize_pool_instruction(
    program_id: Pubkey,
    authority: Pubkey,
    pool_id: [u8; 32],
    template_hash: [u8; 32],
    min_participants: u32,
    max_participants: u32,
    min_release_delay: u64,
    max_release_delay: u64,
    execution_window: u64,
    backend: Backend,
) -> Result<(Instruction, Pubkey), ClientError> {
    let (pool, bump) = Pubkey::find_program_address(&[b"pool", &pool_id], &program_id);
    let data = encode(&CoordinationInstruction::InitializePool {
        pool_id,
        template_hash,
        min_participants,
        max_participants,
        min_release_delay,
        max_release_delay,
        execution_window,
        backend,
        bump,
    })?;
    Ok((
        Instruction::new_with_bytes(
            program_id,
            &data,
            vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(pool, false),
                AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            ],
        ),
        pool,
    ))
}

/// Build a round-open instruction and derive its PDA.
pub fn open_round_instruction(
    program_id: Pubkey,
    authority: Pubkey,
    pool: Pubkey,
    round_id: u64,
    registration_deadline: u64,
    template_hash: [u8; 32],
) -> Result<(Instruction, Pubkey), ClientError> {
    let (round, bump) = Pubkey::find_program_address(
        &[b"round", pool.as_ref(), &round_id.to_le_bytes()],
        &program_id,
    );
    let data = encode(&CoordinationInstruction::OpenRound {
        round_id,
        registration_deadline,
        template_hash,
        bump,
    })?;
    Ok((
        Instruction::new_with_bytes(
            program_id,
            &data,
            vec![
                AccountMeta::new(authority, true),
                AccountMeta::new(pool, false),
                AccountMeta::new(round, false),
                AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            ],
        ),
        round,
    ))
}

/// Build an authority-controlled pool/round transition.
pub fn admin_round_instruction(
    program_id: Pubkey,
    authority: Pubkey,
    pool: Pubkey,
    round: Pubkey,
    instruction: CoordinationInstruction,
) -> Result<Instruction, ClientError> {
    Ok(Instruction::new_with_bytes(
        program_id,
        &encode(&instruction)?,
        vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(pool, false),
            AccountMeta::new(round, false),
        ],
    ))
}

/// Build the permissionless execution-window transition.
pub fn begin_window_instruction(
    program_id: Pubkey,
    round: Pubkey,
) -> Result<Instruction, ClientError> {
    Ok(Instruction::new_with_bytes(
        program_id,
        &encode(&CoordinationInstruction::BeginExecutionWindow)?,
        vec![AccountMeta::new(round, false)],
    ))
}

fn encode(value: &CoordinationInstruction) -> Result<Vec<u8>, ClientError> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut bytes)
        .map_err(|_| ClientError::Serialization)?;
    Ok(bytes)
}

/// SDK failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ClientError {
    #[error("ticket validation failed")]
    Ticket,
    #[error("Merkle proof failed")]
    Merkle,
    #[error("round configuration mismatch")]
    Configuration,
    #[error("participant sending is disabled")]
    ExecutionDisabled,
    #[error("unsupported participant action")]
    UnsupportedAction,
    #[error("invalid action program")]
    InvalidProgram,
    #[error("outside execution window")]
    OutsideExecutionWindow,
    #[error("action safety policy rejected execution")]
    SafetyPolicy,
    #[error("wallet could not be read")]
    Wallet,
    #[error("RPC request failed")]
    Rpc,
    #[error("instruction serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize as _;
    use mirror_pool_actions::{ActionParameters, ActionTemplateDriver, MemoTemplate};

    #[test]
    fn builders_derive_expected_pdas_and_closed_instructions() {
        let program = Pubkey::new_from_array([9; 32]);
        let authority = Pubkey::new_from_array([8; 32]);
        let (initialize, pool) = initialize_pool_instruction(
            program,
            authority,
            [1; 32],
            [2; 32],
            10,
            100,
            2,
            50,
            20,
            Backend::MerkleCohort,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(initialize.accounts.len(), 3);
        assert_eq!(initialize.accounts[1].pubkey, pool);
        assert!(matches!(
            CoordinationInstruction::try_from_slice(&initialize.data),
            Ok(CoordinationInstruction::InitializePool { .. })
        ));
        let (open, round) = open_round_instruction(program, authority, pool, 0, 1_000, [2; 32])
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(open.accounts.len(), 4);
        assert_eq!(open.accounts[2].pubkey, round);
    }

    #[test]
    fn local_execution_fails_before_rpc_when_not_acknowledged() {
        let memo_program: Pubkey = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        let action = MemoTemplate {
            memo_program_id: memo_program.to_bytes(),
        }
        .prepare(&ActionParameters::Memo {
            text: "test".to_owned(),
        })
        .unwrap_or_else(|error| panic!("{error}"));
        let rpc = Url::parse("http://127.0.0.1:8899").unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            execute_local_memo(
                &action,
                Path::new("does-not-exist.json"),
                &rpc,
                0,
                10,
                false,
                false,
            ),
            Err(ClientError::ExecutionDisabled)
        );
    }
}
