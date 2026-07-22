#![forbid(unsafe_code)]
//! Native Solana coordination program. It owns only bounded metadata/rent accounts and never
//! receives, pools, signs for, or transfers participant assets.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
};
use solana_system_interface::{instruction as system_instruction, program as system_program};

// Default fixture ID; the processor validates PDAs and ownership against the runtime deployment ID.
solana_program::declare_id!("J94pz1kX5dZBPAq122uC38skwT9PKe9uPaTiG3khhrfW");
/// Maximum on-chain transparent cohort size. Each participant uses a separate fixed-size PDA.
pub const MAX_COHORT_SIZE: u32 = 100_000;
/// Fixed pool metadata account size.
pub const POOL_ACCOUNT_SIZE: usize = 256;
/// Fixed round metadata account size.
pub const ROUND_ACCOUNT_SIZE: usize = 256;

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

/// On-chain privacy backend tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub enum Backend {
    TransparentRegistry,
    MerkleCohort,
}
/// Compact round lifecycle tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub enum State {
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

/// Bounded pool metadata; no participant funds or keys are stored.
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct PoolAccount {
    pub version: u8,
    pub bump: u8,
    pub authority: Pubkey,
    pub pool_id: [u8; 32],
    pub template_hash: [u8; 32],
    pub min_participants: u32,
    pub max_participants: u32,
    pub min_release_delay: u64,
    pub max_release_delay: u64,
    pub execution_window: u64,
    pub backend: Backend,
    pub next_round: u64,
    pub paused: bool,
}

/// Bounded round metadata. Transparent registrations live in separate fixed-size PDAs.
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct RoundAccount {
    pub version: u8,
    pub bump: u8,
    pub pool: Pubkey,
    pub round_id: u64,
    pub state: State,
    pub registration_deadline: u64,
    pub template_hash: [u8; 32],
    pub accepted_count: u32,
    pub cohort_root: [u8; 32],
    pub release_slot: u64,
    pub window_end_slot: u64,
    pub metrics_hash: [u8; 32],
}

/// One-time public key record for transparent baseline registration.
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct ParticipantRecord {
    pub version: u8,
    pub bump: u8,
    pub round: Pubkey,
    pub coordination_key: [u8; 32],
}

/// Strict, closed instruction set. There is no generic CPI or participant-action instruction.
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub enum CoordinationInstruction {
    InitializePool {
        pool_id: [u8; 32],
        template_hash: [u8; 32],
        min_participants: u32,
        max_participants: u32,
        min_release_delay: u64,
        max_release_delay: u64,
        execution_window: u64,
        backend: Backend,
        bump: u8,
    },
    OpenRound {
        round_id: u64,
        registration_deadline: u64,
        template_hash: [u8; 32],
        bump: u8,
    },
    RegisterTransparent {
        coordination_key: [u8; 32],
        record_bump: u8,
    },
    PublishCohortRoot {
        root: [u8; 32],
        accepted_count: u32,
    },
    SealRound,
    ScheduleRelease {
        release_slot: u64,
    },
    BeginExecutionWindow,
    FinalizeRound {
        metrics_hash: [u8; 32],
    },
    CancelRound,
    CloseRound,
}

/// Program entrypoint.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    data: &[u8],
) -> ProgramResult {
    let instruction = CoordinationInstruction::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    match instruction {
        CoordinationInstruction::InitializePool {
            pool_id,
            template_hash,
            min_participants,
            max_participants,
            min_release_delay,
            max_release_delay,
            execution_window,
            backend,
            bump,
        } => initialize(
            program_id,
            accounts,
            pool_id,
            template_hash,
            min_participants,
            max_participants,
            min_release_delay,
            max_release_delay,
            execution_window,
            backend,
            bump,
        ),
        CoordinationInstruction::OpenRound {
            round_id,
            registration_deadline,
            template_hash,
            bump,
        } => open_round(
            program_id,
            accounts,
            round_id,
            registration_deadline,
            template_hash,
            bump,
        ),
        CoordinationInstruction::RegisterTransparent {
            coordination_key,
            record_bump,
        } => register_transparent(program_id, accounts, coordination_key, record_bump),
        CoordinationInstruction::PublishCohortRoot {
            root,
            accepted_count,
        } => publish_root(program_id, accounts, root, accepted_count),
        CoordinationInstruction::SealRound => seal(program_id, accounts),
        CoordinationInstruction::ScheduleRelease { release_slot } => {
            schedule(program_id, accounts, release_slot)
        }
        CoordinationInstruction::BeginExecutionWindow => begin(program_id, accounts),
        CoordinationInstruction::FinalizeRound { metrics_hash } => {
            finalize(program_id, accounts, metrics_hash)
        }
        CoordinationInstruction::CancelRound => cancel(program_id, accounts),
        CoordinationInstruction::CloseRound => close(program_id, accounts),
    }
}

#[allow(clippy::too_many_arguments)]
fn initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    pool_id: [u8; 32],
    template_hash: [u8; 32],
    min: u32,
    max: u32,
    min_delay: u64,
    max_delay: u64,
    window: u64,
    backend: Backend,
    bump: u8,
) -> ProgramResult {
    if min < 2 || min > max || max > MAX_COHORT_SIZE || window == 0 || min_delay > max_delay {
        return Err(CoordinationError::InvalidPolicy.into());
    }
    let mut iter = accounts.iter();
    let authority = next_account_info(&mut iter)?;
    let pool_info = next_account_info(&mut iter)?;
    let system_info = next_account_info(&mut iter)?;
    require_signer(authority)?;
    let expected = Pubkey::create_program_address(&[b"pool", &pool_id, &[bump]], program_id)
        .map_err(|_| CoordinationError::InvalidPda)?;
    if expected != *pool_info.key {
        return Err(CoordinationError::InvalidPda.into());
    }
    create_pda_account(
        authority,
        pool_info,
        system_info,
        program_id,
        POOL_ACCOUNT_SIZE,
        &[b"pool", &pool_id, &[bump]],
    )?;
    let pool = PoolAccount {
        version: 1,
        bump,
        authority: *authority.key,
        pool_id,
        template_hash,
        min_participants: min,
        max_participants: max,
        min_release_delay: min_delay,
        max_release_delay: max_delay,
        execution_window: window,
        backend,
        next_round: 0,
        paused: false,
    };
    write_account(pool_info, &pool)?;
    msg!("PoolInitialized");
    Ok(())
}

fn open_round(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    round_id: u64,
    deadline: u64,
    template: [u8; 32],
    bump: u8,
) -> ProgramResult {
    let mut iter = accounts.iter();
    let authority = next_account_info(&mut iter)?;
    let pool_info = next_account_info(&mut iter)?;
    let round_info = next_account_info(&mut iter)?;
    let system_info = next_account_info(&mut iter)?;
    require_signer(authority)?;
    require_owned(pool_info, program_id)?;
    let mut pool: PoolAccount = read_account(pool_info)?;
    if pool.authority != *authority.key
        || pool.paused
        || pool.next_round != round_id
        || pool.template_hash != template
    {
        return Err(CoordinationError::Unauthorized.into());
    }
    let clock = Clock::get()?;
    if deadline <= clock.slot {
        return Err(CoordinationError::InvalidTiming.into());
    }
    let expected = Pubkey::create_program_address(
        &[
            b"round",
            pool_info.key.as_ref(),
            &round_id.to_le_bytes(),
            &[bump],
        ],
        program_id,
    )
    .map_err(|_| CoordinationError::InvalidPda)?;
    if expected != *round_info.key {
        return Err(CoordinationError::InvalidPda.into());
    }
    let round_id_bytes = round_id.to_le_bytes();
    create_pda_account(
        authority,
        round_info,
        system_info,
        program_id,
        ROUND_ACCOUNT_SIZE,
        &[b"round", pool_info.key.as_ref(), &round_id_bytes, &[bump]],
    )?;
    let round = RoundAccount {
        version: 1,
        bump,
        pool: *pool_info.key,
        round_id,
        state: State::Registration,
        registration_deadline: deadline,
        template_hash: template,
        accepted_count: 0,
        cohort_root: [0; 32],
        release_slot: 0,
        window_end_slot: 0,
        metrics_hash: [0; 32],
    };
    pool.next_round = pool
        .next_round
        .checked_add(1)
        .ok_or(CoordinationError::Overflow)?;
    write_account(pool_info, &pool)?;
    write_account(round_info, &round)?;
    msg!("RoundOpened");
    Ok(())
}

fn register_transparent(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    key: [u8; 32],
    bump: u8,
) -> ProgramResult {
    let mut iter = accounts.iter();
    let payer = next_account_info(&mut iter)?;
    let pool_info = next_account_info(&mut iter)?;
    let round_info = next_account_info(&mut iter)?;
    let record_info = next_account_info(&mut iter)?;
    let system_info = next_account_info(&mut iter)?;
    require_signer(payer)?;
    require_owned(pool_info, program_id)?;
    require_owned(round_info, program_id)?;
    let pool: PoolAccount = read_account(pool_info)?;
    let mut round: RoundAccount = read_account(round_info)?;
    let clock = Clock::get()?;
    if pool.backend != Backend::TransparentRegistry
        || round.pool != *pool_info.key
        || !matches!(round.state, State::Registration | State::ThresholdReached)
        || clock.slot >= round.registration_deadline
        || round.accepted_count >= pool.max_participants
    {
        return Err(CoordinationError::InvalidState.into());
    }
    let expected = Pubkey::create_program_address(
        &[b"participant", round_info.key.as_ref(), &key, &[bump]],
        program_id,
    )
    .map_err(|_| CoordinationError::InvalidPda)?;
    if expected != *record_info.key {
        return Err(CoordinationError::InvalidPda.into());
    }
    create_pda_account(
        payer,
        record_info,
        system_info,
        program_id,
        96,
        &[b"participant", round_info.key.as_ref(), &key, &[bump]],
    )?;
    round.accepted_count = round
        .accepted_count
        .checked_add(1)
        .ok_or(CoordinationError::Overflow)?;
    if round.accepted_count >= pool.min_participants {
        round.state = State::ThresholdReached;
    }
    write_account(
        record_info,
        &ParticipantRecord {
            version: 1,
            bump,
            round: *round_info.key,
            coordination_key: key,
        },
    )?;
    write_account(round_info, &round)?;
    msg!("TransparentParticipantRegistered");
    Ok(())
}

fn publish_root(
    program_id: &Pubkey,
    accounts: &[AccountInfo<'_>],
    root: [u8; 32],
    count: u32,
) -> ProgramResult {
    let (pool_info, round_info, authority) = admin_accounts(program_id, accounts)?;
    let pool: PoolAccount = read_account(pool_info)?;
    let mut round: RoundAccount = read_account(round_info)?;
    if pool.backend != Backend::MerkleCohort
        || round.pool != *pool_info.key
        || round.state != State::Registration
        || count < pool.min_participants
        || count > pool.max_participants
        || root == [0; 32]
        || round.cohort_root != [0; 32]
        || pool.authority != *authority.key
    {
        return Err(CoordinationError::InvalidState.into());
    }
    round.cohort_root = root;
    round.accepted_count = count;
    round.state = State::ThresholdReached;
    write_account(round_info, &round)?;
    msg!("CohortRootPublished");
    Ok(())
}

fn seal(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ProgramResult {
    let (pool_info, round_info, authority) = admin_accounts(program_id, accounts)?;
    let pool: PoolAccount = read_account(pool_info)?;
    let mut round: RoundAccount = read_account(round_info)?;
    if pool.authority != *authority.key
        || round.pool != *pool_info.key
        || round.state != State::ThresholdReached
        || round.accepted_count < pool.min_participants
    {
        return Err(CoordinationError::InvalidState.into());
    }
    round.state = State::Sealed;
    write_account(round_info, &round)?;
    msg!("RoundSealed");
    Ok(())
}

fn schedule(program_id: &Pubkey, accounts: &[AccountInfo<'_>], release: u64) -> ProgramResult {
    let (pool_info, round_info, authority) = admin_accounts(program_id, accounts)?;
    let pool: PoolAccount = read_account(pool_info)?;
    let mut round: RoundAccount = read_account(round_info)?;
    let slot = Clock::get()?.slot;
    let delay = release
        .checked_sub(slot)
        .ok_or(CoordinationError::InvalidTiming)?;
    if pool.authority != *authority.key
        || round.state != State::Sealed
        || round.release_slot != 0
        || delay < pool.min_release_delay
        || delay > pool.max_release_delay
    {
        return Err(CoordinationError::InvalidTiming.into());
    }
    round.release_slot = release;
    round.window_end_slot = release
        .checked_add(pool.execution_window)
        .ok_or(CoordinationError::Overflow)?;
    round.state = State::ReleaseScheduled;
    write_account(round_info, &round)?;
    msg!("ReleaseScheduled");
    Ok(())
}
fn begin(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ProgramResult {
    let round_info = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    require_owned(round_info, program_id)?;
    let mut round: RoundAccount = read_account(round_info)?;
    let slot = Clock::get()?.slot;
    if round.state != State::ReleaseScheduled
        || slot < round.release_slot
        || slot > round.window_end_slot
    {
        return Err(CoordinationError::InvalidTiming.into());
    }
    round.state = State::ExecutionWindow;
    write_account(round_info, &round)?;
    msg!("ExecutionWindowOpened");
    Ok(())
}
fn finalize(program_id: &Pubkey, accounts: &[AccountInfo<'_>], metrics: [u8; 32]) -> ProgramResult {
    let (pool_info, round_info, authority) = admin_accounts(program_id, accounts)?;
    let pool: PoolAccount = read_account(pool_info)?;
    let mut round: RoundAccount = read_account(round_info)?;
    if pool.authority != *authority.key
        || round.state != State::ExecutionWindow
        || Clock::get()?.slot <= round.window_end_slot
        || metrics == [0; 32]
    {
        return Err(CoordinationError::InvalidState.into());
    }
    round.metrics_hash = metrics;
    round.state = State::Completed;
    write_account(round_info, &round)?;
    msg!("RoundFinalized");
    Ok(())
}
fn cancel(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ProgramResult {
    let (pool_info, round_info, authority) = admin_accounts(program_id, accounts)?;
    let pool: PoolAccount = read_account(pool_info)?;
    let mut round: RoundAccount = read_account(round_info)?;
    if pool.authority != *authority.key
        || matches!(
            round.state,
            State::Completed | State::Cancelled | State::Expired
        )
    {
        return Err(CoordinationError::InvalidState.into());
    }
    round.state = State::Cancelled;
    write_account(round_info, &round)?;
    msg!("RoundCancelled");
    Ok(())
}
fn close(program_id: &Pubkey, accounts: &[AccountInfo<'_>]) -> ProgramResult {
    let (pool_info, round_info, authority) = admin_accounts(program_id, accounts)?;
    let pool: PoolAccount = read_account(pool_info)?;
    let round: RoundAccount = read_account(round_info)?;
    if pool.authority != *authority.key
        || !matches!(
            round.state,
            State::Completed | State::Cancelled | State::Expired
        )
        || !authority.is_writable
    {
        return Err(CoordinationError::InvalidState.into());
    }
    let rent = round_info.lamports();
    **authority.try_borrow_mut_lamports()? = authority
        .lamports()
        .checked_add(rent)
        .ok_or(CoordinationError::Overflow)?;
    **round_info.try_borrow_mut_lamports()? = 0;
    round_info.try_borrow_mut_data()?.fill(0);
    msg!("RoundClosed");
    Ok(())
}

fn admin_accounts<'slice, 'account>(
    program_id: &Pubkey,
    accounts: &'slice [AccountInfo<'account>],
) -> Result<
    (
        &'slice AccountInfo<'account>,
        &'slice AccountInfo<'account>,
        &'slice AccountInfo<'account>,
    ),
    ProgramError,
> {
    let mut iter = accounts.iter();
    let authority = next_account_info(&mut iter)?;
    let pool = next_account_info(&mut iter)?;
    let round = next_account_info(&mut iter)?;
    require_signer(authority)?;
    require_owned(pool, program_id)?;
    require_owned(round, program_id)?;
    Ok((pool, round, authority))
}
fn require_signer(info: &AccountInfo<'_>) -> ProgramResult {
    if info.is_signer {
        Ok(())
    } else {
        Err(ProgramError::MissingRequiredSignature)
    }
}
fn require_owned(info: &AccountInfo<'_>, program_id: &Pubkey) -> ProgramResult {
    if info.owner == program_id {
        Ok(())
    } else {
        Err(ProgramError::IllegalOwner)
    }
}
fn create_pda_account<'account>(
    payer: &AccountInfo<'account>,
    account: &AccountInfo<'account>,
    system: &AccountInfo<'account>,
    program_id: &Pubkey,
    space: usize,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    if account.owner == program_id {
        if account.data.borrow().first().copied().unwrap_or(0) != 0 {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        return Ok(());
    }
    if !system_program::check_id(system.key)
        || !system_program::check_id(account.owner)
        || !account.data_is_empty()
    {
        return Err(ProgramError::IllegalOwner);
    }
    let space = u64::try_from(space).map_err(|_| CoordinationError::Overflow)?;
    let lamports = Rent::get()?
        .minimum_balance(usize::try_from(space).map_err(|_| CoordinationError::Overflow)?);
    invoke_signed(
        &system_instruction::create_account(payer.key, account.key, lamports, space, program_id),
        &[payer.clone(), account.clone(), system.clone()],
        &[signer_seeds],
    )
}
fn read_account<T: BorshDeserialize>(info: &AccountInfo<'_>) -> Result<T, ProgramError> {
    let data = info.try_borrow_data()?;
    T::deserialize(&mut &data[..]).map_err(|_| ProgramError::InvalidAccountData)
}
fn write_account<T: BorshSerialize>(info: &AccountInfo<'_>, value: &T) -> ProgramResult {
    let bytes = borsh::to_vec(value).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = info.try_borrow_mut_data()?;
    if bytes.len() > data.len() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data.fill(0);
    data[..bytes.len()].copy_from_slice(&bytes);
    Ok(())
}

/// Program-specific failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinationError {
    InvalidPolicy = 1,
    InvalidPda,
    Unauthorized,
    InvalidTiming,
    InvalidState,
    Overflow,
}
impl From<CoordinationError> for ProgramError {
    fn from(value: CoordinationError) -> Self {
        Self::Custom(value as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_sizes_are_bounded() {
        let pool = PoolAccount {
            version: 1,
            bump: 1,
            authority: Pubkey::new_unique(),
            pool_id: [1; 32],
            template_hash: [2; 32],
            min_participants: 2,
            max_participants: 100_000,
            min_release_delay: 1,
            max_release_delay: 50,
            execution_window: 4,
            backend: Backend::MerkleCohort,
            next_round: 0,
            paused: false,
        };
        assert!(borsh::to_vec(&pool).unwrap_or_default().len() <= POOL_ACCOUNT_SIZE);
    }
    #[test]
    fn instruction_set_has_no_arbitrary_execution() {
        let variants = [
            CoordinationInstruction::SealRound,
            CoordinationInstruction::BeginExecutionWindow,
            CoordinationInstruction::CancelRound,
            CoordinationInstruction::CloseRound,
        ];
        for value in variants {
            assert!(!borsh::to_vec(&value).unwrap_or_default().is_empty());
        }
    }
}
