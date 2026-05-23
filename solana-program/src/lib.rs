//! rmem-solana-registry — Solana mirror of RmemMemoryRegistry.sol.
//!
//! Implements the ERC-8264 memory rights interface and the ERC-8265-shape body
//! lease, with the explicit `revoked_at` field that closes the Eq. allow-revoke
//! gap in the v0.3.4 spec audit.
//!
//! Solana's account model differs from EVM storage maps: there are no nested
//! mappings, only individual accounts addressed by Program-Derived Addresses
//! (PDAs). The state layout below mirrors the EVM contract semantically by
//! deriving one PDA per logical mapping entry:
//!
//!   memory record:  PDA seeds = ["mem",   subject_pubkey, record_id]
//!   lease state:    PDA seeds = ["lease", subject_pubkey, body_pubkey]
//!
//! Authorization is the spec's Allow_8264 predicate decomposed as:
//!   1. signer == subject  →  always allow
//!   2. otherwise the (subject, signer) lease must exist, AND
//!      revoked_at == 0           (¬Revoked — independent conjunct, Eq. allow-revoke)
//!      AND clock.unix_timestamp < expires_at   (WithinTime, Eq. allow-time)
//!      AND scopes & required_scope == required_scope   (Scope, Eq. allow-scope)
//!
//! Scope bitmap matches the EVM contract:
//!   READ=1  WRITE=2  DELETE=4  EXPORT=8

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

// ---------- scope bitmap ----------
pub const SCOPE_READ:   u8 = 1;
pub const SCOPE_WRITE:  u8 = 2;
pub const SCOPE_DELETE: u8 = 4;
pub const SCOPE_EXPORT: u8 = 8;

// ---------- account discriminators ----------
const DISCRIMINATOR_MEMORY: u8 = 1;
const DISCRIMINATOR_LEASE:  u8 = 2;

// ---------- state types ----------
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct MemoryRecord {
    pub discriminator: u8,    // = DISCRIMINATOR_MEMORY
    pub commitment:    [u8; 32], // keccak/sha256 commitment over the off-chain payload
}
impl MemoryRecord { pub const SIZE: usize = 1 + 32; }

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct Lease {
    pub discriminator: u8,    // = DISCRIMINATOR_LEASE
    pub scopes:        u8,    // scope bitmap
    pub expires_at:    i64,   // unix seconds; lease invalid when clock.now >= expires_at
    pub revoked_at:    i64,   // unix seconds of revocation; 0 means never revoked
}
impl Lease { pub const SIZE: usize = 1 + 1 + 8 + 8; }

// ---------- instruction types ----------
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum RmemInstruction {
    /// Write or update a memory commitment for `subject` at `record_id`.
    /// Accounts: [signer, subject, record_pda, system_program, optional: lease_pda]
    WriteMemory   { record_id: [u8; 32], commitment: [u8; 32] },

    /// Delete a memory commitment.
    /// Accounts: [signer, subject, record_pda, optional: lease_pda]
    DeleteMemory  { record_id: [u8; 32] },

    /// Subject grants `body` a scoped, time-bounded lease.
    /// Resets any prior revocation. Accounts: [subject_signer, body, lease_pda, system_program]
    GrantLease    { body: Pubkey, scopes: u8, expires_at: i64 },

    /// Subject revokes `body`'s lease. Sets revoked_at = clock.now explicitly.
    /// Accounts: [subject_signer, body, lease_pda]
    RevokeLease   { body: Pubkey },
}

// ---------- entrypoint ----------
entrypoint!(process);
pub fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ix = RmemInstruction::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    match ix {
        RmemInstruction::WriteMemory  { record_id, commitment } =>
            write_memory(program_id, accounts, record_id, commitment),
        RmemInstruction::DeleteMemory { record_id } =>
            delete_memory(program_id, accounts, record_id),
        RmemInstruction::GrantLease   { body, scopes, expires_at } =>
            grant_lease(program_id, accounts, body, scopes, expires_at),
        RmemInstruction::RevokeLease  { body } =>
            revoke_lease(program_id, accounts, body),
    }
}

// ---------- authorization helper ----------
//
// Implements Allow_8264 with ¬Revoked as a separate conjunct from WithinTime.
// The order of checks below is for early-exit only; spec-wise both predicates
// must independently hold.
fn authorize(
    program_id: &Pubkey, signer: &Pubkey, subject: &Pubkey,
    lease_account: Option<&AccountInfo>, required_scope: u8,
) -> ProgramResult {
    if signer == subject { return Ok(()); }

    let lease_account = lease_account.ok_or(ProgramError::MissingRequiredSignature)?;

    // verify the lease PDA is the canonical (subject, signer) lease
    let (expected_pda, _bump) = Pubkey::find_program_address(
        &[b"lease", subject.as_ref(), signer.as_ref()], program_id,
    );
    if lease_account.key != &expected_pda {
        msg!("lease PDA mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    if lease_account.data_is_empty() {
        msg!("no lease account");
        return Err(ProgramError::UninitializedAccount);
    }

    let lease = Lease::try_from_slice(&lease_account.data.borrow())?;
    if lease.discriminator != DISCRIMINATOR_LEASE {
        return Err(ProgramError::InvalidAccountData);
    }

    let now = Clock::get()?.unix_timestamp;

    // Eq. allow-revoke (¬Revoked) — INDEPENDENT conjunct from WithinTime
    if lease.revoked_at != 0 {
        msg!("lease revoked at {}", lease.revoked_at);
        return Err(ProgramError::Custom(101));
    }
    // Eq. allow-time (WithinTime)
    if now >= lease.expires_at {
        msg!("lease expired at {} (now {})", lease.expires_at, now);
        return Err(ProgramError::Custom(102));
    }
    // Eq. allow-scope
    if (lease.scopes & required_scope) != required_scope {
        msg!("scope check failed: have {} need {}", lease.scopes, required_scope);
        return Err(ProgramError::Custom(103));
    }
    Ok(())
}

// ---------- write_memory ----------
fn write_memory(
    program_id: &Pubkey, accounts: &[AccountInfo],
    record_id: [u8; 32], commitment: [u8; 32],
) -> ProgramResult {
    let it = &mut accounts.iter();
    let signer        = next_account_info(it)?;
    let subject       = next_account_info(it)?;
    let record_pda    = next_account_info(it)?;
    let system_prog   = next_account_info(it)?;
    let lease_account = it.next();

    if !signer.is_signer { return Err(ProgramError::MissingRequiredSignature); }

    authorize(program_id, signer.key, subject.key, lease_account, SCOPE_WRITE)?;

    let (expected_pda, bump) = Pubkey::find_program_address(
        &[b"mem", subject.key.as_ref(), &record_id], program_id,
    );
    if record_pda.key != &expected_pda {
        return Err(ProgramError::InvalidArgument);
    }

    let rec = MemoryRecord { discriminator: DISCRIMINATOR_MEMORY, commitment };

    if record_pda.data_is_empty() {
        // create new account
        let rent = Rent::get()?.minimum_balance(MemoryRecord::SIZE);
        invoke_signed(
            &system_instruction::create_account(
                signer.key, record_pda.key, rent, MemoryRecord::SIZE as u64, program_id,
            ),
            &[signer.clone(), record_pda.clone(), system_prog.clone()],
            &[&[b"mem", subject.key.as_ref(), &record_id, &[bump]]],
        )?;
    }
    rec.serialize(&mut *record_pda.data.borrow_mut())?;
    msg!("write_memory: subject={} record_id={:?}", subject.key, &record_id[..8]);
    Ok(())
}

// ---------- delete_memory ----------
fn delete_memory(
    program_id: &Pubkey, accounts: &[AccountInfo], record_id: [u8; 32],
) -> ProgramResult {
    let it = &mut accounts.iter();
    let signer        = next_account_info(it)?;
    let subject       = next_account_info(it)?;
    let record_pda    = next_account_info(it)?;
    let lease_account = it.next();

    if !signer.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    authorize(program_id, signer.key, subject.key, lease_account, SCOPE_DELETE)?;

    let (expected_pda, _) = Pubkey::find_program_address(
        &[b"mem", subject.key.as_ref(), &record_id], program_id,
    );
    if record_pda.key != &expected_pda { return Err(ProgramError::InvalidArgument); }
    if record_pda.data_is_empty() { return Err(ProgramError::UninitializedAccount); }

    // refund lamports to the signer and zero data
    let lamports = record_pda.lamports();
    **record_pda.lamports.borrow_mut() = 0;
    **signer.lamports.borrow_mut() += lamports;
    record_pda.data.borrow_mut().fill(0);
    msg!("delete_memory: subject={} record_id={:?}", subject.key, &record_id[..8]);
    Ok(())
}

// ---------- grant_lease ----------
fn grant_lease(
    program_id: &Pubkey, accounts: &[AccountInfo],
    body: Pubkey, scopes: u8, expires_at: i64,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let subject_signer = next_account_info(it)?;
    let _body_account  = next_account_info(it)?;  // not required to sign
    let lease_pda      = next_account_info(it)?;
    let system_prog    = next_account_info(it)?;

    if !subject_signer.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    if scopes == 0 { return Err(ProgramError::InvalidInstructionData); }
    let now = Clock::get()?.unix_timestamp;
    if expires_at <= now { return Err(ProgramError::InvalidInstructionData); }

    let (expected_pda, bump) = Pubkey::find_program_address(
        &[b"lease", subject_signer.key.as_ref(), body.as_ref()], program_id,
    );
    if lease_pda.key != &expected_pda { return Err(ProgramError::InvalidArgument); }

    let lease = Lease {
        discriminator: DISCRIMINATOR_LEASE,
        scopes, expires_at,
        revoked_at: 0,   // grant_lease clears any prior revocation
    };

    if lease_pda.data_is_empty() {
        let rent = Rent::get()?.minimum_balance(Lease::SIZE);
        invoke_signed(
            &system_instruction::create_account(
                subject_signer.key, lease_pda.key, rent, Lease::SIZE as u64, program_id,
            ),
            &[subject_signer.clone(), lease_pda.clone(), system_prog.clone()],
            &[&[b"lease", subject_signer.key.as_ref(), body.as_ref(), &[bump]]],
        )?;
    }
    lease.serialize(&mut *lease_pda.data.borrow_mut())?;
    msg!("grant_lease: subject={} body={} scopes={} expires_at={}",
        subject_signer.key, body, scopes, expires_at);
    Ok(())
}

// ---------- revoke_lease ----------
//
// Sets revoked_at = clock.now explicitly. This is the ¬Revoked conjunct of
// Eq. allow-revoke as a state field, distinct from expires_at — a body holding
// a still-time-valid lease will be rejected by authorize() on the next call.
fn revoke_lease(
    program_id: &Pubkey, accounts: &[AccountInfo], body: Pubkey,
) -> ProgramResult {
    let it = &mut accounts.iter();
    let subject_signer = next_account_info(it)?;
    let _body_account  = next_account_info(it)?;
    let lease_pda      = next_account_info(it)?;

    if !subject_signer.is_signer { return Err(ProgramError::MissingRequiredSignature); }

    let (expected_pda, _bump) = Pubkey::find_program_address(
        &[b"lease", subject_signer.key.as_ref(), body.as_ref()], program_id,
    );
    if lease_pda.key != &expected_pda { return Err(ProgramError::InvalidArgument); }
    if lease_pda.data_is_empty() { return Err(ProgramError::UninitializedAccount); }

    let mut lease = Lease::try_from_slice(&lease_pda.data.borrow())?;
    if lease.discriminator != DISCRIMINATOR_LEASE {
        return Err(ProgramError::InvalidAccountData);
    }
    lease.revoked_at = Clock::get()?.unix_timestamp;
    lease.serialize(&mut *lease_pda.data.borrow_mut())?;
    msg!("revoke_lease: subject={} body={} revoked_at={}",
        subject_signer.key, body, lease.revoked_at);
    Ok(())
}
