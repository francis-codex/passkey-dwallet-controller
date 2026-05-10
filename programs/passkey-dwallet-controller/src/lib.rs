// Copyright (c) Seedless Labs.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! PasskeyDWalletController — passkey-gated Ika dWallet message approval.
//!
//! Bridges WebAuthn / passkey UX (LazorKit-style) with Ika MPC dWallets on
//! Solana. The dWallet's authority is transferred (via the standard Ika flow)
//! to this program's CPI authority PDA. Subsequent signing requests must
//! present a P-256 (secp256r1) signature from a registered passkey over the
//! message digest, verified via Solana's `Secp256r1SigVerify` native
//! precompile in a sibling instruction inside the same transaction.
//!
//! # Instructions
//!
//! - `0` — **InitController**: register a passkey pubkey + dWallet binding.
//! - `1` — **RequestSign**: verify the sibling secp256r1 ix attests the
//!   registered passkey signed the digest, then CPI-approve the message
//!   on the Ika dWallet program.

#![no_std]
#![allow(clippy::arithmetic_side_effects)]

extern crate alloc;

use ika_dwallet_pinocchio::DWalletContext;
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

entrypoint!(process_instruction);
pinocchio::nostd_panic_handler!();

// Deployed on Solana devnet: 3xYHGYP24wH75tB1U3tn2RoQHcgZLkjuWTT4snWbv9zv
pub const ID: Address = Address::new_from_array([
    43, 241, 175, 243, 63, 238, 86, 41, 119, 27, 213, 201, 61, 104, 176, 106,
    32, 6, 177, 60, 198, 181, 58, 7, 210, 52, 113, 162, 29, 36, 141, 7,
]);

// ── Discriminators ──
const CONTROLLER_DISCRIMINATOR: u8 = 1;

// ── Account sizes ──
const CONTROLLER_DATA_LEN: usize = 114;
const CONTROLLER_LEN: usize = 2 + CONTROLLER_DATA_LEN; // 116

// ── Offsets into Controller data ──
const CTRL_OWNER: usize = 2;
const CTRL_PASSKEY_PUBKEY: usize = 34; // 33 bytes (compressed P-256)
const CTRL_DWALLET: usize = 67;
const CTRL_BUMP: usize = 99;

/// Solana secp256r1 native precompile — `Secp256r1SigVerify1111111111111111111111111`.
pub const SECP256R1_PROGRAM_ID: Address = Address::new_from_array([
    6, 146, 13, 236, 47, 234, 113, 181, 183, 35, 129, 77, 116, 45, 169, 3,
    28, 131, 231, 95, 219, 121, 93, 86, 142, 117, 71, 128, 32, 0, 0, 0,
]);

/// Sysvar Instructions account — `Sysvar1nstructions1111111111111111111111111`.
pub const INSTRUCTIONS_SYSVAR_ID: Address = Address::new_from_array([
    6, 167, 213, 23, 24, 123, 209, 102, 53, 218, 212, 4, 85, 253, 194, 192,
    193, 36, 198, 143, 33, 86, 117, 165, 219, 186, 203, 95, 8, 0, 0, 0,
]);

// SIMD-0048 layout constants
const SECP256R1_PUBKEY_LEN: usize = 33;
const SECP256R1_DIGEST_LEN: usize = 32;
/// Inside SignatureOffsets, this means "blob is in the same ix's own data".
const CURRENT_IX_SENTINEL: u16 = u16::MAX;

#[inline(always)]
fn minimum_balance(data_len: usize) -> u64 {
    (data_len as u64 + 128) * 6960
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let (discriminator, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        0 => init_controller(program_id, accounts, rest),
        1 => request_sign(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Register a passkey pubkey + dWallet binding for an owner.
///
/// # Instruction Data
/// `[passkey_pubkey(33), bump(1)]` = 34 bytes
///
/// # Accounts
/// 0. `[writable]`         Controller PDA (seeds: `["controller", owner]`)
/// 1. `[readonly]`         dWallet account
/// 2. `[signer]`           Owner
/// 3. `[writable, signer]` Payer
/// 4. `[readonly]`         System program
fn init_controller(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 34 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [controller_account, dwallet, owner, payer, _system_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer.is_signer() || !payer.is_writable() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut passkey_pubkey = [0u8; 33];
    passkey_pubkey.copy_from_slice(&data[0..33]);
    let bump = data[33];

    let bump_byte = [bump];
    let owner_key = owner.address().as_array();
    let signer_seeds = [
        Seed::from(b"controller" as &[u8]),
        Seed::from(owner_key.as_ref()),
        Seed::from(bump_byte.as_ref()),
    ];
    let signer = Signer::from(&signer_seeds);

    CreateAccount {
        from: payer,
        to: controller_account,
        lamports: minimum_balance(CONTROLLER_LEN),
        space: CONTROLLER_LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&[signer])?;

    let ctrl_data = unsafe { controller_account.borrow_unchecked_mut() };
    ctrl_data[0] = CONTROLLER_DISCRIMINATOR;
    ctrl_data[1] = 1; // version
    ctrl_data[CTRL_OWNER..CTRL_OWNER + 32].copy_from_slice(owner_key);
    ctrl_data[CTRL_PASSKEY_PUBKEY..CTRL_PASSKEY_PUBKEY + 33]
        .copy_from_slice(&passkey_pubkey);
    ctrl_data[CTRL_DWALLET..CTRL_DWALLET + 32]
        .copy_from_slice(dwallet.address().as_array());
    ctrl_data[CTRL_BUMP] = bump;

    Ok(())
}

/// Approve a message digest for signing iff the sibling secp256r1 verify ix
/// attests the registered passkey signed it.
///
/// # Instruction Data
/// `[message_digest(32), user_pubkey(32), signature_scheme(2),
///   message_approval_bump(1), cpi_authority_bump(1),
///   secp256r1_ix_index(1)]` = 69 bytes
///
/// # Accounts
/// 0. `[readonly]`         Controller PDA
/// 1. `[readonly]`         Sysvar instructions account
/// 2. `[readonly]`         DWalletCoordinator PDA
/// 3. `[writable]`         MessageApproval PDA (created via CPI)
/// 4. `[readonly]`         dWallet account
/// 5. `[writable, signer]` Payer
/// 6. `[readonly]`         System program
/// 7. `[readonly]`         This program account (caller_program for CPI)
/// 8. `[readonly]`         CPI authority PDA
/// 9. `[readonly]`         dWallet program
fn request_sign(
    _program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 69 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if accounts.len() < 10 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let controller_account     = &accounts[0];
    let sysvar_instructions    = &accounts[1];
    let coordinator            = &accounts[2];
    let message_approval       = &accounts[3];
    let dwallet                = &accounts[4];
    let payer                  = &accounts[5];
    let system_program         = &accounts[6];
    let caller_program         = &accounts[7];
    let cpi_authority          = &accounts[8];
    let dwallet_program        = &accounts[9];

    let mut message_digest = [0u8; 32];
    message_digest.copy_from_slice(&data[0..32]);
    let mut user_pubkey = [0u8; 32];
    user_pubkey.copy_from_slice(&data[32..64]);
    let signature_scheme = u16::from_le_bytes(
        data[64..66]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    let message_approval_bump = data[66];
    let cpi_authority_bump = data[67];
    let secp256r1_ix_index = data[68];

    // Verify controller integrity and read the registered passkey.
    let ctrl_data = unsafe { controller_account.borrow_unchecked() };
    if ctrl_data.len() < CONTROLLER_LEN || ctrl_data[0] != CONTROLLER_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut registered_passkey = [0u8; 33];
    registered_passkey
        .copy_from_slice(&ctrl_data[CTRL_PASSKEY_PUBKEY..CTRL_PASSKEY_PUBKEY + 33]);

    // Verify sibling secp256r1 ix attests the registered passkey signed `message_digest`.
    if sysvar_instructions.address().as_array() != INSTRUCTIONS_SYSVAR_ID.as_array() {
        return Err(ProgramError::InvalidAccountData);
    }
    verify_secp256r1_sibling_ix(
        sysvar_instructions,
        secp256r1_ix_index,
        &registered_passkey,
        &message_digest,
    )?;

    // CPI-approve the message on the Ika dWallet program.
    let ctx = DWalletContext {
        dwallet_program,
        cpi_authority,
        caller_program,
        cpi_authority_bump,
    };

    let message_metadata_digest = [0u8; 32];
    ctx.approve_message(
        coordinator,
        message_approval,
        dwallet,
        payer,
        system_program,
        message_digest,
        message_metadata_digest,
        user_pubkey,
        signature_scheme,
        message_approval_bump,
    )?;

    Ok(())
}

/// Verify the secp256r1 native precompile ix at `target_ix_index` attests:
///   1. the verifying program is `SECP256R1_PROGRAM_ID`,
///   2. exactly one signature is verified,
///   3. all blobs are in the secp256r1 ix's own data (not a different ix),
///   4. the signed pubkey equals `expected_pubkey` (registered passkey),
///   5. the signed message equals `expected_digest`.
///
/// Returns `Ok(())` only if all five hold; the precompile's own success is
/// implicit (the Solana runtime aborts the tx if the signature itself is bad).
fn verify_secp256r1_sibling_ix(
    sysvar_account: &AccountView,
    target_ix_index: u8,
    expected_pubkey: &[u8; SECP256R1_PUBKEY_LEN],
    expected_digest: &[u8; SECP256R1_DIGEST_LEN],
) -> ProgramResult {
    let sysvar = unsafe { sysvar_account.borrow_unchecked() };

    // Sysvar Instructions layout:
    //   num_ixs(u16) | ix_offsets[u16; num_ixs] | <serialized ixs> | current_ix(u16)
    if sysvar.len() < 4 {
        return Err(ProgramError::InvalidAccountData);
    }
    let num_ixs = u16::from_le_bytes([sysvar[0], sysvar[1]]) as usize;
    let target = target_ix_index as usize;
    if target >= num_ixs {
        return Err(ProgramError::InvalidArgument);
    }

    let offset_pos = 2 + target * 2;
    if sysvar.len() < offset_pos + 2 {
        return Err(ProgramError::InvalidAccountData);
    }
    let ix_offset = u16::from_le_bytes([sysvar[offset_pos], sysvar[offset_pos + 1]]) as usize;
    if sysvar.len() < ix_offset + 2 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Serialized ix layout:
    //   num_accounts(u16) | accounts[u8 meta + [u8; 32] pubkey; num_accounts]
    //   | program_id([u8; 32]) | data_len(u16) | data
    let num_accounts = u16::from_le_bytes([sysvar[ix_offset], sysvar[ix_offset + 1]]) as usize;
    let accounts_size = num_accounts * 33;
    let prog_id_pos = ix_offset + 2 + accounts_size;
    if sysvar.len() < prog_id_pos + 32 + 2 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify program id is the secp256r1 native precompile.
    if &sysvar[prog_id_pos..prog_id_pos + 32] != SECP256R1_PROGRAM_ID.as_array() {
        return Err(ProgramError::InvalidArgument);
    }

    // Read ix data length + slice.
    let data_len_pos = prog_id_pos + 32;
    let data_len = u16::from_le_bytes([sysvar[data_len_pos], sysvar[data_len_pos + 1]]) as usize;
    let data_start = data_len_pos + 2;
    if sysvar.len() < data_start + data_len {
        return Err(ProgramError::InvalidAccountData);
    }
    let ix_data = &sysvar[data_start..data_start + data_len];

    // SIMD-0048 secp256r1 ix data:
    //   num_sigs(u8) | padding(u8) | SignatureOffsets(14 per sig) | <blobs>
    if ix_data.len() < 16 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if ix_data[0] != 1 {
        return Err(ProgramError::InvalidArgument);
    }

    // SignatureOffsets at bytes 2..16 (all little-endian u16):
    //   sig_offset | sig_ix_idx | pk_offset | pk_ix_idx |
    //   msg_offset | msg_size   | msg_ix_idx
    let off = 2;
    let sig_ix_idx = u16::from_le_bytes([ix_data[off + 2], ix_data[off + 3]]);
    let pk_offset = u16::from_le_bytes([ix_data[off + 4], ix_data[off + 5]]) as usize;
    let pk_ix_idx = u16::from_le_bytes([ix_data[off + 6], ix_data[off + 7]]);
    let msg_offset = u16::from_le_bytes([ix_data[off + 8], ix_data[off + 9]]) as usize;
    let msg_size = u16::from_le_bytes([ix_data[off + 10], ix_data[off + 11]]) as usize;
    let msg_ix_idx = u16::from_le_bytes([ix_data[off + 12], ix_data[off + 13]]);

    // All three blobs must live in the secp256r1 ix's own data.
    let self_idx = target_ix_index as u16;
    let in_self = |idx: u16| idx == CURRENT_IX_SENTINEL || idx == self_idx;
    if !in_self(sig_ix_idx) || !in_self(pk_ix_idx) || !in_self(msg_ix_idx) {
        return Err(ProgramError::InvalidArgument);
    }

    // Pubkey must match the registered passkey.
    if pk_offset + SECP256R1_PUBKEY_LEN > ix_data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if &ix_data[pk_offset..pk_offset + SECP256R1_PUBKEY_LEN] != expected_pubkey {
        return Err(ProgramError::InvalidArgument);
    }

    // Message must be the digest exactly (32 bytes).
    if msg_size != SECP256R1_DIGEST_LEN || msg_offset + SECP256R1_DIGEST_LEN > ix_data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if &ix_data[msg_offset..msg_offset + SECP256R1_DIGEST_LEN] != expected_digest {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}
