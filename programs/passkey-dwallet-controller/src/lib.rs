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

use ika_dwallet_pinocchio::{DWalletContext, CPI_AUTHORITY_SEED};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

entrypoint!(process_instruction);
pinocchio::nostd_panic_handler!();

// Deployed on Solana devnet: 3xYHGYP24wH75tB1U3tn2RoQHcgZLkjuWTT4snWbv9zv
pub const ID: Address = Address::new_from_array([
    43, 241, 175, 243, 63, 238, 86, 41, 119, 27, 213, 201, 61, 104, 176, 106,
    32, 6, 177, 60, 198, 181, 58, 7, 210, 52, 113, 162, 29, 36, 141, 7,
]);

// ── Discriminators ──
const CONTROLLER_DISCRIMINATOR: u8 = 1;
/// Controllers written by the old `init_controller` carry version 1 and were
/// created without the dWallet-authority and passkey-possession checks.
/// `request_sign` only accepts this version, so an in-place upgrade cannot
/// carry a controller made by the old code forward.
const CONTROLLER_VERSION: u8 = 2;

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

/// Ika dWallet program: `87W54kGYFQ1rgWqMeu4XTPHWXWmXSQCcjm8vCTfiq1oY`.
pub const IKA_DWALLET_PROGRAM_ID: Address = Address::new_from_array([
    105, 172, 41, 185, 50, 32, 159, 61, 21, 16, 154, 74, 112, 129, 218, 65,
    5, 104, 52, 48, 240, 90, 178, 50, 121, 140, 177, 1, 215, 36, 144, 91,
]);

/// System program: `11111111111111111111111111111111`.
const SYSTEM_PROGRAM_ID: Address = Address::new_from_array([0u8; 32]);

// ── Ika dWallet account layout (the fields this program reads) ──
const DWALLET_DISCRIMINATOR: u8 = 2;
const DWALLET_AUTHORITY: usize = 2; // 32 bytes
const DWALLET_MIN_LEN: usize = 34;

/// Domain tag on the message the passkey signs to register itself.
pub const INIT_DOMAIN: &[u8] = b"passkey-dwallet-controller:init";
/// `INIT_DOMAIN || owner(32) || dwallet(32)`.
pub const INIT_MESSAGE_LEN: usize = 31 + 32 + 32;
/// `message_digest(32) || user_pubkey(32) || signature_scheme(2 LE) || dwallet(32)`.
pub const SIGN_MESSAGE_LEN: usize = 32 + 32 + 2 + 32;

// SIMD-0048 layout constants
const SECP256R1_PUBKEY_LEN: usize = 33;
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
/// The owner must be the dWallet's current authority, and the passkey must
/// sign `INIT_DOMAIN || owner || dwallet` in a sibling secp256r1 ix. That
/// proves the key is a real P-256 point the registrant controls. Hand the
/// dWallet authority to this program's CPI authority only after this ix.
///
/// There is one controller per dWallet. While the dWallet's authority is
/// still a wallet, that authority can call this again to replace the
/// binding, so a controller left behind by an earlier owner never outlives a
/// change of hands. Once the authority is this program's CPI authority, no
/// signer matches it and the binding is fixed. A controller PDA that someone
/// pre-funded is still claimed (top up, allocate, assign) instead of failing
/// `CreateAccount`.
///
/// # Instruction Data
/// `[passkey_pubkey(33), bump(1), secp256r1_ix_index(1)]` = 35 bytes
///
/// # Accounts
/// 0. `[writable]`         Controller PDA (seeds: `["controller", dwallet]`)
/// 1. `[readonly]`         dWallet account (owned by the Ika dWallet program)
/// 2. `[signer]`           Owner (the dWallet's current authority)
/// 3. `[writable, signer]` Payer
/// 4. `[readonly]`         System program
/// 5. `[readonly]`         Sysvar instructions account
fn init_controller(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 35 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [controller_account, dwallet, owner, payer, system_program, sysvar_instructions, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer.is_signer() || !payer.is_writable() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if system_program.address().as_array() != SYSTEM_PROGRAM_ID.as_array() {
        return Err(ProgramError::IncorrectProgramId);
    }
    if sysvar_instructions.address().as_array() != INSTRUCTIONS_SYSVAR_ID.as_array() {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut passkey_pubkey = [0u8; 33];
    passkey_pubkey.copy_from_slice(&data[0..33]);
    let bump = data[33];
    let secp256r1_ix_index = data[34];

    // Compressed SEC1 point: the prefix is 0x02 or 0x03.
    if passkey_pubkey[0] != 2 && passkey_pubkey[0] != 3 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Controller must be the canonical PDA for this dWallet.
    let owner_key = owner.address().as_array();
    let dwallet_key = dwallet.address().as_array();
    let (expected_controller, canonical_bump) =
        Address::find_program_address(&[b"controller", dwallet_key.as_ref()], program_id);
    if controller_account.address().as_array() != expected_controller.as_array()
        || bump != canonical_bump
    {
        return Err(ProgramError::InvalidSeeds);
    }

    // dWallet must be a real Ika dWallet whose authority is the owner signing here.
    if !dwallet.owned_by(&IKA_DWALLET_PROGRAM_ID) {
        return Err(ProgramError::IllegalOwner);
    }
    {
        let dw = unsafe { dwallet.borrow_unchecked() };
        if dw.len() < DWALLET_MIN_LEN || dw[0] != DWALLET_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        if &dw[DWALLET_AUTHORITY..DWALLET_AUTHORITY + 32] != owner_key.as_ref() {
            return Err(ProgramError::IllegalOwner);
        }
    }

    // Proof of possession: the passkey signs this exact registration.
    let mut init_message = [0u8; INIT_MESSAGE_LEN];
    init_message[..31].copy_from_slice(INIT_DOMAIN);
    init_message[31..63].copy_from_slice(owner_key);
    init_message[63..95].copy_from_slice(dwallet.address().as_array());
    verify_secp256r1_sibling_ix(
        sysvar_instructions,
        secp256r1_ix_index,
        &passkey_pubkey,
        &init_message,
    )?;

    let bump_byte = [bump];
    let signer_seeds = [
        Seed::from(b"controller" as &[u8]),
        Seed::from(dwallet_key.as_ref()),
        Seed::from(bump_byte.as_ref()),
    ];
    let rent = minimum_balance(CONTROLLER_LEN);

    if controller_account.owned_by(program_id) {
        // Re-registration by the dWallet's current authority: overwrite.
        if controller_account.data_len() != CONTROLLER_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
    } else if !controller_account.owned_by(&SYSTEM_PROGRAM_ID)
        || controller_account.data_len() != 0
    {
        return Err(ProgramError::AccountAlreadyInitialized);
    } else if controller_account.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: controller_account,
            lamports: rent,
            space: CONTROLLER_LEN as u64,
            owner: program_id,
        }
        .invoke_signed(&[Signer::from(&signer_seeds)])?;
    } else {
        // Someone sent lamports to the PDA first; CreateAccount would fail.
        let have = controller_account.lamports();
        if have < rent {
            Transfer { from: payer, to: controller_account, lamports: rent - have }.invoke()?;
        }
        Allocate { account: controller_account, space: CONTROLLER_LEN as u64 }
            .invoke_signed(&[Signer::from(&signer_seeds)])?;
        Assign { account: controller_account, owner: program_id }
            .invoke_signed(&[Signer::from(&signer_seeds)])?;
    }

    let ctrl_data = unsafe { controller_account.borrow_unchecked_mut() };
    ctrl_data[0] = CONTROLLER_DISCRIMINATOR;
    ctrl_data[1] = CONTROLLER_VERSION;
    ctrl_data[CTRL_OWNER..CTRL_OWNER + 32].copy_from_slice(owner_key);
    ctrl_data[CTRL_PASSKEY_PUBKEY..CTRL_PASSKEY_PUBKEY + 33]
        .copy_from_slice(&passkey_pubkey);
    ctrl_data[CTRL_DWALLET..CTRL_DWALLET + 32].copy_from_slice(dwallet_key);
    ctrl_data[CTRL_BUMP] = bump;

    Ok(())
}

/// Approve a message digest for signing iff the sibling secp256r1 verify ix
/// attests the registered passkey signed
/// `message_digest || user_pubkey || signature_scheme || dwallet`.
///
/// The controller must be this program's canonical PDA for its stored dWallet,
/// and the dWallet must be the one it was registered with, so a controller
/// can only ever approve for its own dWallet.
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
    program_id: &Address,
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

    // Controller: owned by this program, right shape, and the canonical PDA
    // for the dWallet it stores.
    if !controller_account.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }
    let mut registered_passkey = [0u8; 33];
    let mut registered_dwallet = [0u8; 32];
    {
        let ctrl_data = unsafe { controller_account.borrow_unchecked() };
        if ctrl_data.len() < CONTROLLER_LEN
            || ctrl_data[0] != CONTROLLER_DISCRIMINATOR
            || ctrl_data[1] != CONTROLLER_VERSION
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let (expected_controller, _) = Address::find_program_address(
            &[b"controller", &ctrl_data[CTRL_DWALLET..CTRL_DWALLET + 32]],
            program_id,
        );
        if controller_account.address().as_array() != expected_controller.as_array() {
            return Err(ProgramError::InvalidSeeds);
        }
        registered_passkey
            .copy_from_slice(&ctrl_data[CTRL_PASSKEY_PUBKEY..CTRL_PASSKEY_PUBKEY + 33]);
        registered_dwallet.copy_from_slice(&ctrl_data[CTRL_DWALLET..CTRL_DWALLET + 32]);
    }

    // dWallet: the one this controller was registered with, owned by Ika.
    if dwallet.address().as_array() != &registered_dwallet {
        return Err(ProgramError::InvalidArgument);
    }
    if !dwallet.owned_by(&IKA_DWALLET_PROGRAM_ID) {
        return Err(ProgramError::IllegalOwner);
    }

    // Side accounts the CPI trusts.
    if dwallet_program.address().as_array() != IKA_DWALLET_PROGRAM_ID.as_array()
        || caller_program.address().as_array() != program_id.as_array()
        || system_program.address().as_array() != SYSTEM_PROGRAM_ID.as_array()
    {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (expected_cpi_authority, canonical_cpi_bump) =
        Address::find_program_address(&[CPI_AUTHORITY_SEED], program_id);
    if cpi_authority.address().as_array() != expected_cpi_authority.as_array()
        || cpi_authority_bump != canonical_cpi_bump
    {
        return Err(ProgramError::InvalidSeeds);
    }
    if sysvar_instructions.address().as_array() != INSTRUCTIONS_SYSVAR_ID.as_array() {
        return Err(ProgramError::InvalidAccountData);
    }

    // The passkey signs everything the CPI forwards, not just the digest.
    let mut signed_message = [0u8; SIGN_MESSAGE_LEN];
    signed_message[..32].copy_from_slice(&message_digest);
    signed_message[32..64].copy_from_slice(&user_pubkey);
    signed_message[64..66].copy_from_slice(&signature_scheme.to_le_bytes());
    signed_message[66..98].copy_from_slice(&registered_dwallet);
    verify_secp256r1_sibling_ix(
        sysvar_instructions,
        secp256r1_ix_index,
        &registered_passkey,
        &signed_message,
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
///   5. the signed message equals `expected_message`, byte for byte.
///
/// Returns `Ok(())` only if all five hold; the precompile's own success is
/// implicit (the Solana runtime aborts the tx if the signature itself is bad).
fn verify_secp256r1_sibling_ix(
    sysvar_account: &AccountView,
    target_ix_index: u8,
    expected_pubkey: &[u8; SECP256R1_PUBKEY_LEN],
    expected_message: &[u8],
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

    // Message must be exactly the expected bytes.
    if msg_size != expected_message.len() || msg_offset + msg_size > ix_data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if &ix_data[msg_offset..msg_offset + msg_size] != expected_message {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}
