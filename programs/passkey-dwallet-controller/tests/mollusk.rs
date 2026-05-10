// Copyright (c) Seedless Labs.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk SVM tests for PasskeyDWalletController.
//!
//! Coverage targets (build-phase, sat):
//! - init_controller: happy path, missing signer, double init reject
//! - request_sign: happy path with valid secp256r1 sibling ix,
//!   reject on missing sibling ix, wrong pubkey, wrong digest

use mollusk_svm::Mollusk;
use solana_pubkey::Pubkey;

#[test]
fn init_controller_happy_path() {
    let program_id = Pubkey::new_from_array([7u8; 32]);
    let _mollusk = Mollusk::new(&program_id, "passkey_dwallet_controller");

    // TODO(build-phase): build init_controller ix, supply Controller PDA
    // (seeds = ["controller", owner]), dWallet account (mocked), owner +
    // payer keypairs. Assert account discriminator + passkey_pubkey +
    // dwallet fields are written correctly.
}

#[test]
fn request_sign_rejects_without_secp256r1_sibling() {
    // TODO(build-phase): construct a tx with only the request_sign ix
    // (no secp256r1 verify ix). Assert ProgramError::InvalidArgument or
    // similar — the controller must refuse to CPI-approve without the
    // attested sibling ix.
}

#[test]
fn request_sign_rejects_pubkey_mismatch() {
    // TODO(build-phase): include a valid secp256r1 verify ix for a
    // *different* P-256 pubkey than the registered passkey. Assert
    // controller rejects.
}

#[test]
fn request_sign_rejects_digest_mismatch() {
    // TODO(build-phase): secp256r1 verify ix attests a different digest
    // than the request_sign ix data carries. Assert reject.
}

#[test]
fn request_sign_happy_path_cpi_approves() {
    // TODO(build-phase): full happy path with mocked Ika program returning
    // success on approve_message CPI. Assert MessageApproval PDA created
    // with expected seeds.
}
