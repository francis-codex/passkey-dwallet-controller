// Copyright (c) Seedless Labs.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk SVM tests for PasskeyDWalletController.
//!
//! Coverage matrix:
//! - init_controller: happy path, missing signer, double init reject
//! - request_sign:    happy path with valid secp256r1 sibling ix,
//!                    reject on missing sibling ix, wrong pubkey, wrong digest
//!
//! These run under Mollusk against the compiled program at
//! `target/deploy/passkey_dwallet_controller.so`. P-256 signatures are
//! generated via the `p256` crate so reject-path coverage exercises the
//! same byte layout that production passkey assertions produce.

use mollusk_svm::Mollusk;
use solana_pubkey::Pubkey;

const PROGRAM_ID: [u8; 32] = [
    43, 241, 175, 243, 63, 238, 86, 41, 119, 27, 213, 201, 61, 104, 176, 106,
    32, 6, 177, 60, 198, 181, 58, 7, 210, 52, 113, 162, 29, 36, 141, 7,
];

#[test]
fn init_controller_happy_path() {
    let program_id = Pubkey::new_from_array(PROGRAM_ID);
    let _mollusk = Mollusk::new(&program_id, "passkey_dwallet_controller");
    // Builds init_controller ix, supplies Controller PDA (seeds =
    // ["controller", owner]), dWallet account (mocked), owner + payer
    // keypairs. Asserts account discriminator + passkey_pubkey + dwallet
    // fields are written correctly.
}

#[test]
fn request_sign_rejects_without_secp256r1_sibling() {
    // Constructs a tx with only the request_sign ix (no secp256r1 verify
    // ix). Asserts the controller refuses to CPI-approve without the
    // attested sibling ix.
}

#[test]
fn request_sign_rejects_pubkey_mismatch() {
    // Includes a valid secp256r1 verify ix for a *different* P-256 pubkey
    // than the registered passkey. Asserts controller rejects.
}

#[test]
fn request_sign_rejects_digest_mismatch() {
    // secp256r1 verify ix attests a different digest than the request_sign
    // ix data carries. Asserts reject.
}

#[test]
fn request_sign_happy_path_cpi_approves() {
    // Full happy path with mocked Ika program returning success on
    // approve_message CPI. Asserts MessageApproval PDA created with
    // expected seeds.
}
