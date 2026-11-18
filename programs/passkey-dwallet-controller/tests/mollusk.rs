// Copyright (c) Seedless Labs.
// SPDX-License-Identifier: BSD-3-Clause-Clear

//! Mollusk SVM tests for PasskeyDWalletController.
//!
//! They run against the compiled program at
//! `target/deploy/passkey_dwallet_controller.so`, so build it first:
//!
//!     cargo build-sbf --tools-version v1.54 --arch v0 \
//!         --manifest-path programs/passkey-dwallet-controller/Cargo.toml
//!     cargo test -p passkey-dwallet-controller
//!
//! Covered:
//! - init_controller: happy path writes the bound controller; rejects a
//!   missing owner signature, a bad passkey prefix, a non-PDA controller, a
//!   non-canonical bump, a dWallet not owned by Ika, a dWallet whose authority
//!   is not the owner, and a passkey proof over the wrong message.
//! - request_sign: rejects a controller not owned by this program, a
//!   controller that is not the canonical PDA, a dWallet other than the
//!   registered one, a registered dWallet not owned by Ika, a wrong Ika
//!   program, a wrong CPI authority, a missing sibling ix, another passkey,
//!   and a proof over another digest, pubkey, scheme or dWallet.
//!
//! Not covered: the secp256r1 precompile itself (Mollusk runs one instruction,
//! so the sibling ix is only parsed, not verified) and the Ika
//! `approve_message` CPI, which needs the Ika program binary.

use {
    mollusk_svm::{instructions_sysvar, program::keyed_account_for_system_program, Mollusk},
    passkey_dwallet_controller::{
        IKA_DWALLET_PROGRAM_ID, INIT_DOMAIN, INSTRUCTIONS_SYSVAR_ID, SECP256R1_PROGRAM_ID,
    },
    solana_account::Account,
    solana_instruction::{error::InstructionError, AccountMeta, Instruction},
    solana_pubkey::Pubkey,
};

const PROGRAM_ID: [u8; 32] = [
    43, 241, 175, 243, 63, 238, 86, 41, 119, 27, 213, 201, 61, 104, 176, 106, 32, 6, 177, 60, 198,
    181, 58, 7, 210, 52, 113, 162, 29, 36, 141, 7,
];
const CPI_AUTHORITY_SEED: &[u8] = b"__ika_cpi_authority";
const CONTROLLER_LEN: usize = 116;
const SCHEME: u16 = 1;

fn program_id() -> Pubkey {
    Pubkey::new_from_array(PROGRAM_ID)
}
fn ika() -> Pubkey {
    Pubkey::new_from_array(*IKA_DWALLET_PROGRAM_ID.as_array())
}
fn secp() -> Pubkey {
    Pubkey::new_from_array(*SECP256R1_PROGRAM_ID.as_array())
}
fn sysvar() -> Pubkey {
    Pubkey::new_from_array(*INSTRUCTIONS_SYSVAR_ID.as_array())
}

fn mollusk() -> Mollusk {
    if std::env::var_os("SBF_OUT_DIR").is_none() {
        std::env::set_var(
            "SBF_OUT_DIR",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy"),
        );
    }
    Mollusk::new(&program_id(), "passkey_dwallet_controller")
}

fn passkey(seed: u8) -> [u8; 33] {
    let mut pk = [seed; 33];
    pk[0] = 0x02;
    pk
}

/// A secp256r1 precompile instruction carrying `pubkey` and `message` inline.
fn secp_ix(pubkey: &[u8; 33], message: &[u8]) -> Instruction {
    let (sig_off, pk_off, msg_off) = (16u16, 80u16, 113u16);
    let mut data = vec![1u8, 0];
    for v in [
        sig_off,
        u16::MAX,
        pk_off,
        u16::MAX,
        msg_off,
        message.len() as u16,
        u16::MAX,
    ] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    data.extend_from_slice(&[7u8; 64]);
    data.extend_from_slice(pubkey);
    data.extend_from_slice(message);
    Instruction {
        program_id: secp(),
        accounts: vec![],
        data,
    }
}

fn sysvar_account(ixs: &[Instruction]) -> (Pubkey, Account) {
    let (_, account) = instructions_sysvar::keyed_account(ixs.iter());
    (sysvar(), account)
}

fn dwallet_account(authority: &Pubkey, owner: &Pubkey) -> Account {
    let mut data = vec![0u8; 64];
    data[0] = 2;
    data[2..34].copy_from_slice(authority.as_ref());
    Account {
        lamports: 1_000_000,
        data,
        owner: *owner,
        ..Account::default()
    }
}

fn funded() -> Account {
    Account {
        lamports: 10_000_000_000,
        ..Account::default()
    }
}

// ── init_controller ──────────────────────────────────────────────────────

struct Init {
    owner: Pubkey,
    payer: Pubkey,
    dwallet: Pubkey,
    controller: Pubkey,
    bump: u8,
    passkey: [u8; 33],
    dwallet_account: Account,
    proof_message: Vec<u8>,
    owner_signs: bool,
    controller_state: Account,
}

impl Init {
    fn new() -> Self {
        let owner = Pubkey::new_unique();
        let dwallet = Pubkey::new_unique();
        let (controller, bump) =
            Pubkey::find_program_address(&[b"controller", dwallet.as_ref()], &program_id());
        let mut proof_message = INIT_DOMAIN.to_vec();
        proof_message.extend_from_slice(owner.as_ref());
        proof_message.extend_from_slice(dwallet.as_ref());
        Self {
            owner,
            payer: Pubkey::new_unique(),
            dwallet,
            controller,
            bump,
            passkey: passkey(9),
            dwallet_account: dwallet_account(&owner, &ika()),
            proof_message,
            owner_signs: true,
            controller_state: Account::default(),
        }
    }

    fn run(&self) -> mollusk_svm::result::InstructionResult {
        let mut data = vec![0u8];
        data.extend_from_slice(&self.passkey);
        data.push(self.bump);
        data.push(0); // secp256r1 ix index
        let (system_id, system_account) = keyed_account_for_system_program();
        let ix = Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new(self.controller, false),
                AccountMeta::new_readonly(self.dwallet, false),
                AccountMeta::new_readonly(self.owner, self.owner_signs),
                AccountMeta::new(self.payer, true),
                AccountMeta::new_readonly(system_id, false),
                AccountMeta::new_readonly(sysvar(), false),
            ],
            data,
        };
        let proof = secp_ix(&passkey(9), &self.proof_message);
        mollusk().process_instruction(
            &ix,
            &[
                (self.controller, self.controller_state.clone()),
                (self.dwallet, self.dwallet_account.clone()),
                (self.owner, funded()),
                (self.payer, funded()),
                (system_id, system_account),
                sysvar_account(&[proof, ix.clone()]),
            ],
        )
    }
}

#[test]
fn init_controller_happy_path() {
    let t = Init::new();
    let res = t.run();
    assert_eq!(res.raw_result, Ok(()));
    let ctrl = res.get_account(&t.controller).expect("controller");
    assert_eq!(ctrl.owner, program_id());
    assert_eq!(ctrl.data.len(), CONTROLLER_LEN);
    assert_eq!(ctrl.data[0], 1);
    assert_eq!(ctrl.data[1], 2);
    assert_eq!(&ctrl.data[2..34], t.owner.as_ref());
    assert_eq!(&ctrl.data[34..67], &t.passkey);
    assert_eq!(&ctrl.data[67..99], t.dwallet.as_ref());
    assert_eq!(ctrl.data[99], t.bump);
}

#[test]
fn init_claims_a_prefunded_controller_pda() {
    // byfor8 NEW-3: dust sent to the PDA first must not block registration.
    let mut t = Init::new();
    t.controller_state = Account {
        lamports: 1,
        ..Account::default()
    };
    let res = t.run();
    assert_eq!(res.raw_result, Ok(()));
    let ctrl = res.get_account(&t.controller).expect("controller");
    assert_eq!(ctrl.owner, program_id());
    assert_eq!(ctrl.data.len(), CONTROLLER_LEN);
    assert_eq!(&ctrl.data[67..99], t.dwallet.as_ref());
}

#[test]
fn init_lets_the_new_authority_replace_a_stale_controller() {
    // byfor8 NEW-2: the dWallet changed hands; the old owner's binding
    // (another passkey, another owner) is overwritten by the new authority.
    let mut t = Init::new();
    let old_owner = Pubkey::new_unique();
    let mut stale = vec![0u8; CONTROLLER_LEN];
    stale[0] = 1;
    stale[1] = 2;
    stale[2..34].copy_from_slice(old_owner.as_ref());
    stale[34..67].copy_from_slice(&passkey(3));
    stale[67..99].copy_from_slice(t.dwallet.as_ref());
    stale[99] = t.bump;
    t.controller_state = Account {
        lamports: 2_000_000,
        data: stale,
        owner: program_id(),
        ..Account::default()
    };
    let res = t.run();
    assert_eq!(res.raw_result, Ok(()));
    let ctrl = res.get_account(&t.controller).expect("controller");
    assert_eq!(&ctrl.data[2..34], t.owner.as_ref());
    assert_eq!(&ctrl.data[34..67], &t.passkey);
}

#[test]
fn init_rejects_an_account_owned_by_another_program() {
    let mut t = Init::new();
    t.controller_state = Account {
        lamports: 1,
        data: vec![0; 8],
        owner: Pubkey::new_unique(),
        ..Account::default()
    };
    assert_eq!(
        t.run().raw_result,
        Err(InstructionError::AccountAlreadyInitialized)
    );
}

#[test]
fn init_rejects_missing_owner_signature() {
    let mut t = Init::new();
    t.owner_signs = false;
    assert_eq!(
        t.run().raw_result,
        Err(InstructionError::MissingRequiredSignature)
    );
}

#[test]
fn init_rejects_bad_passkey_prefix() {
    let mut t = Init::new();
    t.passkey[0] = 0x04;
    assert_eq!(
        t.run().raw_result,
        Err(InstructionError::InvalidInstructionData)
    );
}

#[test]
fn init_rejects_non_pda_controller() {
    let mut t = Init::new();
    t.controller = Pubkey::new_unique();
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidSeeds));
}

#[test]
fn init_rejects_non_canonical_bump() {
    let mut t = Init::new();
    t.bump = t.bump.wrapping_sub(1);
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidSeeds));
}

#[test]
fn init_rejects_dwallet_not_owned_by_ika() {
    let mut t = Init::new();
    t.dwallet_account = dwallet_account(&t.owner, &Pubkey::new_unique());
    assert_eq!(t.run().raw_result, Err(InstructionError::IllegalOwner));
}

#[test]
fn init_rejects_dwallet_with_another_authority() {
    let mut t = Init::new();
    t.dwallet_account = dwallet_account(&Pubkey::new_unique(), &ika());
    assert_eq!(t.run().raw_result, Err(InstructionError::IllegalOwner));
}

#[test]
fn init_rejects_proof_over_another_dwallet() {
    let mut t = Init::new();
    let n = t.proof_message.len();
    t.proof_message[n - 1] ^= 1;
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidArgument));
}

// ── request_sign ─────────────────────────────────────────────────────────

struct Sign {
    owner: Pubkey,
    controller: Pubkey,
    controller_account: Account,
    registered_dwallet: Pubkey,
    dwallet: Pubkey,
    dwallet_account: Account,
    dwallet_program: Pubkey,
    cpi_authority: Pubkey,
    cpi_bump: u8,
    digest: [u8; 32],
    user_pubkey: [u8; 32],
    proof_pubkey: [u8; 33],
    proof_message: Vec<u8>,
    with_proof: bool,
}

fn controller_account(owner: &Pubkey, dwallet: &Pubkey, bump: u8, program: &Pubkey) -> Account {
    let mut data = vec![0u8; CONTROLLER_LEN];
    data[0] = 1;
    data[1] = 2;
    data[2..34].copy_from_slice(owner.as_ref());
    data[34..67].copy_from_slice(&passkey(9));
    data[67..99].copy_from_slice(dwallet.as_ref());
    data[99] = bump;
    Account {
        lamports: 2_000_000,
        data,
        owner: *program,
        ..Account::default()
    }
}

fn sign_message(
    digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    scheme: u16,
    dwallet: &Pubkey,
) -> Vec<u8> {
    let mut m = digest.to_vec();
    m.extend_from_slice(user_pubkey);
    m.extend_from_slice(&scheme.to_le_bytes());
    m.extend_from_slice(dwallet.as_ref());
    m
}

impl Sign {
    fn new() -> Self {
        let owner = Pubkey::new_unique();
        let dwallet = Pubkey::new_unique();
        let (controller, bump) =
            Pubkey::find_program_address(&[b"controller", dwallet.as_ref()], &program_id());
        let (cpi_authority, cpi_bump) =
            Pubkey::find_program_address(&[CPI_AUTHORITY_SEED], &program_id());
        let (digest, user_pubkey) = ([5u8; 32], [6u8; 32]);
        Self {
            owner,
            controller,
            controller_account: controller_account(&owner, &dwallet, bump, &program_id()),
            registered_dwallet: dwallet,
            dwallet,
            dwallet_account: dwallet_account(&owner, &ika()),
            dwallet_program: ika(),
            cpi_authority,
            cpi_bump,
            digest,
            user_pubkey,
            proof_pubkey: passkey(9),
            proof_message: sign_message(&digest, &user_pubkey, SCHEME, &dwallet),
            with_proof: true,
        }
    }

    fn run(&self) -> mollusk_svm::result::InstructionResult {
        let mut data = vec![1u8];
        data.extend_from_slice(&self.digest);
        data.extend_from_slice(&self.user_pubkey);
        data.extend_from_slice(&SCHEME.to_le_bytes());
        data.push(255); // message approval bump, consumed by Ika
        data.push(self.cpi_bump);
        data.push(0); // secp256r1 ix index
        let (system_id, system_account) = keyed_account_for_system_program();
        let (coordinator, approval, payer) = (
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        let ix = Instruction {
            program_id: program_id(),
            accounts: vec![
                AccountMeta::new_readonly(self.controller, false),
                AccountMeta::new_readonly(sysvar(), false),
                AccountMeta::new_readonly(coordinator, false),
                AccountMeta::new(approval, false),
                AccountMeta::new_readonly(self.dwallet, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(system_id, false),
                AccountMeta::new_readonly(program_id(), false),
                AccountMeta::new_readonly(self.cpi_authority, false),
                AccountMeta::new_readonly(self.dwallet_program, false),
            ],
            data,
        };
        let chain = if self.with_proof {
            vec![secp_ix(&self.proof_pubkey, &self.proof_message), ix.clone()]
        } else {
            vec![ix.clone()]
        };
        let mut accounts = vec![
            (self.controller, self.controller_account.clone()),
            sysvar_account(&chain),
            (coordinator, Account::default()),
            (approval, Account::default()),
            (self.dwallet, self.dwallet_account.clone()),
            (payer, funded()),
            (system_id, system_account),
            (self.cpi_authority, Account::default()),
        ];
        if self.dwallet_program != ika() {
            accounts.push((self.dwallet_program, Account::default()));
        } else {
            accounts.push((
                ika(),
                Account {
                    executable: true,
                    ..Account::default()
                },
            ));
        }
        mollusk().process_instruction(&ix, &accounts)
    }
}

#[test]
fn sign_rejects_controller_not_owned_by_program() {
    let mut t = Sign::new();
    t.controller_account.owner = Pubkey::new_unique();
    assert_eq!(t.run().raw_result, Err(InstructionError::IllegalOwner));
}

#[test]
fn sign_rejects_legacy_v1_controller() {
    // A controller written by the pre-fix init_controller has version 1 but is
    // otherwise byte-identical; it must not survive an in-place upgrade.
    let mut t = Sign::new();
    t.controller_account.data[1] = 1;
    assert_eq!(
        t.run().raw_result,
        Err(InstructionError::InvalidAccountData)
    );
}

#[test]
fn sign_rejects_controller_that_is_not_the_pda() {
    let mut t = Sign::new();
    t.controller = Pubkey::new_unique();
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidSeeds));
}

#[test]
fn sign_rejects_another_dwallet() {
    let mut t = Sign::new();
    t.dwallet = Pubkey::new_unique();
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidArgument));
}

#[test]
fn sign_rejects_registered_dwallet_not_owned_by_ika() {
    let mut t = Sign::new();
    t.dwallet_account.owner = Pubkey::new_unique();
    assert_eq!(t.run().raw_result, Err(InstructionError::IllegalOwner));
}

#[test]
fn sign_rejects_wrong_ika_program() {
    let mut t = Sign::new();
    t.dwallet_program = Pubkey::new_unique();
    assert_eq!(
        t.run().raw_result,
        Err(InstructionError::IncorrectProgramId)
    );
}

#[test]
fn sign_rejects_wrong_cpi_authority() {
    let mut t = Sign::new();
    t.cpi_authority = Pubkey::new_unique();
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidSeeds));
}

#[test]
fn sign_rejects_without_secp256r1_sibling() {
    let mut t = Sign::new();
    t.with_proof = false;
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidArgument));
}

#[test]
fn sign_rejects_another_passkey() {
    let mut t = Sign::new();
    t.proof_pubkey = passkey(10);
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidArgument));
}

#[test]
fn sign_rejects_proof_over_another_digest() {
    let mut t = Sign::new();
    t.proof_message = sign_message(&[8u8; 32], &t.user_pubkey, SCHEME, &t.registered_dwallet);
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidArgument));
}

#[test]
fn sign_rejects_proof_over_another_user_pubkey() {
    let mut t = Sign::new();
    t.proof_message = sign_message(&t.digest, &[8u8; 32], SCHEME, &t.registered_dwallet);
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidArgument));
}

#[test]
fn sign_rejects_proof_over_another_scheme() {
    let mut t = Sign::new();
    t.proof_message = sign_message(&t.digest, &t.user_pubkey, SCHEME + 1, &t.registered_dwallet);
    assert_eq!(t.run().raw_result, Err(InstructionError::InvalidArgument));
}

#[test]
fn sign_rejects_bare_digest_proof() {
    // The pre-fix layout: the passkey signs the digest alone.
    let mut t = Sign::new();
    t.proof_message = t.digest.to_vec();
    assert_eq!(
        t.run().raw_result,
        Err(InstructionError::InvalidInstructionData)
    );
}

#[test]
fn sign_with_valid_binding_reaches_the_ika_cpi() {
    // Every check passes, so the only thing left to fail is the CPI into an
    // Ika program this test does not load.
    let res = Sign::new().run();
    assert!(res.raw_result.is_err());
    for ours in [
        InstructionError::IllegalOwner,
        InstructionError::InvalidSeeds,
        InstructionError::InvalidArgument,
        InstructionError::IncorrectProgramId,
        InstructionError::InvalidAccountData,
        InstructionError::InvalidInstructionData,
    ] {
        assert_ne!(res.raw_result, Err(ours));
    }
}
