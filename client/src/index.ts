// Off-chain client for PasskeyDWalletController.
//
// Composes:
//   1. WebAuthn passkey assertion (mobile / Lazor flow)
//   2. Solana tx with [secp256r1_verify_ix, request_sign_ix]
//   3. Ika network sign poll → Sepolia (or any EVM) broadcast

import {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";

// The Ika SDK wiring lives in the Seedless main app — `src/ika/client.ts`
// uses `SuiJsonRpcClient + getJsonRpcFullnodeUrl('testnet')` against
// `@ika.xyz/sdk`. This client deliberately stays SDK-free so it can be
// consumed by web, mobile, or backend callers without dragging Sui deps in.

// ── Constants ──

// Deployed on Solana devnet — May 10 2026.
// Deploy sig: 2aNbhbwAFGa1YHfv3sQCnAWtmjw5yhcc5UTLMX7k3mF2egvA8PtWMrCKntNtH6GuWEt2vd2L3zAx8ZQigJK3kGmS
export const PASSKEY_CONTROLLER_PROGRAM_ID = new PublicKey(
  "3xYHGYP24wH75tB1U3tn2RoQHcgZLkjuWTT4snWbv9zv",
);

// Solana native secp256r1 sig-verify precompile (SIMD-0048).
export const SECP256R1_PROGRAM_ID = new PublicKey(
  "Secp256r1SigVerify1111111111111111111111111",
);

// Sysvar instructions account — required for sibling-ix introspection.
export const INSTRUCTIONS_SYSVAR_ID = SYSVAR_INSTRUCTIONS_PUBKEY;

// Ika dWallet coordinator program. Set per environment when wiring the mobile
// integration — Ika ships its Solana-side coordinator address through
// @ika.xyz/sdk metadata once the testnet endpoint is selected.
export const IKA_DWALLET_PROGRAM_ID = new PublicKey(
  "11111111111111111111111111111111",
);

// CPI authority seed — every caller program derives:
//   find_program_address(["__ika_cpi_authority"], caller_program_id)
export const CPI_AUTHORITY_SEED = Buffer.from("__ika_cpi_authority");

// ── PDA helpers ──

export function findControllerAddress(owner: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("controller"), owner.toBuffer()],
    PASSKEY_CONTROLLER_PROGRAM_ID,
  );
}

export function findCpiAuthority(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [CPI_AUTHORITY_SEED],
    PASSKEY_CONTROLLER_PROGRAM_ID,
  );
}

// ── Instruction builders ──

export interface InitControllerArgs {
  owner: PublicKey;
  payer: PublicKey;
  dwallet: PublicKey;
  passkeyPubkey: Uint8Array; // 33-byte compressed P-256
}

export function buildInitControllerIx(args: InitControllerArgs): TransactionInstruction {
  const [controller, bump] = findControllerAddress(args.owner);
  if (args.passkeyPubkey.length !== 33) {
    throw new Error("passkey pubkey must be 33-byte compressed P-256");
  }
  const data = Buffer.concat([
    Buffer.from([0]), // discriminator: InitController
    Buffer.from(args.passkeyPubkey),
    Buffer.from([bump]),
  ]);
  return new TransactionInstruction({
    programId: PASSKEY_CONTROLLER_PROGRAM_ID,
    keys: [
      { pubkey: controller, isSigner: false, isWritable: true },
      { pubkey: args.dwallet, isSigner: false, isWritable: false },
      { pubkey: args.owner, isSigner: true, isWritable: false },
      { pubkey: args.payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export interface RequestSignArgs {
  controller: PublicKey;
  dwallet: PublicKey;
  payer: PublicKey;
  coordinator: PublicKey;
  messageApproval: PublicKey;
  messageApprovalBump: number;
  cpiAuthority: PublicKey;
  cpiAuthorityBump: number;
  messageDigest: Uint8Array; // 32 bytes
  userPubkey: Uint8Array;    // 32 bytes
  signatureScheme: number;   // u16
  secp256r1IxIndex: number;  // index of the verify ix in this tx
}

export function buildRequestSignIx(args: RequestSignArgs): TransactionInstruction {
  if (args.messageDigest.length !== 32) throw new Error("digest must be 32 bytes");
  if (args.userPubkey.length !== 32) throw new Error("user pubkey must be 32 bytes");

  const data = Buffer.concat([
    Buffer.from([1]), // discriminator: RequestSign
    Buffer.from(args.messageDigest),
    Buffer.from(args.userPubkey),
    Buffer.from(new Uint16Array([args.signatureScheme]).buffer),
    Buffer.from([args.messageApprovalBump]),
    Buffer.from([args.cpiAuthorityBump]),
    Buffer.from([args.secp256r1IxIndex]),
  ]);

  return new TransactionInstruction({
    programId: PASSKEY_CONTROLLER_PROGRAM_ID,
    keys: [
      { pubkey: args.controller,           isSigner: false, isWritable: false },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      { pubkey: args.coordinator,          isSigner: false, isWritable: false },
      { pubkey: args.messageApproval,      isSigner: false, isWritable: true  },
      { pubkey: args.dwallet,              isSigner: false, isWritable: false },
      { pubkey: args.payer,                isSigner: true,  isWritable: true  },
      { pubkey: SystemProgram.programId,   isSigner: false, isWritable: false },
      { pubkey: PASSKEY_CONTROLLER_PROGRAM_ID, isSigner: false, isWritable: false }, // caller_program
      { pubkey: args.cpiAuthority,         isSigner: false, isWritable: false },
      { pubkey: IKA_DWALLET_PROGRAM_ID,    isSigner: false, isWritable: false },
    ],
    data,
  });
}

// ── secp256r1 sibling-instruction builder (SIMD-0048) ──
//
// Layout:
//   num_sigs(u8) | padding(u8)
//   SignatureOffsets {
//     sig_offset(u16) | sig_ix_idx(u16)
//     pk_offset(u16)  | pk_ix_idx(u16)
//     msg_offset(u16) | msg_size(u16) | msg_ix_idx(u16)
//   }
//   <signature 64 bytes> <pubkey 33 bytes> <message N bytes>
//
// All *_ix_idx fields are set to 0xFFFF so the precompile reads blobs from
// its own ix data. The Pinocchio `request_sign` ix introspects this exact
// layout and rejects any mismatch.
const SECP256R1_HEADER_LEN = 2;
const SECP256R1_OFFSETS_LEN = 14;
const SECP256R1_SIG_LEN = 64;
const SECP256R1_PUBKEY_LEN = 33;
const CURRENT_IX_SENTINEL = 0xffff;

export function buildSecp256r1VerifyIx(args: {
  passkeyPubkey: Uint8Array; // 33 bytes (compressed P-256)
  signature: Uint8Array;     // 64 bytes (r||s, big-endian)
  message: Uint8Array;       // arbitrary; we pass the 32-byte digest
}): TransactionInstruction {
  if (args.passkeyPubkey.length !== SECP256R1_PUBKEY_LEN) {
    throw new Error("passkeyPubkey must be 33-byte compressed P-256");
  }
  if (args.signature.length !== SECP256R1_SIG_LEN) {
    throw new Error("signature must be 64 bytes (r||s)");
  }

  const sigOffset = SECP256R1_HEADER_LEN + SECP256R1_OFFSETS_LEN;
  const pkOffset = sigOffset + SECP256R1_SIG_LEN;
  const msgOffset = pkOffset + SECP256R1_PUBKEY_LEN;
  const totalLen = msgOffset + args.message.length;

  const data = Buffer.alloc(totalLen);
  data.writeUInt8(1, 0); // num_sigs
  data.writeUInt8(0, 1); // padding

  data.writeUInt16LE(sigOffset, 2);
  data.writeUInt16LE(CURRENT_IX_SENTINEL, 4);
  data.writeUInt16LE(pkOffset, 6);
  data.writeUInt16LE(CURRENT_IX_SENTINEL, 8);
  data.writeUInt16LE(msgOffset, 10);
  data.writeUInt16LE(args.message.length, 12);
  data.writeUInt16LE(CURRENT_IX_SENTINEL, 14);

  Buffer.from(args.signature).copy(data, sigOffset);
  Buffer.from(args.passkeyPubkey).copy(data, pkOffset);
  Buffer.from(args.message).copy(data, msgOffset);

  return new TransactionInstruction({
    programId: SECP256R1_PROGRAM_ID,
    keys: [],
    data,
  });
}

// ── Compose a passkey-signed approval tx ──
//
// Returns a Transaction containing two instructions, in order:
//   [0] secp256r1 verify ix (proves the registered passkey signed `digest`)
//   [1] request_sign ix     (introspects [0], CPI-approves the message on Ika)
//
// Caller is responsible for:
//   - Obtaining the WebAuthn assertion (mobile/native), extracting the 64-byte
//     P-256 signature (r||s, big-endian)
//   - Hashing the WebAuthn challenge → 32-byte `digest`
//   - Submitting + waiting for confirmation, then polling Ika network for the
//     dWallet-produced ECDSA sig (use `@ika.xyz/sdk` — see Seedless main-app
//     `src/ika/client.ts` for the SuiJsonRpcClient + testnet pattern)
//   - Assembling + broadcasting the EVM tx with the resulting Ika signature
export interface ComposePasskeySignTxArgs {
  owner: PublicKey;
  payer: PublicKey;
  dwallet: PublicKey;
  coordinator: PublicKey;
  messageApproval: PublicKey;
  messageApprovalBump: number;
  cpiAuthority: PublicKey;
  cpiAuthorityBump: number;
  passkeyPubkey: Uint8Array;     // 33-byte compressed P-256
  passkeySignature: Uint8Array;  // 64 bytes (r||s)
  userPubkey: Uint8Array;        // 32 bytes — Ika user pubkey for the dWallet
  digest: Uint8Array;            // 32 bytes — the message being approved
  signatureScheme: number;       // u16 — Ika signature scheme tag
}

export function composePasskeySignTx(args: ComposePasskeySignTxArgs): Transaction {
  if (args.digest.length !== 32) throw new Error("digest must be 32 bytes");

  const [controller] = findControllerAddress(args.owner);

  const verifyIx = buildSecp256r1VerifyIx({
    passkeyPubkey: args.passkeyPubkey,
    signature: args.passkeySignature,
    message: args.digest,
  });

  const requestSignIx = buildRequestSignIx({
    controller,
    dwallet: args.dwallet,
    payer: args.payer,
    coordinator: args.coordinator,
    messageApproval: args.messageApproval,
    messageApprovalBump: args.messageApprovalBump,
    cpiAuthority: args.cpiAuthority,
    cpiAuthorityBump: args.cpiAuthorityBump,
    messageDigest: args.digest,
    userPubkey: args.userPubkey,
    signatureScheme: args.signatureScheme,
    secp256r1IxIndex: 0, // verifyIx must be at index 0
  });

  return new Transaction().add(verifyIx, requestSignIx);
}
