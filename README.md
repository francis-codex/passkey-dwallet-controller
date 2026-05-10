# PasskeyDWalletController

The on-chain authority that lets a WebAuthn passkey hold an Ika MPC dWallet on Solana — and sign EVM transactions from one FaceID tap.

Shipped by [Seedless](https://www.seedlesslabs.xyz/) — a private mainnet-beta passkey wallet on Solana. This program is the bridge our mobile app uses to sign cross-chain through Ika.

- **Program ID (Solana devnet):** `3xYHGYP24wH75tB1U3tn2RoQHcgZLkjuWTT4snWbv9zv`
- **Deploy tx:** [solscan](https://solscan.io/tx/2aNbhbwAFGa1YHfv3sQCnAWtmjw5yhcc5UTLMX7k3mF2egvA8PtWMrCKntNtH6GuWEt2vd2L3zAx8ZQigJK3kGmS?cluster=devnet)
- **Toolchain:** Solana platform-tools v1.54 · Pinocchio v0.10
- **License:** BSD-3-Clause-Clear

---

## Why this exists

Every existing Ika integration assumes a standard Solana wallet (Phantom, Backpack) is the dWallet's controlling authority. That wallet holds a seed phrase. The user signs with that seed-phrase-backed keypair, and that signature gates the dWallet approval.

Seedless has no seed phrase. The user's only credential is a passkey — a P-256 keypair stored in Secure Enclave / Android Keystore — that the OS guards behind FaceID. We need an on-chain authority that understands passkey signatures, not Solana keypairs.

PasskeyDWalletController is that authority. It's the missing piece between a mobile-first passkey wallet and Ika's cross-chain signing primitive.

---

## How it works

```
┌────────────────┐   1. WebAuthn assertion      ┌────────────────────┐
│  Seedless app  │  ─────────────────────────▶  │  P-256 signature   │
│  (React Native)│                              └────────────────────┘
└────────────────┘                                        │
        │                                                 │ 2. submit
        │                                                 ▼
        │                                       ┌────────────────────┐
        │                                       │  Solana tx (devnet)│
        │                                       │  ┌──────────────┐  │
        │                                       │  │ secp256r1    │  │
        │                                       │  │ verify ix    │  │
        │                                       │  └──────────────┘  │
        │                                       │  ┌──────────────┐  │
        │                                       │  │ request_sign │  │
        │                                       │  │ (this prog)  │  │
        │                                       │  └──────────────┘  │
        │                                       └─────────┬──────────┘
        │                                                 │
        │                                       3. CPI    ▼
        │                                       ┌────────────────────┐
        │                                       │ Ika dWallet program│
        │                                       │ approve_message    │
        │                                       └─────────┬──────────┘
        │                                                 │ MessageApproval PDA
        │                                                 ▼
        │                                       ┌────────────────────┐
        │  ◀─── 4. poll Ika network ─────────  │ Ika MPC quorum     │
        │                                       │ produces ECDSA sig │
        ▼                                       └────────────────────┘
┌────────────────┐
│ Broadcast EVM  │
│ tx with sig    │
└────────────────┘
```

Two instructions, both verified entirely on-chain:

**`init_controller`** registers a passkey + dWallet binding. The Controller PDA (`["controller", owner]`) stores the user's 33-byte compressed P-256 pubkey and the dWallet account address. Dust-rent for the account is ~0.0016 SOL.

**`request_sign`** is the gate. It takes a 32-byte message digest, introspects the sibling Secp256r1SigVerify instruction in the same transaction, and verifies five things on-chain:

1. The sibling instruction is the real Solana secp256r1 precompile (`Secp256r1SigVerify1111111111111111111111111`).
2. Exactly one signature is being verified.
3. All three blobs (signature, pubkey, message) live in the precompile's own data — not borrowed from another instruction.
4. The verified pubkey matches the passkey registered in the Controller PDA.
5. The verified message equals the digest being approved.

Only if all five hold does the program CPI into the Ika dWallet program calling `approve_message`. The MessageApproval PDA is then visible to the Ika MPC quorum, which produces the actual ECDSA signature off-chain and returns it for the caller to broadcast on any EVM chain.

The verification logic mirrors Solana's SIMD-0048 specification byte-for-byte. The `arithmetic_side_effects` clippy lint stays denied at workspace level for everything except the parser, where every offset is bounds-checked against the sysvar data length.

---

## Repository layout

```
.
├── Cargo.toml                                # Rust workspace
├── programs/
│   └── passkey-dwallet-controller/
│       ├── Cargo.toml
│       ├── src/lib.rs                        # Pinocchio program
│       └── tests/mollusk.rs                  # Mollusk SVM tests
├── client/
│   ├── package.json
│   ├── tsconfig.json
│   └── src/index.ts                          # TS instruction builders + composer
└── scripts/
    └── deploy.sh                             # devnet deploy helper
```

The workspace path-deps the Ika SDK from `../Code/ika-pre-alpha/`. Clone alongside:

```
seedless/
  Code/ika-pre-alpha/         # cloned from dWalletLabs/ika-pre-alpha
  frontier-ika-bounty/        # this repo
```

---

## Build & deploy

Requires Solana platform-tools v1.54 (ships cargo 1.89 with `edition2024` stable):

```bash
cargo build-sbf --tools-version v1.54
```

Deploy to devnet:

```bash
solana program deploy target/deploy/passkey_dwallet_controller.so
```

The `.so` binary is 19 KB. Rent-exempt deploy costs ~0.13 SOL.

TypeScript client:

```bash
cd client && npm install && npm run typecheck
```

---

## Integration with Seedless

The Seedless mobile app composes a single transaction containing two instructions, in order:

```ts
import { composePasskeySignTx } from "passkey-dwallet-controller";

const tx = composePasskeySignTx({
  owner, payer, dwallet, coordinator,
  messageApproval, messageApprovalBump,
  cpiAuthority, cpiAuthorityBump,
  passkeyPubkey,           // 33-byte compressed P-256 from WebAuthn
  passkeySignature,        // 64 bytes (r||s) from WebAuthn assertion
  userPubkey,              // 32-byte Ika user pubkey for the dWallet
  digest,                  // 32-byte message being approved
  signatureScheme,         // u16 from @ika.xyz/sdk
});
```

The mobile app already integrates `@ika.xyz/sdk` via `SuiJsonRpcClient` for dWallet creation and signature polling — Sepolia tx [`0xb1bc9e14...`](https://sepolia.etherscan.io/tx/0xb1bc9e14ea17a0e23aedf76a7a1785596c18bd9bfe4bd66338f5778ba97989f4) confirmed on May 6. This program is what closes the loop: every signature the user authorizes flows through on-chain passkey verification before Ika's MPC quorum ever sees the request.

---

## Security model

Threats this program defends against:

| Attack | Defense |
|---|---|
| Attacker submits `request_sign` without the sibling secp256r1 ix | Program reads sysvar instructions, rejects on missing precompile |
| Attacker substitutes a different secp256r1 program | Program ID checked against pinned `Secp256r1SigVerify1111111111111111111111111` |
| Attacker uses a different passkey's signature | Program compares verified pubkey to the one stored in Controller PDA |
| Attacker reuses a signature for a different message | Program asserts the verified message blob equals `message_digest` exactly |
| Attacker points the offsets table at another ix's data | Program rejects unless all blob `*_ix_idx` fields are the sentinel (current ix) |
| Replay across multiple Ika dWallets | Controller PDA seed includes `owner`, scoping each binding to one user |

The Solana runtime aborts the transaction if the secp256r1 precompile itself reports an invalid signature, so we never trust an unverified signature to reach the CPI.

---

## What's next

- **Mobile e2e on devnet.** Wire the Seedless React Native client to broadcast `composePasskeySignTx`, poll Ika, and submit the resulting ECDSA signature to Sepolia. The pieces are in place; the work is gluing them together.
- **Mollusk coverage.** Happy-path + reject paths for both instructions. Skeletons are checked in.
- **Mainnet.** When Ika ships a mainnet-ready Solana coordinator, this program is the bridge for every Seedless user.
