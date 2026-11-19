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

## Quickstart

```bash
git clone https://github.com/seedless-labs/passkey-dwallet-controller
cd passkey-dwallet-controller
cd client && npm ci && npm run typecheck   # TypeScript client, no Solana tooling needed
```

To build the program you also need [ika-pre-alpha](https://github.com/dwallet-labs/ika-pre-alpha) cloned at `../Code/ika-pre-alpha` and Solana platform-tools v1.54. See [Build & deploy](#build--deploy).

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

**`init_controller`** registers a passkey + dWallet binding. The Controller PDA (`["controller", dwallet]`, one per dWallet) stores the user's 33-byte compressed P-256 pubkey and the dWallet account address. The owner signing must be the dWallet's current authority, the dWallet must be owned by the Ika dWallet program, the PDA bump must be canonical, and the passkey must sign `"passkey-dwallet-controller:init" || owner || dwallet` in a sibling secp256r1 instruction, which proves the key is a real P-256 point the registrant controls. Dust-rent for the account is ~0.0016 SOL.

**`request_sign`** is the gate. It first requires the Controller to be owned by this program and to be the canonical PDA for the owner it stores, the dWallet to be the one that Controller was registered with, and the Ika program, caller program, system program and CPI authority accounts to be the pinned ones. It then takes a 32-byte message digest, introspects the sibling Secp256r1SigVerify instruction in the same transaction, and verifies five things on-chain:

1. The sibling instruction is the real Solana secp256r1 precompile (`Secp256r1SigVerify1111111111111111111111111`).
2. Exactly one signature is being verified.
3. All three blobs (signature, pubkey, message) live in the precompile's own data — not borrowed from another instruction.
4. The verified pubkey matches the passkey registered in the Controller PDA.
5. The verified message equals `digest || user_pubkey || signature_scheme (u16 LE) || dwallet`, so the passkey signs everything the CPI forwards.

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
cargo build-sbf --tools-version v1.54 --arch v0 \
  --manifest-path programs/passkey-dwallet-controller/Cargo.toml
cargo test -p passkey-dwallet-controller   # Mollusk tests, need the .so above
```

Platform-tools v1.57 fails to link this `no_std` program, and the Mollusk tests load SBPF v0, so both flags are pinned in `scripts/deploy.sh` too.

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

const tx = await composePasskeySignTx({
  owner, payer, dwallet, coordinator,
  messageApproval, messageApprovalBump,
  cpiAuthority, cpiAuthorityBump,
  passkeyPubkey,           // 33-byte compressed P-256 from WebAuthn
  passkeySignature,        // 64 bytes (r||s) over buildSignMessage()
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
| Replay across multiple Ika dWallets | The signed message includes the dWallet address, and `request_sign` only accepts the dWallet stored in the Controller |
| Attacker passes a look-alike Controller account | Controller must be owned by this program and be the canonical PDA for its stored owner |
| Attacker registers a Controller for someone else's dWallet | `init_controller` requires the signer to be the dWallet's current authority |
| Attacker swaps the Ika program or CPI authority account | Both are checked against pinned / derived addresses before the CPI |

Known limits: the passkey signature is a raw P-256 signature over the message above, not a full WebAuthn assertion (no authenticator data or client data parsing). A Controller stays bound to its dWallet if that dWallet's authority later moves to a different party; there is no on-chain registry enforcing one Controller per dWallet.

The Solana runtime aborts the transaction if the secp256r1 precompile itself reports an invalid signature, so we never trust an unverified signature to reach the CPI.

---

## What's next

- **Mobile e2e on devnet.** Wire the Seedless React Native client to broadcast `composePasskeySignTx`, poll Ika, and submit the resulting ECDSA signature to Sepolia. The pieces are in place; the work is gluing them together.
- **Mollusk coverage.** `init_controller` has a happy path and its reject paths; `request_sign` has every reject path. Still open: the `request_sign` happy path through the Ika `approve_message` CPI (needs the Ika program binary) and real secp256r1 precompile verification (Mollusk runs one instruction, so the sibling ix is parsed, not verified).
- **Mainnet.** When Ika ships a mainnet-ready Solana coordinator, this program is the bridge for every Seedless user.

---

## Community

- Questions: [discussions](https://github.com/seedless-labs/passkey-dwallet-controller/discussions) or [Telegram](https://t.me/seedless_users)
- Updates: [@seedlesslabs](https://x.com/seedlesslabs) on X
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · [Code of conduct](CODE_OF_CONDUCT.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

## Links

- Website: [seedlesslabs.xyz](https://www.seedlesslabs.xyz)
- Developers: [seedlesslabs.xyz/developers](https://www.seedlesslabs.xyz/developers)
- All open-source work: [github.com/seedless-labs](https://github.com/seedless-labs)

## License

MIT. See [LICENSE](LICENSE).
