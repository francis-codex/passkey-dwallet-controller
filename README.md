# PasskeyDWalletController

Passkey-gated Ika dWallet message approval for Solana — built for Frontier Hackathon Ika/Encrypt side track.

**Submission target:** top-3 finish.
**Deadline:** Sun May 11 2026.
**Status:** ✅ Compiled with platform-tools v1.54 (cargo 1.89). ✅ Deployed to Solana devnet.

- **Program ID:** `3xYHGYP24wH75tB1U3tn2RoQHcgZLkjuWTT4snWbv9zv`
- **Deploy tx:** [solscan](https://solscan.io/tx/2aNbhbwAFGa1YHfv3sQCnAWtmjw5yhcc5UTLMX7k3mF2egvA8PtWMrCKntNtH6GuWEt2vd2L3zAx8ZQigJK3kGmS?cluster=devnet)

---

## What it does

Bridges WebAuthn / passkey UX with Ika's MPC dWallets on Solana. The dWallet's authority is transferred to this program's CPI authority PDA via the standard Ika flow. Subsequent signing requests must present a P-256 (secp256r1) signature from the registered passkey over the message digest, verified via Solana's `Secp256r1SigVerify` native precompile in a sibling instruction.

**Composes two protocols:**
- **LazorKit-style passkey UX** (WebAuthn assertion → secp256r1 verify on Solana)
- **Ika MPC dWallets** (cross-chain signing via the dWallet primitive)

The result: a Solana program that lets a passkey hold a dWallet that can sign EVM tx without ever exposing a seed. No browser extension. No seed phrase. Just a passkey on the user's device.

---

## Architecture

```
┌────────────────┐   1. WebAuthn assertion      ┌────────────────────┐
│  Mobile app    │  ─────────────────────────▶  │   P-256 signature  │
│  (Seedless)    │                              └────────────────────┘
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
        │                                       │  │ ix (this prog)│ │
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
        │  ◀─── 4. poll Ika network gRPC ─────  │ Ika MPC quorum     │
        │                                       │ produces ECDSA sig │
        ▼                                       └────────────────────┘
┌────────────────┐
│ Broadcast EVM  │
│ tx with sig    │
└────────────────┘
```

---

## Layout

```
frontier-ika-bounty/
├── Cargo.toml                                # workspace
├── programs/
│   └── passkey-dwallet-controller/
│       ├── Cargo.toml
│       ├── src/lib.rs                        # Pinocchio program (init + request_sign)
│       └── tests/mollusk.rs                  # Mollusk SVM test skeleton
├── client/
│   ├── package.json
│   ├── tsconfig.json
│   └── src/index.ts                          # ix builders + Ika gRPC bridge
├── scripts/
│   └── deploy.sh                             # devnet deploy
└── README.md
```

The workspace path-deps `../Code/ika-pre-alpha/...` for the Ika SDK crates. Clone alongside `ika-pre-alpha` to build:

```bash
# expected layout
seedless/
  Code/ika-pre-alpha/         # cloned from dWalletLabs/ika-pre-alpha
  frontier-ika-bounty/        # this repo
```

---

## Build

```bash
# Rust program
cd programs/passkey-dwallet-controller
cargo build-sbf

# Mollusk tests
cargo test -p passkey-dwallet-controller

# TS client
cd ../../client
npm install
npm run typecheck
```

---

## Deploy (devnet)

```bash
./scripts/deploy.sh
# update src/lib.rs ID + client/src/index.ts PASSKEY_CONTROLLER_PROGRAM_ID
# with the printed program id, rebuild + redeploy
```

---

## Build-phase TODOs (Sat May 9)

Marked in source as `TODO(build-phase, ...)`:

1. **Sibling secp256r1 ix introspection** in `request_sign` — load Sysvar::instructions, deserialize the ix at `secp256r1_ix_index`, validate program ID + pubkey + message hash. Mirror LazorKit's verifier.
2. **secp256r1 program ID** — pin the real native precompile address (SIMD-0048).
3. **Mollusk test bodies** — happy paths + reject paths (no sibling ix, wrong pubkey, wrong digest).
4. **TS `buildSecp256r1VerifyIx`** — assemble the SIMD-0048 layout (offsets table + sig/pubkey/msg blobs).
5. **TS `pollIkaSignature`** — wire @ika.xyz/sdk against testnet, mirror src/ika/client.ts pattern from main app.
6. **TS `passkeySignDigest`** — full e2e orchestration.

## Sun May 10 AM
- Devnet deploy.
- Mobile integration: write a test screen in main app that calls into this controller via the TS client (separate from Phase 4 build — gated behind `__DEV__` flag).
- Smoke test: produce a real Sepolia signature via passkey → dWallet path.

## Sun May 10 PM
- Demo video shows: open Seedless on phone → tap "sign with passkey" → Sepolia tx confirmed.
- Submission writeup.

---

## License

BSD-3-Clause-Clear (matches Ika upstream).
