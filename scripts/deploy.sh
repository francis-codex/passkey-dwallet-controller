#!/usr/bin/env bash
# Deploy PasskeyDWalletController to Solana devnet.
# Usage: ./scripts/deploy.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# 1. Build the SBF program.
echo "▶︎ Building program..."
# Pinned: platform-tools v1.57 fails to link this no_std program, and SBPF v0
# is the arch the Mollusk tests load.
cargo build-sbf --tools-version v1.54 --arch v0 \
  --manifest-path programs/passkey-dwallet-controller/Cargo.toml

PROGRAM_SO=target/deploy/passkey_dwallet_controller.so
KEYPAIR=target/deploy/passkey_dwallet_controller-keypair.json

if [ ! -f "$KEYPAIR" ]; then
  echo "▶︎ Generating program keypair..."
  # Prompts for a BIP39 passphrase. This key is the program's upgrade identity:
  # keep it out of the repo and back it up.
  solana-keygen new -o "$KEYPAIR"
  chmod 600 "$KEYPAIR"
fi

PROGRAM_ID=$(solana-keygen pubkey "$KEYPAIR")
echo "▶︎ Program ID: $PROGRAM_ID"
echo "  → Update src/lib.rs ID constant + client/src/index.ts PASSKEY_CONTROLLER_PROGRAM_ID before deploy."

# 2. Airdrop if needed (devnet).
solana config set --url devnet >/dev/null
BAL=$(solana balance | awk '{print $1}')
echo "▶︎ Devnet balance: ${BAL} SOL"

# 3. Deploy.
echo "▶︎ Deploying..."
solana program deploy "$PROGRAM_SO" --program-id "$KEYPAIR"

echo "✓ Deployed: $PROGRAM_ID"
