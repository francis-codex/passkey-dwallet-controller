#!/usr/bin/env bash
# Deploy PasskeyDWalletController to Solana devnet.
# Usage: ./scripts/deploy.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# 1. Build the SBF program.
echo "▶︎ Building program..."
cargo build-sbf --manifest-path programs/passkey-dwallet-controller/Cargo.toml

PROGRAM_SO=target/deploy/passkey_dwallet_controller.so
KEYPAIR=target/deploy/passkey_dwallet_controller-keypair.json

if [ ! -f "$KEYPAIR" ]; then
  echo "▶︎ Generating program keypair..."
  solana-keygen new --no-bip39-passphrase -o "$KEYPAIR"
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
