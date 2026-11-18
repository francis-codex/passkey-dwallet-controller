# Contributing

Thanks for helping out. Issues and pull requests are welcome.

## Setup

1. Clone this repo, and clone [ika-pre-alpha](https://github.com/dwallet-labs/ika-pre-alpha) to `../Code/ika-pre-alpha`. The Ika crates are path dependencies in `Cargo.toml`.
2. Install Solana platform-tools v1.54 (see the README for why the version is pinned).
3. Build and test:

```bash
cargo build-sbf --tools-version v1.54 --arch v0 \
  --manifest-path programs/passkey-dwallet-controller/Cargo.toml
cargo test -p passkey-dwallet-controller
cd client && npm ci && npm run typecheck
```

## Pull requests

- Branch from `main` and open a PR against `main`. Direct pushes to `main` are blocked.
- Keep each PR to one change. Describe what it does and how you tested it.
- Run `cargo fmt` and `cargo clippy` before pushing. The workspace denies `arithmetic_side_effects`, so use checked math.
- Add or update Mollusk tests for any change to instruction handling.
- Add a line to `CHANGELOG.md` under "Unreleased".

## Reporting bugs

Open an issue with the bug template. For anything security-related, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Code of conduct

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md).
