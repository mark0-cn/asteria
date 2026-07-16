# Repository Guidelines

## Project Structure

- `src/` contains the Rust state machine and domain modules. Consensus and
  ABCI++ integration live in `src/consensus.rs`; matching, margin, private
  orders, shielded state, JMT commitments, and persistence are split into
  focused modules.
- `src/bin/` contains the node, CLI, benchmark, and private-key generator
  binaries.
- `tests/` holds cross-module integration tests, especially restart and
  persistence coverage. Deployment assets are under `deploy/`, Docker files
  are at the repository root, and design/performance notes are in `docs/`.

## Build, Test, and Development Commands

Run these from the repository root:

```powershell
cargo fmt --all -- --check
cargo check --offline --all-targets
cargo test --offline --all-targets
cargo clippy --offline --all-targets -- -D warnings
```

For the Windows four-validator development network, install CometBFT, then
run `deploy\comet\windows\Start-Localnet.ps1`; use
`Get-LocalnetStatus.ps1 -RequireHealthy` to verify liveness and
`Stop-Localnet.ps1` to cleanly stop it. The script
`Test-LocalnetScripts.ps1` covers PowerShell and localnet regressions.

## Coding Style and Naming

Use rustfmt defaults and idiomatic Rust: four-space indentation, `snake_case`
functions/modules, `PascalCase` types, and descriptive error variants. Keep
consensus arithmetic checked and deterministic; avoid unchecked casts,
randomness, or `unwrap` on consensus-controlled data. Use canonical
serialization helpers for signed or state-committed values. PowerShell
functions use approved Verb-Noun names and explicit path handling.

## Testing Guidelines

Name tests after observable behavior, for example
`private_order_admission_locks_available_margin_until_decryption`. Add unit
tests beside the module for protocol rules and integration tests under
`tests/` for persistence or process boundaries. Every consensus change should
cover success, rejection, rollback, determinism, and relevant numeric or
privacy edge cases. Run a focused test while iterating, then the full commands
above before submission.

## Security and Configuration

Never commit `data/`, `target/`, `.tools/`, databases, logs, `.env` files,
private keys, or threshold share files. The shielded-margin transparent proof
backend is development-only; do not describe it as production ZK. Changes to
protocol versions, genesis, threshold bindings, or H/H+1/H+2 execution must
update the deployment scripts and architecture documentation together.

## Commits and Pull Requests

Use concise, imperative commit subjects with a clear scope, such as
`Fix private batch bond release`. Pull requests should explain the behavioral
change, protocol or migration impact, security implications, and exact checks
run. Include deployment or configuration notes when touching `deploy/`, Docker,
genesis, or protocol versions; do not include generated runtime state.
