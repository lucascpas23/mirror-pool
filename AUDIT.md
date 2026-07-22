# Implementation audit

## Scope and requirement mapping

Reviewed the Rust workspace, native Solana metadata program, signed tickets, transparent/Merkle coordination, state transitions, SQLite coordinator recovery, participant SDK/CLI, action safety, deterministic simulator/evaluator, evidence verifier, CI, and documentation. The implementation is Rust-only apart from workflow YAML. The preserved `LICENSE` is MIT.

The program contains a closed coordination instruction enum and no generalized CPI or participant-action execution. It stores only bounded metadata/rent accounts. There are no deposits, withdrawals, common fund accounts, pooled stake, pooled tokens, custody keys, or recipient-hiding transfers.

## Architecture and toolchain

Rust 1.89 is pinned. The inspected host initially provided rustc/cargo 1.97.1, Solana CLI 4.1.1, no Surfpool, and no Anchor. Stable `solana-program 4.0.0` and `solana-client 4.0.0` are pinned through Cargo.lock; the client uses the RPC client's exact split-crate transaction ABI. `rusqlite 0.36.0` is pinned for Rust 1.89 compatibility after a factual failed build with 0.40's `libsqlite3-sys`.

## Validation record

The initial phase gate passed 15 tests across core, tickets, Merkle, actions, simulator, and store. The first full-workspace gate failed on native `AccountInfo` lifetime invariance and then Axum timeout-layer error typing; both were fixed. The final full-workspace gate passed 27 tests with no failures, including coordinator integration and trusted-clock HTTP behavior, client instruction builders, acknowledgement fail-closed behavior, and tampered-action/fee-limit coverage. Final command results, generated metric values, build-SBF/local-validator status, dependency scans, evidence checksums, and remaining warnings are filled from the final validation run below.

## Security and privacy findings

- Positive: fail-closed default sending, loopback enforcement, explicit simulation/confirmation policy, bounded templates/requests/cohorts/accounts, signature/expiry/binding checks using a coordinator-owned confirmed RPC clock, admission failure when that clock is unavailable, domain separation, duplicate constraints, WAL/foreign keys, idempotent roots/schedules, mode-0600 participant ticket files, no coordinator secret persistence, no arbitrary CPI.
- Unfavorable: the coordinator sees tickets and can censor/delay; network/RPC/funding/history can relink participants; Sybils can inflate announced sets; dropouts reduce observed sets; synchronized cohorts may be detectable; synthetic classifier results are not real-world evidence; one coordinator is not decentralized.
- No security audit or cryptographic anonymity claim is made. Public/mainnet readiness is explicitly not claimed.

## Test and evidence results

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- `cargo test --workspace --all-features`: passed; 27 tests, 0 failed/ignored (unit, property, signature, Merkle, coordinator seal/proof/rate/duplicate and trusted-slot failure modes, client PDA/instruction builders, acknowledgement and safety-template/tampering/fee, evaluator, fixed-account/instruction-set, SQLite duplicate/idempotency/on-disk-restart).
- `cargo test --doc --workspace`: passed; no doctest failures.
- `cargo build --workspace --all-features --release`: passed on the inspected host.
- `cargo audit`: passed with one allowed warning: transitive Solana `bincode 1.3.3` is unmaintained (RUSTSEC-2025-0141); no safe Solana 4.0 replacement exists.
- `cargo deny check`: advisories, bans, licenses, and sources passed. The same narrowly documented bincode advisory is ignored; duplicate-version findings and one transitive Solana crate without a manifest license field remain warnings.
- Secret/product-language scan: passed; no TypeScript, JavaScript, Python, keypair, database, `.env`, private-key block, assigned seed phrase/passphrase, or absolute home path exists outside ignored build output. Temporary validator/deployer/program keypairs and ledger were destroyed after use.
- `git diff --check`: passed. No commit, push, or PR was created.

SBF/localnet: `cargo build-sbf --arch v3` passed under cargo-build-sbf 4.1.0/platform-tools 1.54. A first default-arch deployment correctly failed because the validator had not enabled that artifact's required sBPF version; it was not counted. The final dependency-locked v3 artifact SHA-256 is `7a1afcad85a6485fb14c1a550109dd76ddd495494a2f8ac014323cf3da90f555`.

The final `cargo xtask full-demo` started a fresh isolated Solana 4.1.1 validator, deployed that artifact as `4jYt1hagHNqDBsP4qD1gcohPbtHbM5SSxv3gE6rcXu9q` with signature `5hZwykB6DTxSbWhXxbJ2NDsDwDvaLbjbCcVgpwFWmZoCcxgSkqmE7VDmXiugcXkDkbki9eE5SmnV9NPyTt2sDz3s`, created the pool/round PDAs through bounded System Program CPI, published/sealed/scheduled the 25-member Merkle root, began the release window, and verified the on-chain round account. Five independent funded disposable wallets then passed hard-coded Memo allowlisting, slot/fee/shape guards, RPC simulation, local signing, sending, and confirmation; one additional local participant dropped out. Submitted = 5, confirmed = 5, failed = 0, observed execution spread = 4 slots, and redacted receipt hash = `d8efc25bee92cb7e01c27f1920b85ca007f8360cb32f9564c5eee1d902469dd2`. The validator, ledger, wallets, program key, database, and action material were automatically destroyed.

Virtual/evaluator: 127 deterministic scenarios passed evidence verification: 120 rounds plus one same-seed ablation control and six feature ablations, cohort sizes 10/100/1,000, multiple seeds/backends/strategies/windows/dropout/observation periods. Across all scenarios observed size was 4–964, minimum completion 0.40, maximum spread 20 slots, minimum normalized entropy 0.792302, minimum k 1, maximum unique fingerprint rate 1.0, and maximum classifier AUC/FPR/FNR 1.0. These are deliberately retained unfavorable findings. For 1,000-participant scenarios observed size was 631–964; the earlier exact aggregation reported maximum AUC about 0.451 and spread 4 for that subset.

Same-seed ablation control (1,000 announced, 908 observed) had normalized entropy 0.966821, effective set 724.34, AUC 0.399443, uniqueness 0.6894, and minimum k 1. Removing funding graph produced the lowest fingerprint entropy/effective count (0.792302/220.65) and uniqueness (0.0143); removing amount bucket produced the highest ablated AUC (0.454738). This illustrates that fingerprint entropy and unique-rate must be interpreted together; the synthetic classifier is not evidence of real unlinkability.

Latest Merkle benchmark (`cargo xtask full-demo`, debug build, 1,000 leaves): build 4,134 µs, proof generation 1 µs, proof verification 37 µs, deterministic root `a5c4c6cdbc69bfff686081b59b564b3ca6648c5f0b117022e0507626d762286f`. Timings are host-load-sensitive. The cold evidence command including compilation took 6.80 seconds and reported approximately 4.1 MB maximum resident set / 2.0 MB peak footprint on macOS.

Evidence checksums: JSON `fec1c32023254260bbee6aebd0a3119f7161eaf0bde2a45a137cb784d86a10b6`; CSV `bca8e073375cba32f4bfca9afb1be1c8fec2c5543fb4c8dd86af1c82f5b17c0c`; Markdown `26bd8b70c4c0d79edf08c86d601ded1943ec836e5592e9d8065e77b897760db2`.

## Untested paths and remaining risks

Native processor logic has deterministic unit/security tests and its positive Merkle lifecycle is covered by the real validator demo, but stable `solana-program-test` 4.x was unavailable (latest found was alpha), so the full negative on-chain matrix is not executed in a bank harness. The CLI's pool/round subcommands create and validate local intent files; programmatic on-chain administration uses the Rust client and `xtask full-demo`. `observe` consumes an existing public file rather than indexing RPC history, while `report` renders existing synthetic evaluation JSON into JSON/CSV/Markdown. Token and stake templates are preparation/simulation extension points; direct sending is intentionally limited to canonical Memo. Network metadata protection, federated coordination, threshold signing, ZK membership, real chain-analytics resistance, production key management, and mainnet readiness are unimplemented. Future ZK support is a documented interface direction only, with no fake verifier.

## Reproduction

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo test --doc --workspace
cargo build --workspace --all-features --release
cargo xtask setup
cargo xtask demo
cargo xtask full-demo
cargo xtask evaluate --output evidence/generated
cargo xtask verify-evidence --directory evidence/generated
cargo build-sbf --arch v3 --manifest-path programs/mirror-pool-program/Cargo.toml
git diff --check
```

Acceptance requires reading the limitations above: virtual participant counts are not confirmed transactions, and planned/simulated actions are never reported as confirmed. The five full-demo local confirmations are separately identified by their sanitized receipt hash.
