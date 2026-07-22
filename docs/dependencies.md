# Dependency decisions

- Rust `1.89.0` is pinned because the Solana 4.0 SDK line declares Rust 1.85+ and the installed Solana CLI supplies an SBF toolchain based on 1.89.
- Native `solana-program = 4.0.0` and `solana-client = 4.0.0` track the installed Agave CLI 4.1.1. Client transaction split crates are pinned to the RPC client's compatible 3.1 ABI; the monolithic 4.0 SDK transaction type is intentionally not used. The current program-test 4.3 line is alpha, so deterministic processor/security tests avoid that unstable dependency.
- Local deployment uses `cargo build-sbf --arch v3`; the fresh 4.1.1 validator had the SIMD feature for sBPFv3 active, while the default artifact was rejected as requiring an unavailable sBPF version.
- `rusqlite = 0.36.0` is intentionally pinned: 0.40's current `libsqlite3-sys` build script uses `cfg_select`, which fails under Rust 1.89. SQLite is bundled and WAL/foreign keys are enabled.
- Ed25519 ticket signing uses maintained `ed25519-dalek 2.2`; BLAKE3 is used only for non-secret commitments, roots, trace identities, and evidence checksums.

Official references: [Solana program model](https://solana.com/docs/core/programs), [native program execution](https://solana.com/docs/core/programs/program-execution), [program limitations](https://solana.com/docs/programs/limitations), and [local build/deployment](https://solana.com/docs/programs/deploying).
