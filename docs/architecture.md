# Architecture

The system separates immutable protocol types, ticket signatures, Merkle aggregation, participant-owned action construction, durable coordinator state, and bounded on-chain metadata. The native program never receives an instruction capable of executing participant actions or arbitrary CPI. Transparent registrations use one fixed-size PDA per one-time key; Merkle rounds store one fixed-size root and count. This avoids unbounded account vectors.

The recommended tree was consolidated where cohesion mattered: configuration lives with the core model; simulation and evaluation share deterministic trace primitives; test fixtures live beside their crates. This reduces crate plumbing without weakening trust boundaries.

The coordinator trait permits future federation or threshold root signing. Neither is implemented, so this release does not claim decentralization. A future ZK membership backend is only a design option; there is no circuit, verifier, or ZK claim.

Pool, round, and transparent-participant PDAs are created by their corresponding closed program instructions. Their only CPI is a seed-signed System Program `create_account` call for bounded rent-funded metadata. There is no generic CPI surface, participant-action CPI, or program-held participant asset. The Rust client constructs the fixed account lists and the full demo verifies the resulting round account through RPC.
