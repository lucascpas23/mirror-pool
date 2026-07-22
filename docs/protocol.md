# Protocol

A pool fixes governance, template hash, thresholds, timing, backend, clusters, programs, and reporting policy. A round moves through draft, registration, threshold reached, sealed, release scheduled, execution window, finalizing, and completed; cancellation/expiry are terminal.

Tickets bind schema, pool, round, template, one-time key, nonce commitment, and expiry under an Ed25519 signature. The activity wallet is absent. The HTTP API accepts only the ticket; expiry is checked against a confirmed-commitment Solana RPC slot chosen by the operator, never a client-supplied slot. If that clock cannot be read, ticket admission fails closed. The coordinator validates and deduplicates tickets, sorts their commitments, builds a domain-separated Merkle tree, persists every proof transactionally, publishes a root/count, seals once, and schedules once. A participant independently verifies their proof and public configuration before deciding whether to act.
