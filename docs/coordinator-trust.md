# Coordinator trust

The coordinator sees signed tickets, can delay root publication, can censor tickets, and may observe network metadata outside this application. SQLite compromise reveals submitted public ticket material and timing, though not activity-wallet or ticket private keys. Immutable root/schedule rows, unique constraints, transactions, WAL, event hashes, rate limiting, body bounds, leases schema, and restart tests reduce equivocation and crash inconsistency.

Clients cannot choose the slot used for ticket expiry. The coordinator reads it at confirmed commitment from its configured Solana RPC and fails closed when the clock is unavailable. The operator still chooses and trusts that RPC, so a dishonest or stale upstream can influence admission; deployments should monitor slot progress and cluster identity.

One coordinator is implemented. Federation, independent root comparison, threshold signing, and distributed aggregation are future options—not current decentralization claims.
