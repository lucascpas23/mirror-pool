# Operations

Default RPC and API listeners are loopback. Keep sending disabled, run `doctor`, back up SQLite with SQLite-aware tooling, monitor disk/errors/restarts, rotate coordinator identity outside the database, and never place wallet or ticket private keys in coordinator storage. The coordinator's `--rpc-url` is its trusted ticket-expiry clock and must point to a monitored Solana RPC for the intended cluster. Ticket admission returns HTTP 503 rather than trusting callers when that RPC is unavailable. SIGINT/SIGTERM drains the server. Restore by reopening the WAL database; root and release rows are idempotent and conflict-detecting.

For incident response, activate emergency stop/pause at the policy layer, cancel active rounds where valid, retain sanitized event hashes, and do not publish raw databases/logs. Public execution requires a non-default compile feature, explicit acknowledgement, simulation, confirmation, and a spend budget; it is excluded from canonical evidence.
