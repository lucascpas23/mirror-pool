# Synchronization

Fixed slot is an experimental upper bound and sensitive to blockhash, leader, RPC, and latency variance. Narrow window is the robust default. Randomized-within-window derives an offset from participant-held ticket material; publishing offsets would defeat the purpose. Latency-aware mode compensates only within the configured window.

The round seed is reproducible, not claimed unpredictable. Coordinator seed selection and last-revealer behavior can bias timing. Execution spread, median/p95 deviation, dropouts, and trace hashes quantify rather than conceal these limitations.
