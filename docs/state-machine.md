# State machine and invariants

Every permitted edge is explicit in `RoundState::can_transition_to`; terminal states have no outgoing edge. Registration is state/time/maximum bounded. Sealing requires threshold and an unset root. Scheduling requires sealed state, an unset schedule, and checked min/max delay; its end uses checked addition. On-chain roots, windows, metrics, and separate transparent participant records are bounded.

Invalid transitions, expired or mismatched tickets, duplicate keys/commitments, excessive counts, root replacement, conflicting schedules, wrong proof roots/rounds, and arithmetic overflow fail closed.
