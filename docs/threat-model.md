# Threat model

Observers include passive chain analysts, RPC providers, coordinator operators, compromised coordinators, timing/fee/instruction/funding analysts, and longitudinal observers. Active threats include malicious/Sybil participants, dropouts, release manipulation, denial of service, ticket spam, database compromise, and local wallet compromise.

Synchronization attempts to make timing and declared shapes less unique. Merkle aggregation attempts to reduce premature public membership exposure. Public transactions, funding graphs, fees, account age, recipients, action uniqueness, and repeated behavior remain visible. A compromised local wallet defeats participant control. Rate/body/count bounds address resource abuse but cannot stop well-funded Sybils. This is neither fund mixing nor proof of unlinkability.
