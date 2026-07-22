# Adding a safe action template

Implement `ActionTemplateDriver` in `mirror-pool-actions`; give it a stable versioned ID, a fixed program allowlist, strict parameter/value/fee/size bounds, deterministic shape buckets, a local simulation path, safety classification, and a redacted fingerprint. Add it to the pool allowlist and test rejection at every boundary. Never accept raw instructions, generic CPI, unknown recipients, market manipulation, or participant signing material in the coordinator.
