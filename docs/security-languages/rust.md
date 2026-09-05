# Rust

Why: memory-safe, high-throughput sensors and parsers.

Allowed: endpoint/network sensors, binary-safe parsers, PCAP preprocess, local collectors.

Prohibited: detection reasoning, RBAC, incident decisions, AI calls.

Contract: `blueteam-event-model` emits CanonicalEvent JSON. Python ingests it.

Testing: `cargo test`. If rustc is absent, CI reports SKIPPED_WITH_REASON.
