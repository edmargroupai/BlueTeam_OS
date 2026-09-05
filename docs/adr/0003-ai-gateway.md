# ADR 0003 — AI last, gateway only, offline by default

Status: accepted

All model calls go through `services/ai-gateway`. Detection, correlation, scoring, and containment are deterministic-only. Provider outage must not affect those paths. AI claims must cite valid evidence IDs.
