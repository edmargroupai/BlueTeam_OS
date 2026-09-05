# Canonical event schema

Version `1.0.0`. Required fields include `id`, `tenant_id`, `timestamp`, `ingested_at`, `source`, `source_type`, `event_type`, `category`, and `schema_version`. Source-specific data belongs in `attributes` and `raw_event`. The raw payload hash is stored and copied onto evidence objects.
