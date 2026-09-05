# Evidence provenance

Evidence objects record collector, timestamps, integrity hash, parser version, and transformation history. Claims that reference unknown IDs are rejected. Tampered event hashes fail `/api/v1/evidence/{id}/verify`.
