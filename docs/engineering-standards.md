# Engineering standards

- Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2
- Ruff + pytest in CI
- No secrets in source; use `.env.example` only
- Typed request/response models and a stable error envelope
- Request IDs on every response
- Append-only audit with a hash chain
- Detection rules: no network I/O; enrichment injected
- Tests must prove tenant isolation, detection correctness, and Blue Range assertions
