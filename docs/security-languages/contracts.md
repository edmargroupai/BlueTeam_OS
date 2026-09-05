# Contracts

Version `1.0.0` lives in `security-languages/contracts`.

Languages emit CanonicalEvent 1.0.0. They do not invent private event models.

Actions must be pre-registered with the Python execution broker. `shell.exec` and `powershell.invoke_raw` are forbidden prefixes.

Evidence produced by any language must include collector identity, integrity hash, and provenance level.
