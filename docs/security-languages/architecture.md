# Polyglot security architecture

Python remains the only system that reasons about detections, correlation, risk, incidents, replay, and promotion.

```text
TypeScript presents
Python orchestrates and detects
Rust/Go/eBPF sense and collect
PowerShell/Bash collect Windows/Linux artefacts
SQL/BlueQL hunt
Sigma/YARA detect artefacts and tradecraft
Rego governs authority
C/C++ is specialist-only
```

A language folder is not a capability. Credit requires a contract, a test, and evidence flowing back to the canonical event or evidence model.
