# eBPF process probes

Feature-gated. The platform operates with `BTOS_EBPF_ENABLED=false`.

Intended path:

```text
Linux kernel probe → Rust/Go userspace collector → CanonicalEvent → Python engine
```

This directory holds probe specifications only. It is not a loaded kernel program.
A missing runtime must report `SKIPPED_WITH_REASON`, never a silent pass.
