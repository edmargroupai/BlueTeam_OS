# C/C++ specialist boundary

C/C++ is permitted only for binary parsing, specialised packet/memory work, or required native libraries.

Prohibited:

- general backend services
- detection/correlation reasoning
- orchestration
- unauthenticated network listeners

Prefer Rust when a memory-safe implementation is viable. Any future native parser must expose a narrow ABI, run sanitizers, and be fuzzed.
