# Bash / POSIX

Why: Linux host inspection.

Allowed: read-only process/session/persistence collectors with `set -euo pipefail` and `--dry-run`.

Prohibited: eval, curl|sh, arbitrary command construction, LLM-direct execution.
