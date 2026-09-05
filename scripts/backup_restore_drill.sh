#!/usr/bin/env bash
# Phase 29 — backup / restore drill for local compose dataplane.
set -euo pipefail
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=${1:-"./data/backups/$STAMP"}
mkdir -p "$OUT"
if [[ -d ./data ]]; then
  tar -czf "$OUT/data.tgz" ./data
fi
if [[ -f ./data/blueteam.db ]]; then
  cp ./data/blueteam.db "$OUT/blueteam.db"
fi
echo "backup written to $OUT"
echo "restore: tar -xzf $OUT/data.tgz && cp $OUT/blueteam.db ./data/blueteam.db"
