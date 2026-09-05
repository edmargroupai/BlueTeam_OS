#!/usr/bin/env bash
# Version: 1.0.0
# Read-only process inventory. Invoked only by the Python execution broker.
set -euo pipefail
dry_run=0
limit=50
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --limit)
      limit="$2"
      shift 2
      ;;
    *) echo '{"error":"unsupported argument"}' >&2; exit 2 ;;
  esac
done
if ! [[ "$limit" =~ ^[0-9]+$ ]] || [ "$limit" -lt 1 ] || [ "$limit" -gt 500 ]; then
  echo '{"error":"limit out of range"}' >&2
  exit 2
fi
if [ "$dry_run" -eq 1 ]; then
  printf '{"action":"collect.linux.processes","dry_run":true,"limit":%s,"processes":[]}\n' "$limit"
  exit 0
fi
ps -eo pid,comm --no-headers | head -n "$limit" | awk 'BEGIN{print "["} {printf "%s{\"pid\":%s,\"comm\":\"%s\"}", sep,$1,$2; sep=","} END{print "]"}'
