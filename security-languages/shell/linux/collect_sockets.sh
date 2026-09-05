#!/usr/bin/env bash
# Version: 1.0.0
# Read-only listening sockets. Invoked only by the Python execution broker.
set -euo pipefail
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    *) echo '{"error":"unsupported argument"}' >&2; exit 2 ;;
  esac
done
if [ "$dry_run" -eq 1 ]; then
  printf '{"action":"collect.linux.sockets","dry_run":true,"sockets":[]}\n'
  exit 0
fi
ss -lntu 2>/dev/null | awk 'NR>1 {print $1,$5}' | head -n 50 | awk 'BEGIN{print "["} {printf "%s{\"proto\":\"%s\",\"local\":\"%s\"}", sep,$1,$2; sep=","} END{print "]"}'
