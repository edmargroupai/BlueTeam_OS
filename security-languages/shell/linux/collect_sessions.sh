#!/usr/bin/env bash
# Version: 1.0.0
# Read-only session listing.
set -euo pipefail
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    *) echo '{"error":"unsupported argument"}' >&2; exit 2 ;;
  esac
done
if [ "$dry_run" -eq 1 ]; then
  printf '{"action":"collect.linux.sessions","dry_run":true,"sessions":[]}\n'
  exit 0
fi
who | awk 'BEGIN{print "["} {printf "%s{\"user\":\"%s\",\"tty\":\"%s\"}", sep,$1,$2; sep=","} END{print "]"}'
