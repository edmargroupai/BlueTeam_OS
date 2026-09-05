#!/usr/bin/env bash
# Version: 1.0.0
# Read-only SSH auth log tail. Invoked only by the Python execution broker.
set -euo pipefail
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    *) echo '{"error":"unsupported argument"}' >&2; exit 2 ;;
  esac
done
if [ "$dry_run" -eq 1 ]; then
  printf '{"action":"collect.linux.ssh","dry_run":true,"lines":[]}\n'
  exit 0
fi
if [ -r /var/log/auth.log ]; then
  tail -n 20 /var/log/auth.log | awk 'BEGIN{print "["} {gsub(/"/,"\\\""); printf "%s{\"line\":\"%s\"}", sep,$0; sep=","} END{print "]"}'
else
  printf '{"action":"collect.linux.ssh","dry_run":false,"skip_reason":"auth.log unreadable","lines":[]}\n'
fi
