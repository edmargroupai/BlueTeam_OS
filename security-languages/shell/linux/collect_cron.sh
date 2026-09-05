#!/usr/bin/env bash
# Version: 1.0.0
# Read-only current-user crontab. Invoked only by the Python execution broker.
set -euo pipefail
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    *) echo '{"error":"unsupported argument"}' >&2; exit 2 ;;
  esac
done
if [ "$dry_run" -eq 1 ]; then
  printf '{"action":"collect.linux.cron","dry_run":true,"entries":[]}\n'
  exit 0
fi
crontab -l 2>/dev/null | awk 'BEGIN{print "["} {gsub(/"/,"\\\""); printf "%s{\"line\":\"%s\"}", sep,$0; sep=","} END{print "]"}'
