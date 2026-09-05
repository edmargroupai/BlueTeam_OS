#!/usr/bin/env bash
# Version: 1.0.0
# Read-only systemd unit list. Invoked only by the Python execution broker.
set -euo pipefail
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    *) echo '{"error":"unsupported argument"}' >&2; exit 2 ;;
  esac
done
if [ "$dry_run" -eq 1 ]; then
  printf '{"action":"collect.linux.systemd","dry_run":true,"units":[]}\n'
  exit 0
fi
systemctl list-units --type=service --no-pager --no-legend | head -n 50 | awk 'BEGIN{print "["} {printf "%s{\"unit\":\"%s\",\"state\":\"%s\"}", sep,$1,$4; sep=","} END{print "]"}'
