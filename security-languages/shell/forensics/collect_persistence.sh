#!/usr/bin/env bash
# Version: 1.0.0
# Read-only persistence locations. Never follows attacker-controlled paths.
set -euo pipefail
dry_run=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    *) echo '{"error":"unsupported argument"}' >&2; exit 2 ;;
  esac
done
if [ "$dry_run" -eq 1 ]; then
  printf '{"action":"collect.linux.persistence","dry_run":true,"paths":["/etc/crontab","/etc/cron.d"]}\n'
  exit 0
fi
printf '{"crontab_readable":%s}\n' "$( [ -r /etc/crontab ] && echo true || echo false )"
