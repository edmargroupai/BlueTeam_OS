$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = @(
    $root,
    "$root\packages\schemas",
    "$root\packages\python-common",
    "$root\packages\detection-sdk",
    "$root\packages\playbook-sdk",
    "$root\packages\quality-engine",
    "$root\packages\blue-range",
    "$root\services\api"
) -join ";"
python -m uvicorn app.main:app --app-dir "$root\services\api" --reload --host 127.0.0.1 --port 8080
