#!/usr/bin/env bash
set -euo pipefail
BASE="${REPOJAIL_URL:-http://127.0.0.1:8791}"
AUTH=()
[[ -n "${REPOJAIL_TOKEN:-}" ]] && AUTH=(-H "Authorization: Bearer ${REPOJAIL_TOKEN}")
curl -fsS "${AUTH[@]}" "$BASE/healthz" >/dev/null
J="$(curl -fsS "${AUTH[@]}" -H 'content-type: application/json' -d '{"ttl_seconds":60}' "$BASE/api/v1/jails")"
ID="$(printf '%s' "$J" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
trap 'curl -fsS "${AUTH[@]}" -X DELETE "$BASE/api/v1/jails/$ID" >/dev/null 2>&1 || true' EXIT
curl -fsS "${AUTH[@]}" -H 'content-type: application/json' -d '{"argv":["git","--version"],"timeout_seconds":15}' "$BASE/api/v1/jails/$ID/exec" >/dev/null
printf 'RepoJail smoke PASS id=%s\n' "$ID"
