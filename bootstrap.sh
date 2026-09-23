#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ -d /data/data/com.termux/files/usr ]]; then
  export PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
  missing=()
  command -v git >/dev/null 2>&1 || missing+=(git)
  command -v go >/dev/null 2>&1 || missing+=(golang)
  command -v proot >/dev/null 2>&1 || missing+=(proot)
  command -v curl >/dev/null 2>&1 || missing+=(curl)
  if ((${#missing[@]})); then pkg install -y "${missing[@]}"; fi
fi

command -v go >/dev/null 2>&1 || { echo 'ERROR: Go 1.23+ is required.' >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo 'ERROR: git is required.' >&2; exit 1; }

go test ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o bin/repojail ./cmd/repojail

export REPOJAIL_POLICY="${REPOJAIL_POLICY:-$ROOT/config/policy.json}"
export REPOJAIL_ROOT="${REPOJAIL_ROOT:-$HOME/.local/share/repojail/jails}"
export REPOJAIL_ADDR="${REPOJAIL_ADDR:-127.0.0.1:8791}"

case "${1:-serve}" in
  build) printf 'BUILD PASS: %s/bin/repojail\n' "$ROOT" ;;
  test) go test ./... ;;
  doctor) exec "$ROOT/bin/repojail" doctor ;;
  serve) exec "$ROOT/bin/repojail" serve ;;
  *) exec "$ROOT/bin/repojail" "$@" ;;
esac
