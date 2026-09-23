# RepoJail

Disposable coding-agent workspaces with TTL cleanup, command policy, bounded output, workspace quotas, immutable-style hash-chained audit logs, a local HTTP API, CLI, and operational dashboard.

Watermark: `":"`

## Runtime

RepoJail selects the strongest available local execution mode:

- `bubblewrap`: Linux namespaces + filesystem remount + optional network namespace.
- `proot-prefix`: Termux-compatible disposable filesystem view rooted at `$PREFIX`, with the workspace mounted at `/workspace`.
- `direct-explicit`: disabled by default; only enabled with `REPOJAIL_ALLOW_DIRECT=1`.

The workspace is disposable in every mode. Network blocking is enforced by the `bubblewrap` mode. The API reports the active mode and whether network isolation was enforced for each command.

## One launch

```bash
./bootstrap.sh
```

Default dashboard: `http://127.0.0.1:8791`

Build without launching:

```bash
./bootstrap.sh build
```

## CLI

```bash
./bin/repojail doctor
./bin/repojail create --repo https://github.com/org/repo.git --ref main --ttl 1800
./bin/repojail list
./bin/repojail exec <id> -- git status
./bin/repojail destroy <id>
```

## API

- `GET /healthz`
- `GET /api/v1/status`
- `GET /api/v1/jails`
- `POST /api/v1/jails`
- `GET /api/v1/jails/:id`
- `DELETE /api/v1/jails/:id`
- `POST /api/v1/jails/:id/exec`
- `GET /api/v1/jails/:id/events`

Set `REPOJAIL_TOKEN` to require `Authorization: Bearer ...` on `/api/v1/*`.

## Filesystem

Jails live under `${REPOJAIL_ROOT:-$HOME/.local/share/repojail/jails}`. Each jail contains `.repojail/meta.json`, `.repojail/audit.jsonl`, and `.repojail/tmp`.

## Verification

```bash
go test ./...
go vet ./...
go build ./cmd/repojail
```

Owner: Julius Cameron Hill / Titan Universal AI LLC
