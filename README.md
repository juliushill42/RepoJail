# RepoJail

Disposable coding-agent workspaces with TTL cleanup, command policy, bounded output, workspace quotas, hash-chained audit records, a local HTTP API, CLI, and operational dashboard.

## Execution modes

RepoJail selects the strongest local mode available.

### `bubblewrap`

Linux namespace isolation with filesystem remounting and optional network namespace isolation.

### `proot-prefix`

Termux-compatible disposable filesystem view rooted at `$PREFIX`, with the jail workspace mounted at `/workspace`.

### `direct-explicit`

Disabled by default. It is available only when:

```bash
export REPOJAIL_ALLOW_DIRECT=1
```

The API records the active execution mode and whether network isolation was enforced for each command.

## Default policy

The shipped policy sets:

```text
default TTL          1800 seconds
maximum TTL          21600 seconds
command timeout       900 seconds
maximum output          2 MiB
maximum workspace        2 GiB
network default        disabled
```

The command allowlist includes common Git, Go, Rust, Python, Node, Java, native-build, shell, and file utilities.

## One launch

```bash
./bootstrap.sh
```

The bootstrap:

1. Installs missing Termux dependencies when running inside Termux.
2. Runs `go test ./...`.
3. Runs `go vet ./...`.
4. Builds `bin/repojail`.
5. Loads the default policy/root/address.
6. Starts the service.

Default dashboard/API bind:

```text
http://127.0.0.1:8791
```

Build without launching:

```bash
./bootstrap.sh build
```

## CLI

```bash
./bin/repojail doctor

./bin/repojail create \
  --repo https://github.com/org/repo.git \
  --ref main \
  --ttl 1800

./bin/repojail list
./bin/repojail exec <id> -- git status
./bin/repojail destroy <id>
```

## API

```text
GET    /healthz
GET    /api/v1/status
GET    /api/v1/jails
POST   /api/v1/jails
GET    /api/v1/jails/:id
DELETE /api/v1/jails/:id
POST   /api/v1/jails/:id/exec
GET    /api/v1/jails/:id/events
```

Set `REPOJAIL_TOKEN` to require:

```text
Authorization: Bearer <token>
```

for `/api/v1/*`.

## Filesystem

Jails live under:

```text
${REPOJAIL_ROOT:-$HOME/.local/share/repojail/jails}
```

Each jail contains:

```text
.repojail/meta.json
.repojail/audit.jsonl
.repojail/tmp
```

## Verification

```bash
go test ./...
go vet ./...
go build ./cmd/repojail
```

## Repository layout

```text
cmd/          CLI/service entrypoint
internal/     jail lifecycle, execution, policy, audit logic
config/       runtime policy
scripts/      operational helpers
bootstrap.sh  build/verify/launch
```

## Ownership

Owner: Julius Cameron Hill / Titan Universal AI LLC  
Watermark: `":"`
