# ssl-agent

SSL/TLS visibility extender — a Go binary that runs on customer servers to see and fix the cert problems your CDN hides. It extends external monitoring with origin-level TLS configuration drift detection, local certificate health checks, and automated cert installation where ACME doesn't reach.

## Architecture

```
cmd/ssl-agent/main.go          CLI entry point
internal/
  agent/                        Core daemon loop, config, registration
  commands/                     Command registry and handlers
  httpclient/                   HTTP client for backend API communication
  security/                     HMAC-SHA256 signature verification, nonce store
  platform/                     OS, runtime, and port detection
  webserver/                    Nginx and Apache detection & management
  certs/                        Certificate scanning
scripts/install.sh              Production bootstrapper (POSIX sh)
scripts/install.py              Test-only OS prerequisite installer (deprecated)
docker-test/                    Multi-distro test Dockerfiles
```

## Prerequisites

- **Go 1.26.1+** (for building from source)
- **Supported OS:** Ubuntu 20/22/24, Debian 11/12, CentOS 7/8, RHEL, AlmaLinux, Rocky Linux
- **Supported web servers:** Nginx, Apache2
- **Outbound HTTPS** (port 443) to reach the backend API

## Building

```bash
make build    # Build binary to bin/ssl-agent (CGO_ENABLED=0, static)
make test     # Run tests with race detector
make lint     # Run golangci-lint
make clean    # Remove bin/
```

The build embeds the git version tag via `-ldflags` into the binary. Build
artifacts (`bin/`, and the compiled binaries under `docker-test/`) are
git-ignored — run `make build` to (re)generate `bin/ssl-agent` locally.

### Docker

A multi-stage `Dockerfile` produces a minimal Alpine image:

```bash
docker build -t quietls/agent:local --build-arg VERSION=dev .
docker run --rm quietls/agent:local --version
docker run --rm quietls/agent:local status
```

Prebuilt multi-arch images (`linux/amd64`, `linux/arm64`) are published to
Docker Hub as [`quietls/agent`](https://hub.docker.com/r/quietls/agent):

```bash
docker run --rm quietls/agent:latest --help
```

## Installation (Production)

The bootstrapper script automates the full installation:

```bash
SSL_AGENT_TOKEN=<token> wget -qO- https://quietls.com/v1/agents/install | sh
```

This will:
1. Detect OS, architecture, and init system
2. Download the correct pre-built binary from GitHub Releases
3. Verify SHA256 checksum
4. Place binary at `/usr/local/bin/ssl-agent`
5. Register with the backend using the provided token
6. Save config to `/etc/ssl-agent/config.json`
7. Install and start a systemd service

## CLI Commands

```
ssl-agent <command> [options]
```

| Command   | Description                          |
|-----------|--------------------------------------|
| `setup`   | Register this agent with the backend |
| `daemon`  | Start the polling daemon             |
| `status`  | Show agent and server status         |
| `renew`   | Renew certificates (not yet implemented) |

### Global Options

| Flag               | Env Var           | Default                         | Description       |
|--------------------|-------------------|---------------------------------|-------------------|
| `--token`, `-t`    | `SSL_AGENT_TOKEN` | —                               | API token         |
| `--base-url`       | —                 | `https://quietls.com/v1`    | Backend URL       |
| `--config`         | —                 | `/etc/ssl-agent/config.json`    | Config file path  |
| `--version`, `-v`  | —                 | —                               | Show version      |
| `--help`, `-h`     | —                 | —                               | Show help         |

### Setup

Register the agent with the backend. Detects the server platform (OS, web server, runtime) and sends context to the API.

```bash
ssl-agent setup --token <token>
ssl-agent setup --token <token> --base-url https://custom-api.example.com/v1
```

### Daemon

Start the persistent polling loop. Requires a valid config file (created by `setup`).

```bash
ssl-agent daemon
ssl-agent daemon --config /path/to/config.json
```

### Status

Display local agent and server information (no API call required).

```bash
ssl-agent status
```

Output example:
```
Agent ID: ag_abc123
Backend:  https://quietls.com/v1

OS:       Ubuntu 22.04 (x86_64)
Runtime:  host
Web Server: nginx 1.24.0 (3 vhosts)
Port 80:  true
Port 443: true
```

## Configuration

Stored at `/etc/ssl-agent/config.json` with restricted permissions (`0600`).

```json
{
  "agent_id": "ag_abc123",
  "agent_token": "tok_...",
  "agent_secret": "sec_...",
  "base_url": "https://quietls.com/v1",
  "platform_profile": "ubuntu-nginx",
  "poll_interval": 30
}
```

| Field              | Type     | Description                                |
|--------------------|----------|--------------------------------------------|
| `agent_id`         | string   | Unique agent identifier (assigned by backend) |
| `agent_token`      | string   | Bearer token for API authentication        |
| `agent_secret`     | string   | HMAC shared secret for command verification |
| `base_url`         | string   | Backend API base URL                       |
| `platform_profile` | string?  | Detected platform profile (e.g. `ubuntu-nginx`) |
| `poll_interval`    | int      | Command queue poll interval in seconds     |

## Daemon Behavior

The daemon runs two concurrent loops:

**Command polling** (every 30s):
1. `GET /agents/{id}/commands` — fetch pending commands
2. Verify HMAC signature, timestamp, and nonce for each command
3. Execute via the command registry
4. `POST /agents/{id}/results` — report execution result

**Heartbeat** (every 60s):
- `POST /agents/{id}/heartbeat` — send uptime, version, platform profile, system metrics

On poll errors, the daemon uses exponential backoff (30s base, 5min max). Graceful shutdown on `SIGTERM`/`SIGINT`.

## Command Registry

Only predefined commands are accepted — no arbitrary shell execution.

| Command ID                   | Description                                          |
|------------------------------|------------------------------------------------------|
| `cert.scan`                  | Scan installed SSL certificates                       |
| `cert.install`               | Install certificate + key to Nginx/Apache, reload     |
| `webserver.detect`           | Detect web server type, version, vhosts              |
| `webserver.reload`           | Reload nginx or apache configuration                 |
| `webserver.config.validate`  | Validate nginx or apache configuration               |
| `agent.status`               | Collect full server context (OS, web server, certs)  |
| `diag.connectivity`           | Check backend API reachability                       |
| `metric.tls-drift`           | Detect TLS config changes vs baseline                |
| `metric.cert-local`          | Check local certificate expiry and validity          |

## API Endpoints

All authenticated requests include `Authorization: Bearer <token>` and `X-Agent-ID` headers.

| Method | Endpoint                     | Auth | Description                  |
|--------|------------------------------|------|------------------------------|
| POST   | `/agents/register`           | No   | Register new agent           |
| GET    | `/agents/{id}/commands`      | Yes  | Poll command queue           |
| POST   | `/agents/{id}/results`       | Yes  | Report command result        |
| POST   | `/agents/{id}/heartbeat`     | Yes  | Send heartbeat               |
| POST   | `/agents/{id}/context`       | Yes  | Send full server context     |
| GET    | `/agents/{id}/config`        | Yes  | Fetch agent configuration    |

## Security

- **Allowlist-only execution** — only registered command IDs in the compiled registry are accepted
- **HMAC-SHA256 signing** — every command from the backend is signed; the agent verifies the signature using a shared secret before execution
- **Timestamp validation** — commands with stale timestamps are rejected
- **Nonce replay protection** — LRU nonce store (10,000 entries) prevents command replay
- **Timing-safe comparison** — signature verification uses `crypto/subtle.ConstantTimeCompare`
- **Dedicated system user** — runs as low-privilege `ssl-agent` user (`nologin` shell)
- **Restricted config permissions** — config file written with `0600`, directory with `0700`

## Docker Support

The agent detects Docker runtime by checking for `/.dockerenv`. In Docker environments, the agent runs as a sidecar container alongside the web server. Certificates are shared via a named Docker volume.

The published `quietls/agent` image sets `ssl-agent` as its entrypoint, so any
CLI invocation works directly:

```bash
docker run --rm \
  -e SSL_AGENT_TOKEN=<token> \
  -v ssl-agent-config:/etc/ssl-agent \
  quietls/agent:latest setup
```

## Systemd Service

Example unit file for production:

```ini
[Unit]
Description=SSL Agent Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ssl-agent
ExecStart=/usr/local/bin/ssl-agent daemon
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Development

### Running Tests

```bash
make test
```

The test suite uses dependency injection (`Executor`, `FileIO` interfaces) for mocking OS operations.

### Docker Test Matrix

The `docker-test/` directory contains Dockerfiles for testing detection across distributions:

- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- CentOS 7, 8

Run the detection test suite:

```bash
./docker-test/run-detection-test.sh
```

## Continuous Integration & Releases

Two GitHub Actions workflows live in `.github/workflows/`:

- **`tests.yml`** — runs `go test ./...` on every push and pull request.
- **`docker-publish.yml`** — on a `v*` git tag, builds the multi-arch image and
  pushes it to Docker Hub as `quietls/agent` (semver tags + `latest`).

Cutting a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The publish workflow requires two repository secrets:

| Secret               | Purpose                                             |
|----------------------|-----------------------------------------------------|
| `DOCKERHUB_USERNAME` | Docker Hub account/org with push access to the image |
| `DOCKERHUB_TOKEN`    | Docker Hub access token (Account Settings → Security) |

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
