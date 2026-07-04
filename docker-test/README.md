# Agent Multi-Distro Docker Test Suite

This directory contains Dockerfiles and scripts for testing the `ssl-agent` Go binary across multiple Linux distributions in real container environments.

## What's Tested

For each supported distro, the test suite validates:

- **`ssl-agent status`** — OS detection, runtime detection, web server detection
- **`ssl-agent setup`** — Registration with a mock backend API, config persistence
- **`ssl-agent daemon`** — Polling loop, heartbeat, command execution
- **Command execution** — `webserver.detect`, `cert.scan`, `metric.cert-local`
- **Mock backend HMAC** — Command signatures verified end-to-end

## Supported Distributions

| Distro | Dockerfile | Base Image |
|--------|------------|------------|
| Ubuntu 20.04 | `Dockerfile.ubuntu20` | `ubuntu:20.04` |
| Ubuntu 22.04 | `Dockerfile.ubuntu22` | `ubuntu:22.04` |
| Ubuntu 24.04 | `Dockerfile.ubuntu24` | `ubuntu:24.04` |
| Debian 11 | `Dockerfile.debian11` | `debian:11` |
| Debian 12 | `Dockerfile.debian12` | `debian:12` |
| CentOS 7 | `Dockerfile.centos7` | `centos:7` |
| Rocky Linux 8 | `Dockerfile.centos8` | `rockylinux:8` |

## Quick Start

### Run the full matrix

```bash
cd apps/agent
make test-agent-docker
```

### Run specific distros

```bash
cd apps/agent/docker-test
./run-detection-test.sh ubuntu22 debian12
```

### Run via docker-compose

```bash
docker compose -f docker-compose.test-agent.yml build test-ubuntu22
docker compose -f docker-compose.test-agent.yml run --rm test-ubuntu22
```

## How It Works

1. **`make build`** compiles the `ssl-agent` binary.
2. **`mock-backend.go`** is compiled into a self-contained mock API server.
3. Each Dockerfile builds a container with:
   - The target distro + nginx + apache2
   - Dummy vhosts and self-signed SSL certificates
   - The mock backend and test runner (`entrypoint.sh`)
4. `entrypoint.sh` runs inside each container:
   - Starts the mock backend
   - Builds the agent from source
   - Runs `ssl-agent status`, `ssl-agent setup`, `ssl-agent daemon`
   - Queues commands via the mock backend's `/agents/{id}/queue/{command}` endpoint
   - Asserts outputs and exits with non-zero if any assertion fails
5. `run-detection-test.sh` orchestrates the builds and runs, printing a summary.

## Architecture

```
┌─────────────────────────────────────┐
│  Docker Container (e.g. Ubuntu 22)  │
│  ┌───────────────────────────────┐    │
│  │  Mock Backend (:8080)         │    │
│  │  - /agents/register           │    │
│  │  - /agents/{id}/commands      │    │
│  │  - /agents/{id}/results       │    │
│  └──────────────┬────────────────┘    │
│                 │ HTTP                │
│  ┌──────────────▼────────────────┐    │
│  │  ssl-agent daemon             │    │
│  │  - polls commands             │    │
│  │  - executes on real nginx/ssl │    │
│  └───────────────────────────────┘    │
└─────────────────────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `Dockerfile.*` | Distro-specific container definitions |
| `nginx.conf` | Dummy nginx vhost with SSL |
| `apache.conf` | Dummy Apache vhost with SSL |
| `mock-backend.go` | Self-contained mock QuietLS API |
| `entrypoint.sh` | Per-container test runner |
| `run-detection-test.sh` | Full matrix orchestrator |
| `README.md` | This file |

## Notes

- All tests are **self-contained** — no external API calls.
- The mock backend signs commands with HMAC-SHA256 exactly like the real backend.
- CentOS 7 uses `platform: linux/amd64` because it lacks ARM64 Docker images.
