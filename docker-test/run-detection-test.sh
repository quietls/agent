#!/usr/bin/env bash
set -euo pipefail

# QuietLS Agent Multi-Distro Detection Test Orchestrator
# Usage: ./run-detection-test.sh [distro ...]
#   If no distros specified, tests all supported distros.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# docker-test/ lives directly under the agent module root, so the agent root is
# one level up from this script — works both in the monorepo and standalone.
AGENT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKER_DIR="${SCRIPT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ALL_DISTROS=(
    ubuntu20
    ubuntu22
    ubuntu24
    debian11
    debian12
    centos7
    centos8
)

PASS=0
FAIL=0
FAILED_DISTROS=()

echo "========================================"
echo "QuietLS Agent Multi-Distro Test Suite"
echo "========================================"
echo ""

# Determine which distros to test
if [ $# -gt 0 ]; then
    DISTROS=("$@")
else
    DISTROS=("${ALL_DISTROS[@]}")
fi

# ── Step 1: Build agent binary for linux/amd64 ────────────────
echo "Building ssl-agent binary (linux/amd64)..."
cd "${AGENT_ROOT}"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=test" \
    -o "${DOCKER_DIR}/ssl-agent-linux" \
    ./cmd/ssl-agent

# ── Step 2: Build mock backend for linux/amd64 ───────────────
echo "Building mock backend (linux/amd64)..."
cd "${DOCKER_DIR}"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
    -ldflags="-s -w" \
    -o mock-backend-linux \
    mock-backend.go

# ── Step 3: Run tests per distro ───────────────────────────────
for DISTRO in "${DISTROS[@]}"; do
    DOCKERFILE="${DOCKER_DIR}/Dockerfile.${DISTRO}"
    TAG="agent-test-${DISTRO}"

    echo ""
    echo "----------------------------------------"
    echo "Testing distro: ${DISTRO}"
    echo "----------------------------------------"

    if [ ! -f "${DOCKERFILE}" ]; then
        echo -e "${RED}SKIP${NC}: Dockerfile not found: ${DOCKERFILE}"
        continue
    fi

    # Build
    echo "  Building image ${TAG}..."
    if ! docker build \
        --file "${DOCKERFILE}" \
        --tag "${TAG}" \
        --platform linux/amd64 \
        "${DOCKER_DIR}" >/tmp/agent-test-build-${DISTRO}.log 2>&1; then
        echo -e "  ${RED}BUILD FAILED${NC}"
        cat /tmp/agent-test-build-${DISTRO}.log
        ((FAIL+=1))
        FAILED_DISTROS+=("${DISTRO}")
        continue
    fi

    # Run
    echo "  Running tests in ${TAG}..."
    if docker run --rm --platform linux/amd64 "${TAG}"; then
        echo -e "  ${GREEN}PASSED${NC}: ${DISTRO}"
        ((PASS+=1))
    else
        echo -e "  ${RED}FAILED${NC}: ${DISTRO}"
        ((FAIL+=1))
        FAILED_DISTROS+=("${DISTRO}")
    fi
done

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}${PASS}${NC}"
echo -e "Failed: ${RED}${FAIL}${NC}"

if [ "${#FAILED_DISTROS[@]}" -gt 0 ]; then
    echo ""
    echo "Failed distros:"
    for D in "${FAILED_DISTROS[@]}"; do
        echo "  - ${D}"
    done
    exit 1
fi

echo ""
echo "All tests passed!"
exit 0
