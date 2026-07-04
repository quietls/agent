#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
FAILED_DISTROS=()

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local msg="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo -e "${GREEN}PASS${NC}: $msg"
        ((PASS+=1))
    else
        echo -e "${RED}FAIL${NC}: $msg"
        echo "  Expected to contain: $needle"
        echo "  Got: $haystack"
        ((FAIL+=1))
    fi
}

assert_file_exists() {
    local path="$1"
    local msg="$2"
    if [ -f "$path" ]; then
        echo -e "${GREEN}PASS${NC}: $msg"
        ((PASS+=1))
    else
        echo -e "${RED}FAIL${NC}: $msg"
        echo "  File not found: $path"
        ((FAIL+=1))
    fi
}

assert_json_field() {
    local file="$1"
    local field="$2"
    local msg="$3"
    if grep -q "\"${field}\"" "$file" 2>/dev/null; then
        echo -e "${GREEN}PASS${NC}: $msg"
        ((PASS+=1))
    else
        echo -e "${RED}FAIL${NC}: $msg"
        echo "  Field '$field' missing or empty in $file"
        ((FAIL+=1))
    fi
}

AGENT_BIN="/usr/local/bin/ssl-agent"

# Mock backend is plain HTTP on localhost — allow the agent to talk to it.
export SSL_AGENT_INSECURE_DEV=1

# ── Validate pre-built binary exists ────────────────────────
if [ ! -f "$AGENT_BIN" ]; then
    echo -e "${RED}ERROR${NC}: Agent binary not found at $AGENT_BIN"
    exit 1
fi

# ── Start mock backend ──────────────────────────────────────
echo "=== Starting mock backend ==="
/usr/local/bin/mock-backend &
MOCK_PID=$!
sleep 1

# Wait for mock backend
for i in {1..10}; do
    if curl -sf http://localhost:8080/health >/dev/null 2>&1; then
        echo "Mock backend is ready"
        break
    fi
    sleep 1
done

# ── Test 1: ssl-agent status (unregistered) ─────────────────
echo "=== Test: ssl-agent status (unregistered) ==="
STATUS_OUTPUT=$($AGENT_BIN status 2>&1 || true)
echo "$STATUS_OUTPUT"
assert_contains "$STATUS_OUTPUT" "not registered" "status shows unregistered"

# ── Test 2: ssl-agent setup ────────────────────────────────
echo "=== Test: ssl-agent setup ==="
$AGENT_BIN setup --token fake-token --base-url http://localhost:8080/v1 --config /tmp/ssl-agent-config.json 2>&1 || true

assert_file_exists "/tmp/ssl-agent-config.json" "config file created"
assert_json_field "/tmp/ssl-agent-config.json" "agent_id" "config has agent_id"
assert_json_field "/tmp/ssl-agent-config.json" "agent_token" "config has agent_token"
assert_json_field "/tmp/ssl-agent-config.json" "agent_secret" "config has agent_secret"

# ── Test 3: ssl-agent status (registered) ────────────────────
echo "=== Test: ssl-agent status (registered) ==="
STATUS_OUTPUT=$($AGENT_BIN status --config /tmp/ssl-agent-config.json 2>&1 || true)
echo "$STATUS_OUTPUT"

# The distro name should appear in output (e.g., Ubuntu, Debian, CentOS, Rocky)
assert_contains "$STATUS_OUTPUT" "OS:" "status shows OS"
# Use regex-like pattern matching for Runtime line (handles double spaces)
if echo "$STATUS_OUTPUT" | grep -q "Runtime:"; then
    echo -e "${GREEN}PASS${NC}: status shows runtime"
    ((PASS+=1))
else
    echo -e "${RED}FAIL${NC}: status shows runtime"
    ((FAIL+=1))
fi

# ── Test 4: ssl-agent daemon polling ───────────────────────
echo "=== Test: ssl-agent daemon polling ==="
$AGENT_BIN daemon --config /tmp/ssl-agent-config.json &
DAEMON_PID=$!
sleep 3

# Confirm daemon is running
if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo -e "${GREEN}PASS${NC}: daemon is running"
    ((PASS+=1))
else
    echo -e "${RED}FAIL${NC}: daemon failed to start"
    ((FAIL+=1))
fi

# ── Test 5: Queue and execute commands ──────────────────────
AGENT_ID=$(python3 -c "import json; print(json.load(open('/tmp/ssl-agent-config.json'))['agent_id'])")

# Queue webserver.detect
echo "=== Test: webserver.detect command ==="
curl -sf -X POST http://localhost:8080/agents/${AGENT_ID}/queue/webserver.detect >/dev/null
sleep 8

# Queue cert.scan
echo "=== Test: cert.scan command ==="
curl -sf -X POST http://localhost:8080/agents/${AGENT_ID}/queue/cert.scan >/dev/null
sleep 8

# Queue metric.cert-local
echo "=== Test: metric.cert-local command ==="
curl -sf -X POST http://localhost:8080/agents/${AGENT_ID}/queue/metric.cert-local \
    -H "Content-Type: application/json" \
    -d '{"domain":"nother.one"}' >/dev/null
sleep 8

# ── Stop daemon ─────────────────────────────────────────────
echo "=== Stopping daemon ==="
kill -TERM "$DAEMON_PID" || true
sleep 1

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Failed: ${RED}$FAIL${NC}"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0

