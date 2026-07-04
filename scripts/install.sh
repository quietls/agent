#!/bin/sh
# ssl-agent bootstrapper — installs and registers the SSL agent
#
# Usage (production):
#   SSL_AGENT_TOKEN=<token> curl -sSL https://api.quietls.com/v1/agents/install | sh
#
# Environment variables:
#   SSL_AGENT_TOKEN          (required) Setup token from the dashboard
#   SSL_AGENT_BASE_URL       (optional) Backend API URL (default: https://api.quietls.com/v1)
#   SSL_AGENT_VERSION        (optional) Version tag to install (default: latest)
#   SSL_AGENT_SKIP_SIGNATURE (optional) Skip minisign verification when the backend
#                            does not yet publish signatures (not recommended for prod)
#
# Production hardening:
#   Set MINISIGN_PUBLIC_KEY to the minisign public key used to sign release binaries.
#   The installer will download ${API_BASE_URL}/agents/download/${ARCH}.minisig and
#   verify the binary before installation. Until signatures are published, set
#   SSL_AGENT_SKIP_SIGNATURE=1 only in test environments.
#
set -eu

# ── Configuration ────────────────────────────────────────────────

API_BASE_URL="${SSL_AGENT_BASE_URL:-https://api.quietls.com/v1}"
TOKEN="${SSL_AGENT_TOKEN:-}"
VERSION="${SSL_AGENT_VERSION:-latest}"
BINARY_PATH="/usr/local/bin/ssl-agent"
CONFIG_DIR="/etc/ssl-agent"
CONFIG_PATH="${CONFIG_DIR}/config.json"
SERVICE_NAME="ssl-agent"

# Set this to the production minisign public key before deploying to production.
# Example: MINISIGN_PUBLIC_KEY="RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaHD73jmdG"
MINISIGN_PUBLIC_KEY="${MINISIGN_PUBLIC_KEY:-}"

TMPFILE=""
CHECKSUM_FILE=""
SIG_FILE=""

# ── Helpers ───────────────────────────────────────────────────────

log()  { printf "[ssl-agent] %s\n" "$1"; }
warn() { printf "[ssl-agent] WARNING: %s\n" "$1" >&2; }
err()  { printf "[ssl-agent] ERROR: %s\n" "$1" >&2; exit 1; }

cleanup() {
    rm -f "$TMPFILE" "$CHECKSUM_FILE" "$SIG_FILE"
}
trap cleanup EXIT

require_cmd() {
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || err "Required command not found: $cmd"
    done
}

# ── Step 1: Detect OS ─────────────────────────────────────────────

detect_os() {
    if [ ! -f /etc/os-release ]; then
        err "Cannot detect OS: /etc/os-release not found"
    fi

    # shellcheck disable=SC1091
    . /etc/os-release

    DISTRO="${ID}"
    VERSION_ID="${VERSION_ID}"
    FAMILY=""

    case "$DISTRO" in
        ubuntu|debian)        FAMILY="debian" ;;
        centos|rhel|almalinux|rocky) FAMILY="rhel" ;;
        *) err "Unsupported OS: ${DISTRO}" ;;
    esac

    log "Detected OS: ${DISTRO} ${VERSION_ID} (${FAMILY})"
}

# ── Step 2: Detect architecture ───────────────────────────────────

detect_arch() {
    ARCH=""
    case "$(uname -m)" in
        x86_64)   ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)        err "Unsupported architecture: $(uname -m)" ;;
    esac
    log "Detected architecture: ${ARCH}"
}

# ── Step 3: Detect init system ────────────────────────────────────

detect_init() {
    if pidof systemd >/dev/null 2>&1 || [ -d /run/systemd/system ]; then
        INIT="systemd"
    else
        INIT="unknown"
        log "WARNING: Only systemd is supported in MVP. Service will not be auto-installed."
    fi
}

# ── Step 4: Resolve version ──────────────────────────────────────

resolve_version() {
    if [ "$VERSION" = "latest" ]; then
        log "Resolving latest version..."
        TAG=$(curl -sSL "${API_BASE_URL}/agents/version" | grep -o '"version":"[^"]*"' | head -1 | sed 's/"version":"//;s/"//')
        if [ -z "$TAG" ]; then
            err "Failed to resolve latest version from API"
        fi
        log "Latest version: ${TAG}"
    else
        TAG="$VERSION"
        log "Using pinned version: ${TAG}"
    fi
}

# ── Step 5: Download binary ──────────────────────────────────────

download_binary() {
    BINARY_URL="${API_BASE_URL}/agents/download/${ARCH}"
    TMPFILE=$(mktemp)

    log "Downloading ssl-agent ${TAG} (${ARCH})..."
    if ! curl -fSL --retry 1 -o "$TMPFILE" "$BINARY_URL"; then
        err "Failed to download binary from ${BINARY_URL}"
    fi
}

# ── Step 6: Verify SHA256 checksum ──────────────────────────────

verify_checksum() {
    CHECKSUM_URL="${API_BASE_URL}/agents/checksums"
    CHECKSUM_FILE=$(mktemp)

    log "Verifying checksum..."
    if ! curl -fSL -o "$CHECKSUM_FILE" "$CHECKSUM_URL"; then
        err "Failed to download checksums from ${CHECKSUM_URL}"
    fi

    BINARY_NAME="ssl-agent-${ARCH}"
    EXPECTED=$(grep "  ${BINARY_NAME}$" "$CHECKSUM_FILE" | awk '{print $1}')

    if [ -z "$EXPECTED" ]; then
        err "Checksum for ${BINARY_NAME} not found in checksums file"
    fi

    ACTUAL=$(sha256sum "$TMPFILE" | awk '{print $1}')

    if [ "$EXPECTED" != "$ACTUAL" ]; then
        err "Checksum mismatch: expected ${EXPECTED}, got ${ACTUAL}"
    fi

    log "Checksum verified"
}

# ── Step 6b: Verify binary signature (minisign) ─────────────────

verify_signature() {
    if [ -z "$MINISIGN_PUBLIC_KEY" ]; then
        warn "MINISIGN_PUBLIC_KEY is not set; signature verification is disabled."
        warn "For production, set MINISIGN_PUBLIC_KEY and publish ${API_BASE_URL}/agents/download/${ARCH}.minisig."
        if [ "${SSL_AGENT_SKIP_SIGNATURE:-}" = "1" ]; then
            warn "Skipping signature verification (SSL_AGENT_SKIP_SIGNATURE=1)."
        fi
        return 0
    fi

    require_cmd minisign

    SIG_URL="${API_BASE_URL}/agents/download/${ARCH}.minisig"
    SIG_FILE=$(mktemp)

    log "Downloading signature..."
    if ! curl -fSL -o "$SIG_FILE" "$SIG_URL"; then
        err "Failed to download signature from ${SIG_URL}. Set SSL_AGENT_SKIP_SIGNATURE=1 to skip only in test environments."
    fi

    log "Verifying binary signature..."
    if ! minisign -V -m "$TMPFILE" -x "$SIG_FILE" -P "$MINISIGN_PUBLIC_KEY"; then
        err "Signature verification failed. The binary may have been tampered with."
    fi

    log "Signature verified"
}

# ── Step 7: Install binary ──────────────────────────────────────

install_binary() {
    log "Installing binary to ${BINARY_PATH}..."
    install -m 755 "$TMPFILE" "$BINARY_PATH"
    log "ssl-agent installed: $("${BINARY_PATH}" --version 2>/dev/null || echo "unknown")"
}

# ── Step 8: Create system user ───────────────────────────────────

create_user() {
    if id "$SERVICE_NAME" >/dev/null 2>&1; then
        log "User ${SERVICE_NAME} already exists, skipping"
    else
        log "Creating system user ${SERVICE_NAME}..."
        if [ "$FAMILY" = "debian" ]; then
            useradd -r -M -s /usr/sbin/nologin "$SERVICE_NAME"
        else
            useradd -r -M -s /sbin/nologin "$SERVICE_NAME"
        fi
    fi
}

# ── Step 9: Create config directory ─────────────────────────────

create_config_dir() {
    mkdir -p "$CONFIG_DIR"
    chmod 0700 "$CONFIG_DIR"
    chown "$SERVICE_NAME:$SERVICE_NAME" "$CONFIG_DIR" 2>/dev/null || true
    log "Config directory ready: ${CONFIG_DIR}"
}

# ── Step 10: Run setup ──────────────────────────────────────────

run_setup() {
    if [ -f "$CONFIG_PATH" ]; then
        log "Config already exists at ${CONFIG_PATH}, skipping setup"
        return 0
    fi

    log "Registering agent with backend..."
    SSL_AGENT_TOKEN="$TOKEN" "$BINARY_PATH" setup --base-url "$API_BASE_URL" || {
        err "Agent setup failed. Check that your SSL_AGENT_TOKEN is valid and the backend is reachable."
    }
    log "Agent registered successfully"

    # Ensure config file has correct ownership
    chown "$SERVICE_NAME:$SERVICE_NAME" "$CONFIG_PATH" 2>/dev/null || true
    chmod 0600 "$CONFIG_PATH"
}

# ── Step 11: Install systemd service ────────────────────────────

install_service() {
    if [ "$INIT" != "systemd" ]; then
        log "Skipping service installation (init system: ${INIT})"
        return 0
    fi

    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

    log "Installing systemd service..."
    cat > "$SERVICE_FILE" <<'SERVICEEOF'
[Unit]
Description=SSL Agent Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ssl-agent
Group=ssl-agent
ExecStart=/usr/local/bin/ssl-agent daemon
Restart=on-failure
RestartSec=10

# Sandboxing
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/etc/ssl-agent /etc/nginx/ssl /etc/apache2/ssl /etc/httpd/conf.d
CapabilityBoundingSet=
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
SERVICEEOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    log "Systemd service installed and enabled"
}

# ── Step 12: Start daemon ──────────────────────────────────────

start_daemon() {
    if [ "$INIT" != "systemd" ]; then
        log "Manual start required (init system: ${INIT}):"
        log "  ${BINARY_PATH} daemon"
        return 0
    fi

    log "Starting ${SERVICE_NAME} daemon..."
    systemctl start "$SERVICE_NAME"

    # Wait briefly and check status
    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Daemon started successfully"
    else
        log "WARNING: Daemon may not have started. Check with: systemctl status ${SERVICE_NAME}"
    fi
}

# ── Main ────────────────────────────────────────────────────────

main() {
    log "=== ssl-agent bootstrapper ==="

    [ -z "$TOKEN" ] && err "SSL_AGENT_TOKEN is required. Usage: SSL_AGENT_TOKEN=<token> curl -sSL <url> | sh"

    require_cmd curl
    require_cmd sha256sum

    log "[1/8] Detecting OS..."
    detect_os

    log "[2/8] Detecting architecture..."
    detect_arch

    detect_init

    log "[3/8] Resolving version..."
    resolve_version

    log "[4/8] Downloading binary..."
    download_binary

    log "[5/8] Verifying checksum..."
    verify_checksum

    log "[5b/8] Verifying signature..."
    verify_signature

    log "[6/8] Installing binary..."
    install_binary

    log "[7/8] Setting up agent..."
    create_user
    create_config_dir
    run_setup
    install_service

    log "[8/8] Starting daemon..."
    start_daemon

    log "=== Installation complete ==="
}

main "$@"