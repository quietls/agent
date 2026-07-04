#!/usr/bin/env python3
"""QuietLS SSL Agent — OS Prerequisite Installer (DEPRECATED for production).

NOTE: This script is for Docker test environments ONLY. Production agent
installation is handled by scripts/install.sh, which downloads the Go binary,
verifies its checksum, creates the system user, runs ssl-agent setup, installs
the systemd service, and starts the daemon.

This script only installs OS-level prerequisites (Node.js, nginx, openssl, etc.)
and is not needed for production deployments where the agent is a pre-built
Go binary.

Usage (test):
    python3 scripts/install.py --test
"""

import argparse
import os
import subprocess
import sys
import textwrap


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: str, **kwargs) -> subprocess.CompletedProcess:
    """Run a shell command, printing it first. Raises on failure."""
    print(f"  $ {cmd}", flush=True)
    # Keep shell features (pipes/redirection/globs) while avoiding shell=True.
    return subprocess.run(['/bin/bash', '-lc', cmd], shell=False, check=True, **kwargs)


def write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    print(f"  wrote {path}")


def detect_os() -> dict:
    """Parse /etc/os-release and return {id, version, family}."""
    info = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    key, _, val = line.strip().partition("=")
                    info[key] = val.strip('"')
    except FileNotFoundError:
        print("ERROR: /etc/os-release not found — unsupported OS")
        sys.exit(1)

    os_id = info.get("ID", "unknown").lower()
    version = info.get("VERSION_ID", "unknown")

    if os_id in ("ubuntu", "debian"):
        family = "debian"
    elif os_id in ("centos", "rhel", "almalinux", "rocky"):
        family = "rhel"
    else:
        print(f"ERROR: Unsupported OS: {os_id}")
        sys.exit(1)

    return {"id": os_id, "version": version, "family": family}


# ---------------------------------------------------------------------------
# Debian / Ubuntu
# ---------------------------------------------------------------------------

def install_debian() -> None:
    """Install prerequisites on Debian/Ubuntu via apt."""
    run("apt-get update")
    run("apt-get install -y curl ca-certificates gnupg openssl iproute2 nginx")
    install_nodejs_debian()


def install_nodejs_debian() -> None:
    """Install Node.js 20.x from NodeSource on Debian/Ubuntu."""
    run("mkdir -p /etc/apt/keyrings")
    run(
        "curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key"
        " | gpg --batch --dearmor -o /etc/apt/keyrings/nodesource.gpg"
    )
    run(
        'echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg]'
        ' https://deb.nodesource.com/node_20.x nodistro main"'
        " > /etc/apt/sources.list.d/nodesource.list"
    )
    run("apt-get update")
    run("apt-get install -y nodejs")


# ---------------------------------------------------------------------------
# CentOS / RHEL
# ---------------------------------------------------------------------------

def fix_centos7_mirrors() -> None:
    """Switch CentOS 7 repos to vault.centos.org (EOL mirrors)."""
    run(
        r"sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo"
    )
    run(
        r"sed -i 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g'"
        " /etc/yum.repos.d/CentOS-*.repo"
    )


def fix_centos8_mirrors() -> None:
    """Switch CentOS Stream 8 repos to vault.centos.org (EOL mirrors)."""
    run(
        r"sed -i 's|^mirrorlist=|#mirrorlist=|g'"
        " /etc/yum.repos.d/CentOS-Stream-*.repo"
    )
    run(
        r"sed -i 's|^#baseurl=http://mirror.centos.org/$contentdir/$stream"
        r"|baseurl=https://vault.centos.org/centos/8-stream|g'"
        " /etc/yum.repos.d/CentOS-Stream-*.repo"
    )


def install_centos7() -> None:
    """Install prerequisites on CentOS 7 via yum."""
    # Mirror fix may already be done in Dockerfile (needed for python3),
    # but running again is idempotent.
    fix_centos7_mirrors()
    run("yum install -y epel-release")
    run("yum install -y curl nginx openssl iproute")
    install_nodejs_centos7()


def install_nodejs_centos7() -> None:
    """Install Node.js 16.x on CentOS 7 (last version supporting glibc 2.17)."""
    run("curl -fsSL https://rpm.nodesource.com/setup_16.x | bash -")
    run("yum install -y nodejs")


def install_centos8() -> None:
    """Install prerequisites on CentOS Stream 8 via dnf."""
    # Mirror fix may already be done in Dockerfile, but idempotent.
    fix_centos8_mirrors()
    run("dnf install -y epel-release")
    run("dnf install -y curl nginx openssl iproute")
    install_nodejs_centos8()


def install_nodejs_centos8() -> None:
    """Install Node.js 20.x on CentOS Stream 8."""
    run("curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -")
    run("dnf install -y nodejs")


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

NGINX_VHOST_DEBIAN = textwrap.dedent("""\
    server {
        listen 80;
        server_name test.example.com;
        root /var/www/html;
    }

    server {
        listen 443 ssl;
        server_name test.example.com;
        ssl_certificate /etc/nginx/ssl/test.crt;
        ssl_certificate_key /etc/nginx/ssl/test.key;
        root /var/www/html;
    }
""")

NGINX_VHOST_RHEL = textwrap.dedent("""\
    server {
        listen 80;
        server_name test.example.com;
        root /usr/share/nginx/html;
    }

    server {
        listen 443 ssl;
        server_name test.example.com;
        ssl_certificate /etc/nginx/ssl/test.crt;
        ssl_certificate_key /etc/nginx/ssl/test.key;
        root /usr/share/nginx/html;
    }
""")


def setup_test_fixtures(os_family: str) -> None:
    """Create self-signed cert, vhost config, and start nginx for testing."""
    print("\n[test] Setting up test fixtures...", flush=True)

    # Self-signed certificate
    run("mkdir -p /etc/nginx/ssl")
    run(
        "openssl req -x509 -nodes -days 365 -newkey rsa:2048"
        " -keyout /etc/nginx/ssl/test.key -out /etc/nginx/ssl/test.crt"
        ' -subj "/CN=test.example.com"'
    )

    # Nginx vhost config
    if os_family == "debian":
        write_file("/etc/nginx/sites-enabled/test-vhost", NGINX_VHOST_DEBIAN)
    else:
        write_file("/etc/nginx/conf.d/test-vhost.conf", NGINX_VHOST_RHEL)

    # Start nginx
    run("nginx")
    print("[test] nginx started", flush=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="QuietLS SSL Agent — System Bootstrapper")
    parser.add_argument("--test", action="store_true", help="Also create test fixtures (certs, vhost, start nginx)")
    args = parser.parse_args()

    print("[1/3] Detecting OS...", flush=True)
    os_info = detect_os()
    print(f"  OS: {os_info['id']} {os_info['version']} (family: {os_info['family']})")

    print(f"\n[2/3] Installing packages for {os_info['id']} {os_info['version']}...", flush=True)
    if os_info["family"] == "debian":
        install_debian()
    elif os_info["id"] == "centos" and os_info["version"].startswith("7"):
        install_centos7()
    elif os_info["family"] == "rhel":
        install_centos8()

    print("\n[3/3] Verifying installation...", flush=True)
    run("node --version")
    run("nginx -v 2>&1")
    run("openssl version")

    if args.test:
        setup_test_fixtures(os_info["family"])

    print("\nBootstrap complete.", flush=True)


if __name__ == "__main__":
    main()
