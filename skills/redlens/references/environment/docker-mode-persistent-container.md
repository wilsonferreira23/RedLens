# Docker Persistent Container

Use a named persistent container so installed tools remain available after `docker stop`.

## Quick Start

```bash
# Pull the official Kali Linux rolling image
docker pull kalilinux/kali-rolling

# Create a named persistent container if it does not already exist
docker ps -a --filter name=^/kali-pentest$ --format '{{.Names}}' | grep -qx kali-pentest || \
  docker run -d --name kali-pentest \
    -v "$(pwd)":/workspace \
    --network host \
    --privileged \
    kalilinux/kali-rolling sleep infinity

# Start it if it is stopped
docker ps --filter name=^/kali-pentest$ --filter status=running --format '{{.Names}}' | grep -qx kali-pentest || \
  docker start kali-pentest

# Install tools into the persistent container so they remain available next time
docker exec kali-pentest bash -c "apt-get update -qq && apt-get install -y nmap"

# Run tools inside the persistent container
docker exec kali-pentest nmap -sV 192.168.1.1

# Copy results out of the container
docker cp kali-pentest:/tmp/scan.xml ./scan.xml

# Stop when done; do not remove the container
docker stop kali-pentest
```

## Container Rules

> **Docker containers run as root.** `kalilinux/kali-rolling` uses root by default. `sudo` is not installed, so run commands directly.
>
> **Do not recreate an existing container.** Always check if `kali-pentest` already exists before running `docker run`. If the container exists but is stopped, use `docker start`.
>
> **Preserve artifacts before changing containers.** If a container was created with the wrong options, copy needed output files out before creating a corrected persistent container.

## Installing Tools

The base Kali Docker image is minimal. Install tools into the named persistent container with `docker exec`.

```bash
# Install a single tool
docker exec kali-pentest bash -c "apt-get update -qq && apt-get install -y nmap"

# Install a focused meta-package
docker exec kali-pentest bash -c "apt-get update -qq && apt-get install -y kali-tools-web"

# Install the full Kali toolset (large download, use selectively)
docker exec kali-pentest bash -c "apt-get update && apt-get install -y kali-linux-everything"
```

## CloakHQ/CloakBrowser (Stealth Browser — Required for CDN Bypass)

CloakBrowser is the standard browser automation tool for bypassing CDN JS challenges, Cloudflare Turnstile, and anti-bot protection. It replaces Puppeteer/Playwright entirely.

```bash
# Install CloakBrowser (Python) — the Chromium binary auto-downloads on first use
docker exec kali-pentest pip install -q cloakbrowser

# Verify installation (will auto-download stealth Chromium on first call)
docker exec kali-pentest python3 -c "from cloakbrowser import launch; print('CloakBrowser ready')"
```

**When to use:** whenever `curl`, `wget`, `httpx`, or any CLI tool returns a JS challenge, CAPTCHA, or "Checking your browser" page instead of real content. CloakBrowser's source-patched Chromium passes Cloudflare Turnstile, reCAPTCHA v3, and 30+ bot detection services.

**Reference:** see `../web/tools/cloakbrowser.md` for full CLI/Python API and common workflows.

If `apt-get update` fails because of network errors or timeout, switch to Kali's official CDN before retrying:

```bash
docker exec kali-pentest sed -i 's|http.kali.org|kali.download|g' /etc/apt/sources.list
docker exec kali-pentest apt-get update -qq
```

## Kali Metapackages

| Metapackage | Contents |
|---|---|
| `kali-tools-top10` | Most popular tools such as nmap and metasploit |
| `kali-tools-web` | Web application testing tools |
| `kali-tools-wireless` | Wireless attack tools |
| `kali-tools-exploitation` | Exploitation frameworks |
| `kali-tools-passwords` | Password cracking tools |
| `kali-tools-forensics` | Digital forensics tools |
| `kali-tools-information-gathering` | Reconnaissance tools |

## Wordlists

```bash
# rockyou.txt and common lists
docker exec kali-pentest bash -c "apt-get update -qq && apt-get install -y wordlists && ls /usr/share/wordlists/"

# SecLists
docker exec kali-pentest bash -c "apt-get update -qq && apt-get install -y seclists && ls /usr/share/seclists/"
```

## Custom Dockerfile

Use a custom image when you need a reproducible local environment.

```dockerfile
FROM kalilinux/kali-rolling
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      nmap masscan gobuster ffuf sqlmap nikto \
      hydra john hashcat wordlists \
      metasploit-framework && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
```

```bash
docker build -t kali-custom .
docker ps -a --filter name=^/kali-custom-pentest$ --format '{{.Names}}' | grep -qx kali-custom-pentest || \
  docker run -d --name kali-custom-pentest -v "$(pwd)":/workspace kali-custom sleep infinity
docker ps --filter name=^/kali-custom-pentest$ --filter status=running --format '{{.Names}}' | grep -qx kali-custom-pentest || \
  docker start kali-custom-pentest
docker exec -it kali-custom-pentest bash
```
