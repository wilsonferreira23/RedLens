# kiterunner

- **Category**: Web / API Endpoint Discovery
- **Risk Level**: 🟡 Medium

---

## Description

API endpoint discovery tool that understands structured routes and API wordlists. It is useful for REST API path discovery where conventional directory brute-forcing misses parameterized routes.

## Installation

```bash
# Download the latest release binary from the official repository
curl -L https://github.com/assetnote/kiterunner/releases/latest/download/kr-linux-amd64 -o kr
chmod +x kr
sudo mv kr /usr/local/bin/
kr -h
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `scan` | Scan targets using kite wordlists |
| `brute` | Brute-force targets using plain-text wordlists |
| `-w <wordlist>` | Kite or plain-text wordlist |
| `-A <type/name>` / `--assetnote-wordlist` | Use Assetnote wordlists (e.g. `apiroutes-210228`) |
| `-x <n>` / `--max-connection-per-host` | Max connections per host (default `3`) |
| `-j <n>` / `--max-parallel-hosts` | Max parallel hosts (default `50`) |
| `-d <n>` / `--preflight-depth` | Preflight wildcard check depth (default `1` scan, `0` brute) |
| `-H <header>` | Custom header |
| `-o <format>` | Output format: `json`, `text`, `pretty` (default: `pretty`) |
| `--success-status-codes <codes>` | Whitelist status codes as successful |
| `--fail-status-codes <codes>` | Blacklist status codes as failures |
| `--force-method <method>` | Override HTTP method for all requests |
| `-t <duration>` / `--timeout` | Request timeout (default `3s`) |
| `--max-redirects <n>` | Max redirects to follow (default `3`) |

## Common Commands

```bash
# Scan API targets with kite wordlist (output to file via redirect)
kr scan targets.txt -w <api_wordlist.kite> | tee /tmp/kiterunner.txt

# Scan one API base URL
echo https://target/api | kr scan - -w <api_wordlist.kite>

# Brute-force with a plain-text wordlist
kr brute https://target/api -w /usr/share/wordlists/dirb/common.txt

# Use Assetnote wordlists
kr scan targets.txt -A apiroutes-210228

# Limit connections and force GET method
kr scan targets.txt -w <api_wordlist.kite> -x 3 --force-method GET
```

## Notes & Tips

1. Use after identifying API base paths with `katana`, ZAP, or traffic captures.
2. Calibrate negative status codes and response lengths to reduce false positives.
3. Kiterunner is active enumeration; respect rate limits.

---

## Official References

- [Kiterunner GitHub](https://github.com/assetnote/kiterunner)
