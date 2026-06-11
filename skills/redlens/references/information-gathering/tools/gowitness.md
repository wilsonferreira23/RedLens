# gowitness

- **Category**: Information Gathering / Web Service Screenshots
- **Risk Level**: 🟢 Low

---

## Description

A high-speed web screenshot tool that uses a headless Chrome/Chromium browser to take bulk screenshots of large numbers of URLs and generate a searchable HTML report. Faster than eyewitness; ideal for large-scale web asset documentation and report generation.

## Installation

```bash
sudo apt install gowitness
go install github.com/sensepost/gowitness@latest
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `scan single` | Scan a single URL (v3: requires `--url <url>`) |
| `--url <url>` | Target URL for `scan single` (v3 required flag) |
| `scan file -f <file>` | Scan URLs from file |
| `--chrome-path <path>` | Path to Chrome binary |
| `--timeout <seconds>` | Screenshot timeout |
| `--resolution-x <px>` / `--resolution-y <px>` | Screenshot width/height (v2; short: `-X`/`-Y`) |
| `--chrome-window-x <px>` / `--chrome-window-y <px>` | Screenshot width/height (v3) |

## Common Commands

```bash
# Screenshot a single URL
gowitness single http://target.com  # v2.x
# gowitness scan single --url http://target.com  # v3.x

# Bulk URLs (read from file)
gowitness file -f urls.txt  # v2.x
# gowitness scan file -f urls.txt  # v3.x

# Bulk URLs (save to specified directory)
gowitness file -f urls.txt --screenshot-path /tmp/screenshots/  # v2.x
# gowitness scan file -f urls.txt --screenshot-path /tmp/screenshots/  # v3.x

# Scan a CIDR range (internal network)
gowitness scan --cidr 192.168.1.0/24  # v2.x
# gowitness scan cidr --cidr 192.168.1.0/24  # v3.x

# Scan nmap XML results
gowitness nmap -f /tmp/nmap_scan.xml  # v2.x
# gowitness scan nmap -f /tmp/nmap_scan.xml  # v3.x

# Start report server (browse screenshots locally)
# gowitness v2:
gowitness report serve --address 127.0.0.1:7171
# gowitness v3:
gowitness report server --host 127.0.0.1 --port 7171
# Access http://127.0.0.1:7171

# Specify concurrency (--threads flag is used in both v2.x and v3.x)
gowitness file -f urls.txt --threads 20    # v2.x
# gowitness scan file -f urls.txt --threads 20  # v3.x

# Set timeout (v2: root persistent flag for preflight; v3: --timeout on parent scan command for page load)
gowitness file -f urls.txt --timeout 15    # v2.x
# gowitness scan file -f urls.txt --timeout 15  # v3.x

# Use a proxy (v2.x uses --proxy; v3.x uses --chrome-proxy)
gowitness file -f urls.txt --proxy http://127.0.0.1:8080  # v2.x
# gowitness scan file -f urls.txt --chrome-proxy http://127.0.0.1:8080  # v3.x
```

## Notes & Tips

1. gowitness v3 reorganized all subcommands — `scan single`, `scan file`, `scan cidr`, `scan nmap` are the v3 equivalents of v2's top-level commands.
2. The generated HTML report (via `report serve`/`report server`) supports filtering by HTTP status code, title, and technology — ideal for triaging large asset lists.
3. Use `--threads 20` or higher for faster bulk scanning; the default thread count is conservative.
4. Combine with nmap XML output (`gowitness scan nmap -f scan.xml`) to automatically screenshot all web services discovered during port scanning.
5. Screenshots are stored as PNG files alongside a SQLite database — the report server reads from this database, so keep both in the same directory.

---

## Official References

- [gowitness (GitHub)](https://github.com/sensepost/gowitness)
