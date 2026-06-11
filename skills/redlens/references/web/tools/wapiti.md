# Wapiti

- **Category**: Web / Vulnerability Scanning
- **Risk Level**: 🔴 High

---

## Description

Black-box web application vulnerability scanner. Crawls target pages and injects payloads to test for XSS, SQL injection, SSRF, XXE, command injection, file inclusion, CRLF injection, open redirects, and more. Supports authenticated scanning and generates reports in HTML, JSON, TXT, and XML formats.

## Installation

```bash
sudo apt install wapiti
```

Alternative (latest version):

```bash
pip3 install wapiti3
```

## Parameter Reference

| Parameter | Description |
|------|------|
| `-u <url>` | The base URL used to define the scan scope (default scope is folder) |
| `-s <url>` | Add a URL to start scan with |
| `-m <modules>` | List of modules to load |
| `--scope <scope>` | Scan scope: `page`, `folder`, `domain`, or `url` |
| `-f <format>` | Output format: csv, html, json, md, txt, xml (default: html) |
| `-o <output>` | Output file or folder |
| `--flush-session` | Flush everything previously found for this target |
| `--auth-cred <user%pass>` | (DEPRECATED) Set HTTP authentication credentials |
| `--auth-method <type>` | Authentication type: `basic`, `digest`, `ntlm` |
| `-p <proxy>` | Set the HTTP(S) proxy to use (supports http(s) and socks proxies) |
| `--max-links-per-page <n>` | Maximum number of links to extract per page |
| `-v <level>` | Verbosity level: `0` (quiet), `1` (normal), `2` (verbose) |
| `-x <url>` | Add a URL to exclude from the scan |
| `-t <seconds>` | Set timeout for requests |
| `--skip <param>` | Skip attacking given parameter(s) |

## Common Commands

```bash
# Full site scan with HTML report
wapiti -u http://target.com/ -f html -o /tmp/wapiti_report

# Scan specific modules only (XSS and SQL injection)
wapiti -u http://target.com/ -m xss,sql -o /tmp/wapiti_report

# Authenticated scan with basic auth
wapiti -u http://target.com/ --auth-cred "admin%password123" --auth-method basic

# Restrict scope to a single folder
wapiti -u http://target.com/app/ --scope folder -o /tmp/wapiti_report

# Scan through a proxy with JSON report
wapiti -u http://target.com/ -p http://127.0.0.1:8080 -f json -o /tmp/wapiti_report.json

# Exclude logout URL and limit crawl depth
wapiti -u http://target.com/ -x "http://target.com/logout" --max-links-per-page 500

# Flush previous session and rescan with verbose output
wapiti -u http://target.com/ --flush-session -v 2 -o /tmp/wapiti_report
```

## Notes & Tips

1. wapiti crawls the entire site before attacking — use `--scope folder` or `--max-links-per-page` to limit scope on large applications.
2. Use `--flush-session` when retesting after application changes; otherwise wapiti resumes from its cached session.
3. Module selection with `-m` significantly reduces scan time — target specific vulnerability classes rather than running all modules.
4. Pair with a proxy (`-p`) pointing to Burp/ZAP to capture and review all injected payloads.
5. The `--skip` option prevents testing on sensitive parameters (e.g., CSRF tokens) that could break session state.

---

## Official References

- [Wapiti Official Site](https://wapiti-scanner.github.io/)
- [Wapiti GitHub](https://github.com/wapiti-scanner/wapiti)
- [Kali wapiti](https://www.kali.org/tools/wapiti/)
