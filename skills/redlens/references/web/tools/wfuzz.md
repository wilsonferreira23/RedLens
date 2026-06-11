# Wfuzz

- **Category**: Web / Fuzzing
- **Risk Level**: 🟡 Medium

---

## Description

wfuzz is a powerful Web application fuzzing tool written in Python. Its core feature is using placeholders like `FUZZ`, `FUZ2Z`, `FUZ3Z` to inject payloads at any position in HTTP requests. It supports multiple encoders, filters, and iterators. Particularly suitable for parameter enumeration, authentication bypass testing, directory scanning, and similar scenarios.

**Core Capabilities:**
- Multiple simultaneous FUZZ points
- Rich built-in payload types
- Powerful response filtering and matching rules
- Encoder chaining (multiple encoding passes)
- Built-in authentication support (Basic/NTLM/Digest)

## Installation

```bash
apt install wfuzz -y

# pip install
pip3 install wfuzz
```

## Parameter Reference

### Basic Parameters

| Parameter | Description |
|------|------|
| `-u URL` | Specify a URL for the request |
| `-w wordlist` | Wordlist file |
| `-z payload` | Specify a payload for each FUZZ keyword |
| `-p proxy` | Use proxy in format ip:port:type |
| `-t threads` | Number of concurrent connections (default: 10) |
| `-s seconds` | Time delay between requests (default: 0) |
| `--req-delay N` | Maximum time in seconds the request is allowed to take (default: 90) |
| `--conn-delay N` | Maximum time in seconds for connection phase (default 90) |

### HTTP Configuration

| Parameter | Description |
|------|------|
| `-X method` | HTTP method |
| `-d data` | POST data |
| `-H header` | Use header (e.g., `Cookie:id=1312321&user=FUZZ`) |
| `-b cookie` | Cookie |
| `-R depth` | Recursive path discovery (depth = maximum recursion level) |
| `--follow` | Follow HTTP redirections |

### Filter Parameters (Important)

| Parameter | Description |
|------|------|
| `--hc codes` | Hide responses with the specified code/lines/words/chars |
| `--sc codes` | Show responses with the specified code/lines/words/chars |
| `--hl lines` | Hide responses with specified line count |
| `--sl lines` | Show responses with specified line count |
| `--hw words` | Hide responses with specified word count |
| `--sw words` | Show responses with specified word count |
| `--hh chars` | Hide responses with specified character count |
| `--sh chars` | Show responses with specified character count |
| `--hs regex` | Hide responses matching string/regex in content |
| `--ss regex` | Show/hide responses with the specified regex within the content |

### Payload Types (-z)

| Type | Description | Example |
|------|------|------|
| `file` | Read from file | `-z file,wordlist.txt` |
| `list` | Specify value list | `-z list,a-b-c` |
| `range` | Numeric range | `-z range,1-100` |
| `hex` | Hexadecimal range | `-z hex,0-ff` |
| `burplog` | Burp Suite log | `-z burplog,burp.log` |
| `stdin` | Standard input | `-z stdin` |

### Encoders (used with -z)

| Encoder | Description |
|--------|------|
| `urlencode` | URL encoding |
| `html` | HTML entity encoding |
| `base64` | Base64 encoding |
| `md5` | MD5 hash |
| `sha1` | SHA1 hash |
| `hexlify` | Hexadecimal encoding |
| `none` | No encoding (default) |

## Common Commands

### Scenario 1: Directory Enumeration

```bash
# Basic directory enumeration, filter 404
wfuzz -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirb/common.txt \
  --hc 404

# Multi-threaded directory enumeration
wfuzz -u http://target.com/FUZZ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 30 --hc 404

# Enumerate specific extension files (using FUZ2Z)
wfuzz -u http://target.com/FUZZ.FUZ2Z \
  -w /usr/share/wordlists/dirb/common.txt \
  -z list,php-html-txt-bak \
  --hc 404
```

### Scenario 2: GET Parameter Enumeration

```bash
# Discover hidden parameters
wfuzz -u "http://target.com/page.php?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  --hh 1234   # Hide normal page size

# Parameter value fuzzing
wfuzz -u "http://target.com/page.php?id=FUZZ" \
  -z range,1-1000 \
  --hc 404
```

### Scenario 3: POST Data Fuzzing

```bash
# Login brute-force
wfuzz -u http://target.com/login.php \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/wordlists/rockyou.txt \
  --hc 401 \
  --ss "Welcome"   # Only show responses containing "Welcome"

# Credential brute-force (dual FUZZ: both username and password)
wfuzz -u http://target.com/login.php \
  -X POST \
  -d "username=FUZZ&password=FUZ2Z" \
  -z file,usernames.txt \
  -z file,passwords.txt \
  --hc 401
```

### Scenario 4: Cookie Injection

```bash
wfuzz -u http://target.com/page.php \
  -b "session=FUZZ" \
  -w sessions.txt \
  --hc 302
```

### Scenario 5: Header Injection

```bash
# Test X-Forwarded-For IP spoofing
wfuzz -u http://target.com/admin \
  -H "X-Forwarded-For: FUZZ" \
  -z list,127.0.0.1-10.0.0.1-192.168.1.1 \
  --hc 403

# Test Host Header injection
wfuzz -u http://target.com/page.php \
  -H "Host: FUZZ" \
  -w subdomains.txt \
  --sc 200
```

### Scenario 6: Using Encoders

```bash
# URL-encode payload
wfuzz -u "http://target.com/page.php?path=FUZZ" \
  -z file,lfi_payloads.txt,urlencode \
  --hc 404

# Double encoding
wfuzz -u "http://target.com/page.php?path=FUZZ" \
  -z file,lfi_payloads.txt,urlencode-urlencode \
  --hc 404

# Base64 encoding
wfuzz -u "http://target.com/page.php?data=FUZZ" \
  -z file,payloads.txt,base64 \
  --hc 404
```

### Scenario 7: Subdomain Enumeration

```bash
# DNS-based subdomain brute-force: FUZZ the hostname in the URL
# The Host header is derived automatically — no need to add -H here
wfuzz -u http://FUZZ.target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --hc 404 --hw 200  # Adjust --hw value based on a baseline request word count
```

## Notes & Tips

1. **Filters**: Run a few requests without filters first to identify characteristics of default responses (line count/byte count), then use `--hl/--hh` to filter.
2. **Multiple wordlists**: The first `-w` corresponds to `FUZZ`, the second to `FUZ2Z`, and so on; you can also use the `-z file,wordlist.txt` format.
3. **Speed control**: Use `-t` for threads and `-s` for intervals to avoid overwhelming the server.
4. **wfuzz vs ffuf**: ffuf is faster; wfuzz has richer encoders and iterators — each has its strengths.
5. **Encoder chaining**: `-z file,payloads.txt,urlencode-base64` means URL-encode first, then base64 — order matters.
6. **Background execution**: wfuzz may not flush output buffers when run in detached mode (`docker exec -d`). Run in foreground with stdin redirected (`< /dev/null`) and capture output to a file (`-f /tmp/result.json,json`), or use `nohup` with explicit redirection.

---

## Official References

- [wfuzz GitHub](https://github.com/xmendez/wfuzz)
- [wfuzz Documentation](https://wfuzz.readthedocs.io/)
