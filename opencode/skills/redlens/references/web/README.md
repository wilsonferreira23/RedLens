# Web Application Penetration (Web)

A toolset for security testing of Web applications, APIs, CMSes, and more. Covers directory enumeration, injection detection, XSS, parameter discovery, CMS scanning, proxy interception, and the full chain of Web penetration capabilities.

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| Liveness and fingerprinting | `httpx` + `whatweb` + `wafw00f` | — |
| Directory/file brute-force | `feroxbuster` (recursive) or `ffuf` (fine-grained) | Use `gobuster` for quick small-site scans |
| Parameter discovery | `arjun` | — |
| SQL injection | `sqlmap` | Add `--tamper` in WAF environments |
| XSS | `dalfox` (bulk) or `xsstrike` (deep analysis) | — |
| Command injection | `commix` | — |
| SSTI | `sstimap` | — |
| JWT testing | `jwt_tool` | — |
| CRLF injection | `crlfuzz` | — |
| CMS-specific | `wpscan` (WordPress) / `joomscan` (Joomla) | Use `cmseek` first when CMS is unknown |
| Crawler | `katana` (modern) or `gospider` | Use waybackurls when historical URLs are needed |
| Full DAST | `zaproxy` full scan | Explicit authorization required |
| Black-box web vulnerability scanning | `wapiti` | — |
| CDN / anti-bot bypass | `CloakBrowser` (see `tools/cloakbrowser.md`) | Do NOT use Puppeteer/Playwright — CloakBrowser only |
| WebDAV testing | `davtest` | — |
| Traffic proxy | `mitmproxy` / `mitmdump` | Use `curl -x` when only request replay is needed |
| Padding oracle | `padbuster` | — |
| PHP deserialization | `phpggc` (generate) → delivery via upload/injection | — |
| Subdomain takeover | `subjack` | — |
| HTTP slow DoS testing | `slowhttptest` | Explicit authorization required |
| Path traversal | `ffuf` with traversal wordlists | — |

---

## Vulnerability Scanning

**[nuclei](../vulnerability/tools/nuclei.md)** — Template-based Web vulnerability scanning
A high-speed vulnerability scanning framework based on YAML templates. 12000+ templates cover Web CVEs, misconfigurations, exposure detection, API security testing, and more — with a low false-positive rate. **In Web penetration testing, most commonly used for quickly detecting known CVEs and common misconfigurations; should be run early in almost every Web assessment.**

**[nikto](tools/nikto.md)** — Web server vulnerability scanning
Quickly scans Web servers for known vulnerabilities, misconfigurations, and outdated software. Contains 6700+ detection checks. Suitable for quickly finding low-hanging fruit, but scanning has a distinctive fingerprint and is easily detected.

**[zaproxy](tools/zaproxy.md)** — OWASP ZAP CLI and DAST automation
OWASP ZAP is a web security testing proxy and DAST scanner with official command-line, daemon/API, Automation Framework, and Docker packaged scan support. Use baseline scans for low-impact passive testing, API scans for OpenAPI/GraphQL targets, and full scans only with explicit authorization.

**[wapiti](tools/wapiti.md)** — Black-box web vulnerability scanner
A black-box web application vulnerability scanner that crawls target sites and tests for XSS, SQL injection, SSRF, XXE, command injection, CRLF injection, open redirects, and more. Generates HTML/JSON/XML reports. Useful as a complementary scanner alongside `nuclei` and `nikto`.

**[slowhttptest](tools/slowhttptest.md)** — HTTP slow attack testing
Tests web servers for vulnerability to slow HTTP attacks including Slowloris (slow headers), Slow POST (slow body), Slow Read (small receive window), and Range Header DoS. Identifies servers susceptible to connection exhaustion with minimal bandwidth.

**[subjack](tools/subjack.md)** — Subdomain takeover detection
Scans subdomains for potential takeover vulnerabilities caused by deprovisioned cloud services (S3 buckets, Azure, GitHub Pages, Heroku, etc.). Checks CNAME records against known fingerprints of claimable services. Pipeline-friendly for bulk scanning after subdomain enumeration.

---

## Injection Testing

Injection vulnerabilities remain the most impactful class of Web flaws. Choose the right tool for the injection type:

| Injection Type | Tool | When to Use |
|----------------|------|-------------|
| SQL injection | `sqlmap` | Any suspected SQL injection point; add `--tamper` scripts for WAF bypass |
| Command injection | `commix` | Parameters that may reach OS commands (`ping`, `curl`, `system()`) |
| SSTI | `sstimap` | Template-rendered user input (Jinja2, Twig, Smarty, Freemarker) |

**[sqlmap](tools/sqlmap.md)** — SQL injection automation
The most powerful SQL injection detection and exploitation tool. Supports Union/blind/error-based/time-based injection and all other injection types, covering MySQL/MSSQL/Oracle/PostgreSQL and other major databases. Can automatically obtain a shell. The standard tool for SQL injection testing.

**[commix](tools/commix.md)** — Command injection automation
Similar to sqlmap but focused on command injection vulnerabilities. Automatically detects injection points in GET/POST/Cookie/Header, and supports obtaining an interactive shell. Suitable for discovering OS command injection vulnerabilities.

**[sstimap](tools/sstimap.md)** — Server-Side Template Injection detection
Automated SSTI detection and exploitation supporting Jinja2, Twig, Smarty, and other template engines. Can escalate to remote command execution, file read/write. The sqlmap equivalent for SSTI vulnerabilities.

**[tinja](tools/tinja.md)** — Automated SSTI detection and exploitation
Detects and exploits Server-Side Template Injection vulnerabilities across multiple template engines. Automatically identifies the engine type and attempts code execution. Complements sstimap with additional engine support and detection techniques.

**[phpggc](tools/phpggc.md)** — PHP deserialization gadget chain generator
Generates serialized PHP payloads exploiting known gadget chains in 100+ frameworks and libraries (Laravel, Symfony, WordPress, Magento, etc.). Use when a PHP deserialization sink is confirmed to produce RCE, file write, or SSRF payloads.

**[padbuster](tools/padbuster.md)** — Padding oracle attack automation
Automates padding oracle attacks against CBC-mode encrypted tokens and parameters. Decrypts ciphertext and forges valid encrypted values without knowing the key. Use when a web application leaks padding validation errors in responses.

---

## Client-Side Testing

Client-side vulnerabilities — XSS, CRLF injection, and header injection — are exploited through user interaction. Testing should cover both reflected and stored vectors.

| Vulnerability | Primary Tool | Alternative / Complement |
|---------------|-------------|--------------------------|
| XSS (bulk scanning) | `dalfox` | `xsstrike` for deep context-aware analysis |
| XSS (depth analysis) | `xsstrike` | Blind XSS testing for backend panels |
| CRLF injection | `crlfuzz` | Pipeline-friendly; reads URLs from stdin |

**[dalfox](tools/dalfox.md)** — Automated XSS detection
An intelligent XSS detection tool with low false-positive rates and fast speed. Supports reflected and DOM-based XSS; can batch-scan URLs or be used with pipes. Suitable for large-scale XSS testing and Bug Bounty programs.

**[xsstrike](tools/xsstrike.md)** — Context-aware XSS detection
An advanced XSS scanner that analyzes HTML/JavaScript context to generate precise, WAF-bypassing payloads. Supports crawling, blind XSS testing (for backend panels), and WAF fingerprinting. Complements dalfox in depth-over-speed scenarios.

**[crlfuzz](tools/crlfuzz.md)** — CRLF injection scanner
A fast Go-based scanner for CRLF (Carriage Return Line Feed) injection vulnerabilities. Tests whether user-supplied input can inject CR+LF characters into HTTP headers, enabling response splitting and header injection. Pipeline-friendly — reads URLs from stdin or a file.

---

## Directory and Parameter Enumeration

**[gobuster](tools/gobuster.md)** — Directory/DNS/virtual host brute-forcing
A dictionary-based multi-mode brute-forcing tool supporting dir (directory), dns (subdomain), and vhost (virtual host) modes. Fast and suitable for quick enumeration of small to medium targets.

**[dirb](tools/dirb.md)** — Classic web directory/file brute-forcer
A traditional URL brute-forcing tool that tests paths from wordlists against a web server. Supports custom user agents, cookies, authentication, and certificate-based connections. A simple, reliable fallback when more modern tools are unavailable.

**[dirsearch](tools/dirsearch.md)** — Web directory brute-forcing with extension chaining
A fast web path scanner with a built-in wordlist and multi-extension support. Supports recursive scanning and multiple output formats. Useful as a cross-check alongside feroxbuster and gobuster.

**[ffuf](tools/ffuf.md)** — High-speed Web fuzzing
More flexible than gobuster; can fuzz any position in URLs, Headers, and Body. Supports multiple keyword substitution, response filtering, and output format selection. Suitable for fuzzing scenarios requiring fine-grained control.

**[feroxbuster](tools/feroxbuster.md)** — Recursive directory enumeration
Written in Rust; supports automatic recursive subdirectory discovery, extremely fast, with automatic deduplication. Suitable for scenarios requiring deep directory traversal — an alternative to gobuster for recursive enumeration.

**[wfuzz](tools/wfuzz.md)** — Web fuzzing framework
A powerful Web Fuzzer supporting multiple payload types, encoders, and filters. Suitable for complex testing scenarios such as authentication bypass and parameter enumeration.

**[gospider](tools/gospider.md)** — Fast web spider for endpoint and subdomain discovery
A Go-based web spider that discovers URLs, JavaScript endpoints, subdomains, and AWS S3 buckets. Also queries historical URLs from the Wayback Machine, Common Crawl, and VirusTotal. Supports parallel multi-site crawling.

**[katana](tools/katana.md)** — Modern web crawler and endpoint discovery
ProjectDiscovery's CLI crawler for HTTP and optional headless browser crawling. Supports JavaScript endpoint parsing, known-file crawling, form extraction, scope controls, JSONL output, and pipelines into nuclei or parameter discovery tools.

**[arjun](tools/arjun.md)** — Hidden HTTP parameter discovery
Specifically designed to discover hidden parameters in Web endpoints. Supports GET/POST/JSON/XML; helps find injection points that might otherwise be overlooked. Suitable for API testing and parameter mining.

---

## CMS Scanning

**[wpscan](tools/wpscan.md)** — WordPress security scanning
A WordPress-specific scanning tool that enumerates users/plugins/themes, detects known CVEs, and supports password brute-forcing. An essential tool for assessing WordPress sites.

**[cmseek](tools/cmseek.md)** — CMS detection and enumeration
Detects 180+ CMS types (WordPress, Joomla, Drupal, etc.) and enumerates version, users, plugins, and themes. Automatically identifies the target CMS and retrieves associated information for vulnerability research.

**[joomscan](tools/joomscan.md)** — Joomla-specific vulnerability scanning
OWASP JoomScan checks Joomla versions, components, administrative paths, common backup/config files, and Joomla-specific exposure. Use it after fingerprinting confirms or strongly suggests Joomla.

---

## WebDAV Testing

**[davtest](tools/davtest.md)** — WebDAV server testing
Tests WebDAV-enabled web servers for file upload and execution capabilities. Uploads files with various extensions (PHP, ASP, JSP, CGI, etc.) and verifies whether they can be executed on the server. Essential for identifying file upload vulnerabilities on WebDAV endpoints.

**[weevely](tools/weevely.md)** — Obfuscated PHP webshell generator and manager
Generates obfuscated PHP webshells and provides an interactive terminal with built-in post-exploitation modules for file management, network pivoting, brute-forcing, and privilege escalation. Use after gaining file upload or code execution on a PHP-based target.

---

## Source and Secret Scanning

**[gitleaks](tools/gitleaks.md)** — Git and source secret scanning
Scans Git repositories, directories, files, and stdin for hardcoded secrets such as passwords, API keys, and tokens. Use it when source code, exposed `.git` data, deployment bundles, or CI artifacts are in scope.

---

## Authentication Testing

**[jwt_tool](tools/jwt_tool.md)** — JWT vulnerability testing
A toolkit for analyzing and attacking JSON Web Tokens. Tests for alg:none, algorithm confusion (RS256→HS256), weak secrets, and claim injection. Essential for any API or Single Page Application (SPA) assessment.

---

## Proxy and Traffic Interception

**[mitmproxy](tools/mitmproxy.md)** — Scriptable HTTP(S) interception proxy
Official CLI-capable interception proxy toolkit. Use `mitmdump` for non-interactive capture, HAR export, request replay, reverse proxy mode, SOCKS mode, and Python addon-based traffic inspection or modification.

---

## API and WebSocket Testing

Modern web applications increasingly rely on APIs (REST, GraphQL, gRPC) and WebSocket connections rather than traditional form-based interactions. When the target exposes API endpoints or real-time WebSocket channels, use these tools for schema-driven tests, introspection exploitation, and protocol-specific fuzzing.

**[kiterunner](tools/kiterunner.md)** — API route discovery
Discovers REST API routes using API-aware wordlists. Use instead of `ffuf`/`feroxbuster` for API-specific path patterns.

**[schemathesis](tools/schemathesis.md)** — Schema-based API fuzzing
Generates API requests from OpenAPI or GraphQL schemas to detect crashes and schema violations. High-risk; explicit approval required.

**[graphw00f](tools/graphw00f.md)** — GraphQL engine fingerprinting
Identifies GraphQL server implementations and engine-specific behavior.

**[clairvoyance](tools/clairvoyance.md)** — GraphQL schema recovery
Infers schema details when introspection is disabled. Avoid when request volume is not approved.

**[grpcurl](tools/grpcurl.md)** — gRPC command-line client
Lists services, describes methods, and invokes RPC calls. Requires proto files if reflection is disabled.

**[websocat](tools/websocat.md)** — WebSocket command-line client
Sends and receives WebSocket messages for handshake and message-level testing.

**[mitmproxy2swagger](tools/mitmproxy2swagger.md)** — OpenAPI specification recovery
Converts captured HTTP traffic into OpenAPI 3.0 definitions. Requires representative captured traffic.

---

## Related Categories

- For the full web application penetration playbook, see `../playbooks/web-application.md`.
- For reconnaissance and fingerprinting before web testing, see `../information-gathering/README.md`.

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| sqlmap reports clean on default settings | escalate to `--level=5 --risk=3` before accepting negative result |
| Multiple injection types possible on one parameter | test SQL → command → SSTI in order; `commix` and `sstimap` handle different backends |
| API with OpenAPI/Swagger spec available | `schemathesis` for automated spec-driven testing |
| GraphQL endpoint detected | `graphw00f` fingerprint, then `clairvoyance` for schema recovery if introspection disabled |
| Need recursive directory discovery | `feroxbuster` (auto-recursive); `ffuf` for custom recursion logic |
| API requires custom request signing (HMAC, timestamp, nonce, encrypted login) | `mitmproxy` addon with `--set http2=false` as signing proxy (see [mitmproxy](tools/mitmproxy.md)); proxy-incompatible tools (nikto) inject auth headers directly via their own header flags |

---

## Official References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Kali Tools](https://www.kali.org/tools/all-tools/)
