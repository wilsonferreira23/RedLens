# Information Gathering & Reconnaissance

The first phase of penetration testing. The goal is to collect as much information about the target as possible without triggering alerts. Divided into **passive reconnaissance** (no contact with the target, pure OSINT) and **active reconnaissance** (direct interaction with the target).

---

## Golden Path

Start here when you know what you need; the table picks the right tool chain.

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| Passive subdomain discovery | `subfinder` → `dnsx` → `httpx` | Use `amass` when deep recursive enumeration and historical data are needed |
| Port scanning (large scale) | `naabu` → `nmap -sV` | Add `nmap -sU` for UDP |
| Port scanning (precise) | `nmap -sS -sV -sC` | — |
| Full DNS enumeration | `dnsenum` or `dnsrecon` | Use `dig` when only quick A/AAAA records are needed |
| Internal host discovery | `arp-scan` or `netdiscover` | Use `nmap -sn` for cross-subnet |
| Quick OSINT collection | `whois` → `theHarvester` | Use `spiderfoot` or `recon-ng` when automation/database framework is needed |
| Web fingerprinting | `whatweb` + `wafw00f` | Use `httpx` for bulk liveness probing |
| Subdomain brute-force | `dnsgen`/`altdns` generate → `massdns`/`dnsx` validate | Skip to subfinder for passive-only collection |
| Cloud asset enumeration | `cloud-enum` (keyword) or `cloudbrute` (brute-force) | — |
| Domain permutation / typosquatting | `dnstwist` | — |
| Passive OS fingerprinting | `p0f` (listen on interface) | Use `nmap -O` for active fingerprinting |
| Secret scanning | `trufflehog` | Use `gitleaks` when only git repos are in scope |
| Historical URL discovery | `gau` (getallurls) | Use `gospider`/`katana` when active crawling is preferred |
| Document metadata harvesting | `metagoofil` | — |
| Username / identity OSINT | `sherlock` | Use `spiderfoot` for broader automated OSINT |
| Email breach lookup | `h8mail` | — |

---

## Network Scanning & Host Discovery

**[nmap](tools/nmap.md)** — Network scanning and port probing
The most essential tool in Kali, supporting host discovery, port scanning, service version detection, OS identification, and NSE script scanning. Suitable for network asset discovery at all stages of penetration testing. Most comprehensive features but moderate speed.

**[masscan](tools/masscan.md)** — Ultra-high-speed port scanning
Claims to be the fastest port scanner, capable of scanning the entire internet in under 6 minutes. Suitable for rapidly discovering open ports at scale, though less accurate than nmap. Typically use masscan first to locate ports, then nmap for detailed analysis.

**[naabu](tools/naabu.md)** — Fast pipeline-friendly port scanning
ProjectDiscovery's fast port scanner for large target lists, top-port scans, custom ports, JSONL output, and direct chaining into httpx or nuclei. Use it for quick TCP port discovery before deeper nmap service detection.

**[netdiscover](tools/netdiscover.md)** — Internal network ARP host discovery
ARP-based LAN host discovery tool, unaffected by host firewalls, fast. Supports passive mode (completely silent ARP traffic monitoring). Suitable for host enumeration in the early stages of internal network penetration.

**[arp-scan](tools/arp-scan.md)** — Fast ARP scanning
Discovers LAN hosts by sending ARP requests while obtaining MAC addresses and device vendor information. Faster than netdiscover, suitable for quick internal network host inventory.

**[nbtscan](tools/nbtscan.md)** — NetBIOS name table scanning
Scans local or routed networks for NetBIOS name tables, revealing Windows hostnames, workgroups/domains, and logged-in user indicators. Useful after host discovery on internal networks.

**[fping](tools/fping.md)** — Fast multi-host ICMP ping
Probes multiple hosts simultaneously in a round-robin fashion, far faster than standard ping for subnet-wide host discovery. Accepts host lists from files or stdin; pipeline-friendly for chaining into nmap.

**[p0f](tools/p0f.md)** — Passive OS fingerprinting
Completely passive — infers the remote host's operating system, browser type, etc. by analyzing network traffic passing through. Sends no packets at all, completely covert. Suitable for reconnaissance scenarios requiring high stealth.

**IPv6 discovery**: `nmap -6 -sn <prefix>` for neighbor scanning; `ping6 ff02::1%<interface>` for link-local multicast to enumerate on-link IPv6 hosts that may not appear in IPv4 scans.

---

## Subdomain & Endpoint Discovery

**[subfinder](tools/subfinder.md)** — Passive subdomain enumeration
A passive subdomain discovery tool that queries 40+ public data sources (VirusTotal, Shodan, Certificate Transparency, etc.) without sending packets to the target. Fast and pipeline-friendly; chain with httpx and nuclei for automated discovery-to-scan workflows.

**[assetfinder](tools/assetfinder.md)** — Fast passive subdomain discovery
Queries certificate transparency logs, the Wayback Machine, and multiple threat intelligence platforms to find subdomains. Lightweight and pipeline-friendly; no API keys required. Use as a quick first pass or alongside subfinder for broader coverage.

**[findomain](tools/findomain.md)** — Fast subdomain discovery (Rust)
Queries certificate transparency logs and APIs for passive subdomain enumeration. Written in Rust for high performance; outputs results to stdout or files for pipeline integration.

**[hakrawler](tools/hakrawler.md)** — Fast web crawler for endpoint discovery
A lightweight crawler that extracts URLs, JS files, forms, and subdomains from web applications. Designed for pipeline use: `subfinder | httpx | hakrawler` maps the full attack surface efficiently.

**[getallurls (gau)](tools/getallurls.md)** — Known URL fetching from historical sources
Fetches known URLs from the Wayback Machine, Common Crawl, OTX, and URLScan for a given domain. Useful for discovering hidden endpoints, parameters, and historical paths that may still be active.

**[httprobe](tools/httprobe.md)** — HTTP/HTTPS liveness probing
Probes a list of domains to determine which respond on HTTP or HTTPS. Filters alive hosts from subdomain discovery output; pipeline-friendly for chaining with subfinder and other tools.

**[hosthunter](tools/hosthunter.md)** — Virtual hostname discovery via SSL/TLS certificates and Bing reverse IP
Discovers virtual hostnames associated with an IP address by querying SSL/TLS certificates and Bing reverse IP lookups. Useful for identifying co-hosted domains and expanding the attack surface on shared hosting environments.

**[spiderfoot](tools/spiderfoot.md)** — Comprehensive OSINT automation
Queries 200+ data sources (VirusTotal, Shodan, HaveIBeenPwned, etc.) to gather intelligence about IPs, domains, emails, and person names. Provides both CLI and web GUI interfaces. The most thorough automated OSINT framework available.

**[autorecon](tools/autorecon.md)** — Automated multi-service enumeration
Orchestrates nmap, gobuster, nikto, enum4linux, and dozens of other tools in parallel against each open port. Saves hours on initial footprinting. Widely used for OSCP and CTF lab environments.

---

## DNS Enumeration & Subdomain Discovery

**[amass](tools/amass.md)** — Comprehensive subdomain enumeration
The most powerful subdomain enumeration tool, integrating both OSINT (passive) and active DNS query modes, with over 50 data sources. Suitable as the primary tool for subdomain discovery.

**[sublist3r](tools/sublist3r.md)** — Multi-engine subdomain enumeration
Passively collects subdomains using multiple search engines (Google/Bing/Yahoo, etc.), fast, suitable for quickly getting an initial subdomain list; can supplement amass coverage.

**[dnsenum](tools/dnsenum.md)** — Automated DNS enumeration
Integrates DNS record queries, zone transfer attempts, and subdomain brute-force enumeration. Suitable for comprehensive DNS reconnaissance on target domains with high automation.

**[dnsrecon](tools/dnsrecon.md)** — Multi-mode DNS reconnaissance
Supports standard queries, zone transfers, Google enumeration, brute-force enumeration, reverse lookups, and more, with rich output formats (JSON/XML/CSV). One of the most comprehensive DNS reconnaissance tools.

**[fierce](tools/fierce.md)** — DNS subdomain brute-force enumeration
First attempts zone transfer; if that fails, falls back to brute-force enumeration and performs reverse lookups on discovered IPs. Suitable for discovering non-contiguous IP ranges and internal hostnames of targets.

**[dnsmap](tools/dnsmap.md)** — DNS subdomain brute-force
Brute-forces subdomains using a built-in or custom wordlist; outputs plain text and CSV. Includes dnsmap-bulk for scanning multiple domains. A simpler, faster alternative to dnsenum for targeted subdomain brute-forcing.

**[dig](tools/dig.md) / host / nslookup** — DNS basic query tools
Standard DNS query tools; dig is the most powerful. Can query various DNS record types, attempt zone transfers, and trace resolution paths. Essential baseline tools for DNS reconnaissance.

**[dnsx](tools/dnsx.md)** — Fast bulk DNS resolution and brute-force
A fast, multi-purpose DNS toolkit by ProjectDiscovery. Resolves domains in bulk, brute-forces subdomains, and extracts DNS records (A, CNAME, MX, TXT, NS, SOA). Pipeline-friendly — reads from stdin and integrates directly with subfinder, httpx, and other ProjectDiscovery tools.

**[massdns](tools/massdns.md)** — High-performance bulk DNS resolver
Resolves very large domain lists through recursive resolvers at high speed. Use it to validate generated subdomain candidates from dnsgen or altdns before passing live names into httpx.

**[dnsgen](tools/dnsgen.md)** — DNS permutation generation
Generates candidate subdomains from known names using word splitting, substitutions, and permutation rules. Combine with massdns or dnsx to validate which generated names resolve.

**[altdns](tools/altdns.md)** — Subdomain permutation and alteration
Creates altered subdomain candidates from known hostnames and wordlists, then optionally resolves them. Useful for discovering naming-pattern variants not returned by passive sources.

**[dnstwist](tools/dnstwist.md)** — Domain permutation and typosquatting detection
Generates permutations of a target domain name — typosquatting, homoglyphs, bitsquatting, addition, omission, and more — then checks which permutations are registered. Used to identify phishing infrastructure and detect domain squatting.

**[certgraph](tools/certgraph.md)** — Certificate transparency graph builder
Maps domain relationships by querying Certificate Transparency logs and following Subject Alternative Names (SANs) to build a graph of connected domains and certificates. Useful for discovering related domains and infrastructure owned by the target.

### DNS Deep Dive — Permutation-Based Discovery

When passive sources and standard brute-forcing have been exhausted, permutation-based DNS discovery uncovers subdomains that follow naming patterns (e.g., `api-v2`, `staging-us-east`, `internal-db-01`). The pipeline is:

1. **Seed collection** — gather known subdomains from `subfinder`, `amass`, or `dnsenum`.
2. **Permutation generation** — feed known names into `dnsgen` (word-split permutations) or `altdns` (wordlist-driven alterations) to produce candidate lists that can reach millions of entries.
3. **High-speed resolution** — pipe candidates into `massdns` (fastest, uses external resolvers) or `dnsx` (ProjectDiscovery, integrates with the rest of the pipeline) to discard non-resolving names.
4. **Liveness verification** — pass resolving names through `httpx` to confirm live HTTP services.

```
cat known-subs.txt | dnsgen - | massdns -r resolvers.txt -t A -o S | httpx -silent
```

Use `altdns` when you have a custom wordlist of environment/region tokens specific to the target organization. Use `dnsgen` when you want automated word-splitting without maintaining a wordlist.

---

## OSINT & Intelligence Gathering

**[theHarvester](tools/theHarvester.md)** — Multi-source intelligence collection for emails/domains
Collects email addresses, subdomains, IPs, URLs, and other intelligence from 40+ data sources including Google, Bing, LinkedIn, and Shodan. Suitable for collecting personnel information and digital assets about the target.

**[recon-ng](tools/recon-ng.md)** — OSINT framework
Modular OSINT framework with a Metasploit-like interface, supporting 80+ modules, integrating multiple OSINT data sources. Suitable for systematic intelligence collection with database storage.

**[shodan (CLI)](tools/shodan.md)** — Network asset search engine
Queries the Shodan database (without sending packets to the target) to discover devices, services, and vulnerabilities exposed on the public internet. Suitable for quickly understanding a target's internet exposure surface. Requires an API Key.

**[whois](tools/whois.md)** — Domain registration information lookup
Queries domain registrant, registrar, DNS servers, IP range ownership, and other information. Purely passive; the most basic first-step tool in the reconnaissance phase.

**[dmitry](tools/dmitry.md)** — Comprehensive OSINT collection
Single tool integrating WHOIS, subdomain search, email collection, and port scanning. Suitable for quick initial reconnaissance, though each module lacks the depth of specialized tools.

**[metagoofil](tools/metagoofil.md)** — Public document metadata extraction
Downloads public documents (PDF, DOCX, XLSX, PPTX) from target domains via search engines and extracts metadata including usernames, file paths, and software versions. Useful for profiling internal infrastructure and personnel.

**[sherlock](tools/sherlock.md)** — Username search across social media
Searches for a username across 400+ social media sites to identify accounts associated with a target identity. Useful for OSINT profiling, correlating online personas, and mapping a target's digital footprint.

**[h8mail](tools/h8mail.md)** — Email OSINT and breach credential search
Searches email addresses against multiple breach databases and paste sites to discover leaked credentials and associated data. Supports API integration with HaveIBeenPwned, Snusbase, and other breach intelligence services.

**[ldeep](tools/ldeep.md)** — LDAP deep enumeration for Active Directory
Enumerates Active Directory objects via LDAP including users, groups, GPOs, trusts, delegations, and password policies. Useful for mapping AD structure during internal network reconnaissance when LDAP access is available.

---

## Cloud Asset Discovery

Cloud reconnaissance identifies publicly exposed resources — storage buckets, app service endpoints, virtual machine hostnames, and databases — across AWS, Azure, and Google Cloud. Combine keyword-based enumeration with Shodan to cover both brute-forced naming patterns and passively indexed services.

**[cloud-enum](tools/cloud-enum.md)** — Multi-cloud public asset enumeration
Enumerates public resources across AWS, Azure, and Google Cloud using keyword-based checks. Use it when organization names, product names, or cloud naming conventions are in scope.

**[cloudbrute](tools/cloudbrute.md)** — Cloud bucket and app endpoint brute-forcing
Brute-forces cloud resource names across providers, including object storage buckets and app endpoints. Complements cloud-enum when you have target-specific naming patterns.

**[shodan (CLI)](tools/shodan.md)** — Cloud and internet-facing asset search
Beyond traditional OSINT, Shodan indexes cloud-hosted services, exposed dashboards, databases, and misconfigured instances. Query `org:` or `hostname:` filters to discover cloud assets passively. See the OSINT section below for full details.

### Cloud Reconnaissance Pipeline

```
1. cloud-enum -k <keyword> -l results.txt   (keyword-based bucket/app enumeration)
2. cloudbrute -d <domain> -w wordlist.txt    (brute-force naming patterns)
3. shodan search org:"Target Corp"           (passively indexed cloud services)
4. Validate discovered buckets/endpoints     (confirm access, check permissions)
5. nuclei/httpx on discovered endpoints      (vulnerability and liveness checks)
```

---

## Source & Secret Scanning

**[trufflehog](tools/trufflehog.md)** — Secret scanning for git repos, filesystems, and cloud storage
Scans git repositories, filesystems, S3 buckets, and other sources for leaked secrets including API keys, passwords, tokens, and private keys. Uses regex patterns and entropy analysis to detect high-confidence findings. Essential for identifying exposed credentials during reconnaissance.

---

## Anti-Tracking

**[macchanger](../sniffing-spoofing/tools/macchanger.md)** — MAC address randomization
Changes the network interface MAC address before reconnaissance scans. Prevents the host's real hardware address from appearing in target ARP tables, DHCP logs, and switch CAM tables.

---

## Web Reconnaissance & Fingerprinting

**[whatweb](tools/whatweb.md)** — Web fingerprinting
Identifies the technology stack of target web services (CMS, frameworks, servers, languages, etc.), supports batch scanning, and helps determine which vulnerability tools to use next.

**[wafw00f](tools/wafw00f.md)** — WAF detection
Identifies whether a target has deployed a Web Application Firewall and the WAF type (supports 200+ WAF types). Must detect WAF before performing injection tests in order to choose a bypass strategy.

**[finalrecon](tools/finalrecon.md)** — All-in-one web reconnaissance
Performs header analysis, SSL inspection, WHOIS, DNS enumeration, subdomain discovery, web crawling, Wayback Machine URL retrieval, and port scanning in a single run. A fast first-pass tool before deeper specialized testing.

**[eyewitness](tools/eyewitness.md)** — Batch web service screenshots
Automatically takes screenshots of a large number of URLs and generates an HTML report, helping testers quickly and visually browse all web interfaces and identify high-value targets like login pages, admin panels, and default configuration pages.

**[gowitness](tools/gowitness.md)** — Web service screenshotting
Takes screenshots of web services from URLs or nmap/nessus output. Generates a browsable report database. Use alongside eyewitness for comprehensive visual reconnaissance.

**[httpx](tools/httpx.md)** — HTTP service liveness probing
High-speed verification of whether HTTP services are alive across large numbers of domains/IPs, while also obtaining titles, status codes, technology stacks, and other information. An essential filtering tool after subdomain enumeration.

---

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| Passive-only constraint (no target contact) | `subfinder` + `amass -passive` + `shodan` + `theHarvester`; skip nmap/naabu entirely |
| Target behind CDN/WAF, real IP needed | `dnsx` for DNS records, `certgraph` for CT-linked infrastructure, `shodan search hostname:` for historical IPs |
| subfinder/amass return few results for a known-large org | Add `certgraph` for CT-linked domains + `theHarvester` with multiple sources + `dnstwist` for typosquatting variants |

---

## Related Categories

- For the full external attack surface playbook, see `../playbooks/external-attack-surface.md`.
- For Web application and API testing after reconnaissance, see `../web/README.md`.

---

## Official References

- [Kali Tools](https://www.kali.org/tools/all-tools/)
