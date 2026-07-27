# Amass

- **Category**: Information Gathering / Subdomain Enumeration / Attack Surface Discovery
- **Risk Level**: 🟡 Medium

---

## Description

Amass is an OWASP project for subdomain enumeration and network attack surface discovery, and is one of the most powerful subdomain enumeration tools available. It integrates over 50 data sources, supports both active and passive enumeration modes, and provides visual network topology maps.

## Installation

```bash

amass -version     # v3 style; v4/v5 uses: amass version

# Also works
amass -h

sudo apt install amass

# Install latest version using Go (v4/v5)
go install -v github.com/owasp-amass/amass/v4/...@master
# ⚠️  amass v5 (current Kali default) significantly restructured config format and subcommands vs v3
#    v5 adds: engine, subs, assoc subcommands; removes intel, db
#    The examples below apply primarily to v3/v4 style. v5 behavior may differ — check `amass -h`.

# Configure API keys (strongly recommended)
mkdir -p ~/.config/amass
# Copy example config:
# v3 (Kali default) uses INI format:
# The example path varies by Kali/distro version; common locations:
#   /usr/share/amass/examples/config.ini
#   /usr/share/doc/amass/examples/config.ini
# Try both; if neither exists, copy from the GitHub repo or create from scratch.
cp /usr/share/amass/examples/config.ini ~/.config/amass/config.ini 2>/dev/null || \
  cp /usr/share/doc/amass/examples/config.ini ~/.config/amass/config.ini
# v4/v5 (Go install) uses YAML format:
# cp /usr/share/amass/examples/config.yaml ~/.config/amass/config.yaml
# Edit the config file to fill in API Keys for each data source
```

## Parameter Reference

### Subcommands

> ⚠️  **v5 (current Kali default) has significantly restructured subcommands vs v3/v4. See the version notes below.**

**v5 subcommands (current Kali default — v5.x):**

| Parameter | Description |
|-----------|-------------|
| `enum` | Interface with the enumeration engine |
| `engine` | Run the collection engine to populate the OAM database |
| `subs` | Analyze and present discovered subdomains |
| `track` | Identify newly discovered assets |
| `viz` | Generate graph visualizations |
| `assoc` | Query the OAM along walk-defined triples |

**v3/v4 subcommands (legacy; shown for reference):**

| Parameter | Description |
|-----------|-------------|
| `enum` | Subdomain enumeration (core feature) |
| `intel` | Target organization information gathering |
| `viz` | Visualize results as charts |
| `track` | Track changes in assets |
| `db` | Manage the database |

### enum Subcommand Parameters

| Parameter | Description |
|-----------|-------------|
| `-d <domain>` | Specify target domain Example: `-d example.com` |
| `-df <file>` | Read domain list from file Example: `-df domains.txt` |
| `-o <file>` | Output file Example: `-o results.txt` |
| `-oA <dir>` | Output to directory (multiple formats) Example: `-oA output/` |
| `-json <file>` | JSON format output Example: `-json results.json` |
| `-passive` | Pure passive mode (no active queries) |
| `-active` | Active mode (zone transfers, etc.) |
| `-brute` | Enable DNS brute-forcing |
| `-w <wordlist>` | Specify wordlist file Example: `-w wordlist.txt` |
| `-min-for-recursive` | Minimum subdomains to trigger recursive enumeration Example: `-min-for-recursive 1` |
| `-src` | Show data source |
| `-ip` | Show IP addresses |
| `-ipv4` | Only show IPv4 |
| `-ipv6` | Only show IPv6 |
| `-r <resolver>` | Custom DNS resolver Example: `-r 8.8.8.8` |
| `-rf <file>` | Read resolvers from file |
| `-bl <domain>` | Blacklist domain |
| `-blf <file>` | Read blacklist from file |
| `-nolocaldb` | Do not use local database |
| `-config <file>` | Configuration file path |
| `-dir <dir>` | Output directory |
| `-timeout <minutes>` | Timeout duration Example: `-timeout 30` |
| `-max-dns-queries` | Maximum DNS queries |
| `-dns-qps <n>` | DNS queries per second Example: `-dns-qps 1000` |
| `-share` | Share enumeration state |
| `-include-unresolvable` | Include unresolvable subdomains |
| `-ef <file>` | Exclude data sources file |
| `-exclude <source>` | Exclude specified data source |
| `-if <file>` | Only use data sources from file |
| `-include <source>` | Only use specified data source |

### intel Subcommand Parameters

| Parameter | Description |
|-----------|-------------|
| `-org <org>` | Query by organization name |
| `-asn <ASN>` | Query by ASN |
| `-cidr <CIDR>` | Query by CIDR |
| `-whois` | Perform WHOIS lookup |
| `-d <domain>` | Specify target domain |
| `-ip` | Show IPs |
| `-ipv4 / -ipv6` | Filter by IP version |

## Common Commands

### Scenario 1: Quick Passive Enumeration

```bash
# Passive mode enumeration (fastest, no active queries)
amass enum -passive -d example.com

# Passive enumeration with IP display
amass enum -passive -d example.com -ip

# Passive enumeration of multiple domains
amass enum -passive -df domains.txt -o results.txt
```

### Scenario 2: Active Enumeration (More Comprehensive)

```bash
# Active enumeration (default mode)
amass enum -d example.com

# Enable DNS brute-forcing
amass enum -brute -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Active mode + zone transfer attempts
amass enum -active -d example.com

# Full enumeration (active + brute-force + show sources)
amass enum -active -brute -d example.com -src -ip -o full_enum.txt
```

### Scenario 3: Organization Intelligence Gathering

```bash
# Discover assets by organization name
amass intel -org "Example Corp"

# Discover related IPs by ASN
amass intel -asn 12345

# Discover related domains by IP range
amass intel -cidr 203.0.113.0/24

# WHOIS reverse lookup
amass intel -d example.com -whois
```

### Scenario 4: Persistence and Tracking

```bash
# Save results to a specified directory (with graph database)
amass enum -d example.com -dir ./amass_output

# Track newly discovered subdomains (requires existing database)
amass track -d example.com -dir ./amass_output

# Query the database
amass db -dir ./amass_output -d example.com -list
```

### Scenario 5: Visualization

```bash
# Generate D3.js visualization chart
amass viz -d3 -dir ./amass_output

# Generate Gephi format (for advanced graph analysis)
amass viz -gephi -dir ./amass_output
```

### Scenario 6: Using API Keys (Recommended)

```ini
# ~/.config/amass/config.ini example configuration (v3/v4 — INI format)
# Note: amass v5 (current Kali default, Go install) uses YAML format instead; see installation notes above.

[data_sources.SecurityTrails]
[data_sources.SecurityTrails.Credentials]
apikey = YOUR_API_KEY

[data_sources.Shodan]
[data_sources.Shodan.Credentials]
apikey = YOUR_API_KEY

[data_sources.VirusTotal]
[data_sources.VirusTotal.Credentials]
apikey = YOUR_API_KEY

[data_sources.Censys]
[data_sources.Censys.Credentials]
apikey = YOUR_API_ID
secret = YOUR_SECRET
```

```bash
# Use configuration file (automatically loads API keys; v3/v4 style)
amass enum -d example.com -config ~/.config/amass/config.ini
```

## Notes & Tips

1. Configuring API keys significantly increases discovered subdomains — at minimum, configure VirusTotal and Shodan. View supported data sources with `amass enum -list`.
2. Use `-dns-qps` to control DNS query rate and avoid being blocked by resolvers.
3. Custom DNS resolvers (`-r 8.8.8.8,1.1.1.1`) improve speed and stability over system defaults.
4. Set `-timeout 30` to prevent long-running enumerations from hanging indefinitely.

---

## Official References

- [OWASP Amass GitHub](https://github.com/owasp-amass/amass)
- [Amass Documentation](https://owasp-amass.github.io/docs)
