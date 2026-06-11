# State Files

State files persist key findings on the Agent's local host so progress survives context compression. They are NOT inside the Kali environment.

## State Directory

Location: `/tmp/kali-pentest-state/<target>/`

Naming rules for `<target>`:

| Scope | Name |
|-------|------|
| Single host | IP or hostname (e.g., `192.168.1.101`, `fileserver`) |
| CIDR range | CIDR with slash replaced (e.g., `192.168.1.0_24`, `10.0.0.0_8`) |
| Multiple discrete hosts | Short task name from user description (e.g., `corp-servers`, `lab-dmz`) |

## State Summary Files

| File | Format | Write when |
|------|--------|-----------|
| `live_hosts.txt` | One IP per line | Host discovery scan confirms a host is up |
| `open_ports.txt` | `<ip>:<port>` per line | Port scan completes or a new port is discovered |
| `services.txt` | `<ip>:<port> <service> <version>` per line | Service/version detection completes |
| `credentials.txt` | `<service> <host> <user>:<secret> <status>` per line | Credential found from any source (tool output, config files, database dumps, path traversal, SNMP strings, confirmed defaults) |
| `cred_matrix.txt` | `<user>:<secret> <host>:<service> <result>` per line | After testing a credential against a host:service — record result (success/fail/locked/error) |
| `findings.txt` | One-line summary per finding | Vulnerability confirmed via cross-validation — not on first tool report |
| `todo.txt` | One item per line, prefix `[playbook]` for return entries | Service untestable now; switching playbooks (record return point); test deferred by constraint |
| `decisions.txt` | `[TYPE] <subject> — reason: <why>` per line | After any skip, replacement, N/A, or strategy decision that affects subsequent phases |
| `command_log.txt` | `[ISO8601] [tool] [command] -> [output_file or "inline"]` per line | After each tool command execution |

## Raw Tool Output

Raw tool output stays inside the Kali environment (`/tmp/` on the SSH server or Docker container):

| Data | Preferred format |
|------|------------------|
| Host and port scans | XML/grepable + JSON (machine-parseable, all major scanners support these) |
| HTTP inventory | JSON, screenshots |
| Vulnerabilities | JSONL or structured HTML |
| Web crawling | URL lists, HAR/flow captures |
| Credentials and hashes | tool output plus source context, scope, and validation status |
| Evidence | screenshots, raw request/response, proof commands, timestamps |
