# Server Mode

Server mode means using a full Kali Linux VM, bare-metal host, or cloud instance over SSH. This is the recommended environment for maximum Kali capability.

## When to Use

Use server mode for:

- full penetration tests,
- internal LAN and ARP-dependent testing,
- raw-socket scanning and OS fingerprinting,
- wireless testing with physical adapters,
- GPU password cracking,
- service-backed tools such as GVM/OpenVAS, Metasploit database, BloodHound/Neo4j, and ZAP daemon,
- long-running scans, databases, and background services.

## Non-Interactive SSH Access

When using password-based SSH, non-interactive scripts will hang waiting for input. On first connection, generate a key pair and deploy it using `expect` to supply the password:

```bash
# 1. Generate key (skip if ~/.ssh/kali_pentest already exists)
ssh-keygen -t ed25519 -f ~/.ssh/kali_pentest -N ''

# 2. Deploy public key via expect (one-time, uses password)
expect -c "
spawn ssh-copy-id -i $HOME/.ssh/kali_pentest.pub -o StrictHostKeyChecking=no user@host
expect \"password:\"
send \"PASSWORD\r\"
expect eof
"

# 3. All subsequent commands use key — no password needed
ssh -i ~/.ssh/kali_pentest user@host "command"
scp -i ~/.ssh/kali_pentest file user@host:/tmp/
# sudo requires a TTY — use ssh -t:
ssh -t -i ~/.ssh/kali_pentest user@host "sudo apt-get install -y <package>"
```

If the host key changes (e.g., Kali was reinstalled), clear the stale entry: `ssh-keygen -R <host-ip>`

## Readiness Checks

Run these to verify the system environment is operational. Individual tools are installed on-demand by playbooks using `which <tool> || apt-get install -y <tool>` — do not pre-install every tool here.

```bash
whoami && id
uname -a
ip addr
ip route
df -h
systemctl --version                   # service manager available
apt-get update -qq && echo "apt OK"   # package manager reachable
ping -c 2 kali.org && echo "network OK"
ls /usr/share/wordlists /usr/share/seclists 2>/dev/null
```

If the SSH user is not root, use the privilege method authorized by the user before installing packages or managing services.

## Kali Packages

Choose packages based on task scope:

| Package | Use |
|---|---|
| `kali-linux-default` | General Kali environment with common tools |
| `kali-linux-large` | Broader tool coverage for full assessments |
| `kali-linux-everything` | Maximum coverage; very large, use selectively |
| `kali-tools-top10` | Fast baseline set |
| `kali-tools-web` | Web testing |
| `kali-tools-information-gathering` | Reconnaissance |
| `kali-tools-exploitation` | Exploitation frameworks |
| `kali-tools-passwords` | Password attacks |
| `kali-tools-forensics` | Forensics |
| `kali-tools-wireless` | Wireless testing |

```bash
apt-get update
apt-get install -y kali-linux-default seclists wordlists
```

## Service-Backed Tools

Full Kali can run tools that depend on services or local databases.

### Metasploit

```bash
msfdb status
msfdb init
msfdb run
```

Use database-backed Metasploit workflows when tracking hosts, services, vulnerabilities, and credentials across a larger assessment.

### GVM/OpenVAS

```bash
gvm-check-setup
gvm-start
```

Use GVM/OpenVAS only for Deep assessments or when the user explicitly wants comprehensive vulnerability scanning. Expect long setup and scan times.

### BloodHound/Neo4j

```bash
systemctl status neo4j
systemctl start neo4j
```

Use BloodHound for Active Directory attack path analysis after collection is authorized.

### OWASP ZAP

```bash
zaproxy -cmd -version
zap.sh -daemon -host 127.0.0.1 -port 8080
```

Prefer ZAP Automation Framework, daemon/API mode, or packaged scan scripts for unattended agent workflows.

## Updating Data Sources

Before deep scans, check whether local data is stale:

```bash
nuclei -version
nuclei -update-templates
searchsploit -u
nmap --script-updatedb
```

Do not spend assessment time updating large databases unless the scan requires it or the user approved the delay.

## Hardware and Network Checks

For GPU cracking:

```bash
hashcat -I
```

For wireless testing:

```bash
iw dev
airmon-ng
```

For same-LAN testing, verify the target network is reachable from Kali itself, not just from the user's workstation.

## Operational Notes

- Keep generated logs and reports in task-specific files.
- Preserve service databases and installed tools across sessions.
- Do not clear long-lived service data unless the user explicitly requests a clean rebuild.
