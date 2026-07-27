# Password Attacks (Password)

Password attacks cover techniques including online brute-forcing, offline hash cracking, wordlist generation, and network hash capture. They are a key method for gaining access during penetration testing.

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| Hash type identification | `hashid` | — |
| GPU hash cracking | `hashcat` | Use `john` when no GPU is available |
| CPU hash cracking | `john` | — |
| SSH/FTP/Web brute-force | `hydra` | Use `crowbar` for RDP |
| AD account enumeration | `kerbrute userenum` | — |
| AD password spraying | `kerbrute passwordspray` or `netexec` | Use `hydra` for non-AD services |
| Multi-protocol/fine-grained | `medusa` or `patator` | — |
| NTLM hash capture | `responder` | Same broadcast domain required on internal network |
| Wordlist generation | `cewl` (target-custom) + `crunch` (rule-based) | — |
| ZIP password cracking | `fcrackzip` | Use `john` for RAR/7z/PDF |
| Offline Windows SAM | `chntpw` | — |
| Network authentication cracking | `ncrack` | Use `hydra` for most protocols |
| Default credential scan | `changeme` | — |
| Hash type auto-identification | `name-that-hash` | — |

---

## Hash Extraction Sources

Before cracking, you need hashes. Know where they come from and which tool extracts them.

| Source | OS/Platform | Hash Type | Extraction Tool |
|--------|-------------|-----------|-----------------|
| SAM database | Windows (local) | NTLM | `impacket-secretsdump -sam SAM -system SYSTEM LOCAL` or `mimikatz lsadump::sam` |
| NTDS.dit | Windows (domain controller) | NTLM | `impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL` or `netexec smb <dc> --ntds` |
| LSASS memory | Windows (live) | NTLM, Kerberos tickets | `mimikatz sekurlsa::logonpasswords` or `lsassy` (remote, fileless) |
| LSA Secrets | Windows | Service account passwords | `impacket-secretsdump` or `mimikatz lsadump::secrets` |
| DPAPI secrets | Windows | Browser passwords, WiFi, RDP creds | `dploot` (remote) or `mimikatz dpapi::` |
| `/etc/shadow` | Linux | SHA-512 (`$6$`), SHA-256 (`$5$`), bcrypt (`$2b$`) | Direct file read with root access; `unshadow` to merge with `/etc/passwd` for john |
| Database tables | Any | MD5, SHA-1, bcrypt, application-specific | SQL queries (`SELECT user, password FROM users`) |
| Application configs | Any | Various | Grep config files for password hashes, API keys |
| Network capture | Internal network | NetNTLMv1/v2 | `responder` (LLMNR/NBT-NS poisoning) |
| Kerberos | AD | Kerberos TGS (krb5tgs) | `impacket-GetUserSPNs` (Kerberoasting) |

Cross-references:
- `../post-exploitation/tools/mimikatz.md` -- Windows memory and SAM extraction
- `../exploitation/tools/impacket.md` -- secretsdump for SAM, NTDS.dit, LSA Secrets
- `../post-exploitation/tools/lsassy.md` -- remote fileless LSASS dumping
- `../post-exploitation/tools/dploot.md` -- remote DPAPI secret extraction

---

## Online Password Brute-Force

**[hydra](tools/hydra.md)** — Multi-protocol online password brute-force
A password brute-forcing tool supporting 50+ protocols; the go-to choice for online brute-forcing. Supports SSH, FTP, HTTP forms, RDP, SMB, MySQL, and more. Fast with multi-threaded concurrency. Account lockout policies must be carefully considered.

**[medusa](tools/medusa.md)** — Parallel multi-protocol brute-force
Functionally similar to hydra, but more stable for protocols like MSSQL and VNC. Supports concurrent batch host testing; ideal for large-scale internal network brute-forcing scenarios.

**[patator](tools/patator.md)** — Modular multi-protocol brute-force and fuzzing
A flexible brute-force framework with modules for SSH, FTP, HTTP, SMTP, SMB, LDAP, RDP, DNS, and more. Use it when hydra/medusa syntax is too rigid or when a protocol-specific module and response matching are needed.

**[kerbrute](tools/kerbrute.md)** — Kerberos username enumeration and password spraying
Enumerates valid AD accounts and sprays passwords via Kerberos (port 88/UDP), bypassing some lockout policies. Username enumeration requires no password and generates minimal logs. Flags AS-REP roastable accounts during enumeration.

**[netexec](tools/netexec.md)** — Windows network batch exploitation (CrackMapExec successor)
The maintained successor to CrackMapExec. Tests SMB/WinRM/LDAP/MSSQL/SSH/RDP across entire subnets, executes commands, dumps SAM/LSA/LSASS, and runs post-exploitation modules. The Swiss Army knife for lateral movement.

**[brutespray](tools/brutespray.md)** — nmap-driven default credential spraying
Automatically sprays default credentials against services discovered in an nmap XML scan. Reads nmap output, identifies service types (SSH, FTP, MySQL, VNC, etc.), and tests built-in default username/password combinations. Bridges scanning and initial access in a single command.

**[crowbar](tools/crowbar.md)** — RDP/OpenVPN/SSH-key brute-force
A brute-force tool targeting protocols not reliably supported by hydra: RDP, OpenVPN, SSH private key authentication, and VNC key authentication. The most reliable tool for RDP credential testing — use instead of hydra for RDP targets.

**[ncrack](tools/ncrack.md)** — Network authentication cracker
The Nmap project's high-speed network authentication cracker supporting 20+ protocols including SSH, RDP, FTP, SMB, VNC, HTTP(S), POP3, IMAP, Telnet, and more. Designed for large-scale parallel credential testing with adaptive timing.

---

## Offline Hash Cracking

**[hashcat](tools/hashcat.md)** — GPU-accelerated hash cracking
The industry's fastest hash cracking tool. Uses GPU acceleration, supports 450+ hash types (MD5/SHA/NTLM/bcrypt/NetNTLMv2, etc.), and multiple attack modes including dictionary, rule-based, mask, and hybrid attacks.

**[john](tools/john.md)** — John the Ripper hash cracking
A classic hash cracking tool with comprehensive functionality and a built-in rule generation system. Excellent at handling Linux shadow files and various encrypted files (ZIP/PDF/RAR). Runs on CPU; complements hashcat.

### Attack Mode Selection

Choose the attack mode based on what you know about the password policy and target environment:

| Mode | hashcat Flag | When to Use |
|------|-------------|-------------|
| Dictionary | `-a 0` | First attempt. Use `rockyou.txt` or target-custom wordlist from `cewl`. Fastest for common passwords. |
| Dictionary + Rules | `-a 0 -r <rule>` | After plain dictionary fails. Rules mutate each word (capitalize, append digits, leet-speak). |
| Mask (brute-force) | `-a 3` | Known password pattern (e.g., `Company@?d?d?d?d` for "Company@" + 4 digits). |
| Hybrid wordlist+mask | `-a 6` | Append mask to dictionary words (e.g., `rockyou.txt` + `?d?d?d`). |
| Hybrid mask+wordlist | `-a 7` | Prepend mask to dictionary words. |

### Recommended Rules (most effective first)

1. **`best64.rule`** -- Small, fast, catches ~50% of rule-crackable passwords. Always start here.
2. **`OneRuleToRuleThemAll.rule`** -- Community-maintained comprehensive rule. Good balance of speed and coverage.
3. **`dive.rule`** -- Very large rule set (~100k rules). Use only when faster rules have been exhausted.
4. **`d3ad0ne.rule`** -- Large, aggressive. Useful for high-value hashes where time is not a constraint.

### Typical Cracking Order

```
1. hashcat -a 0 -m <mode> hashes.txt rockyou.txt                          # plain dictionary
2. hashcat -a 0 -m <mode> hashes.txt rockyou.txt -r best64.rule           # dictionary + rules
3. hashcat -a 0 -m <mode> hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule
4. hashcat -a 3 -m <mode> hashes.txt ?u?l?l?l?l?l?d?d?d?s                # mask for policy
5. hashcat -a 6 -m <mode> hashes.txt rockyou.txt ?d?d?d                   # hybrid
```

**Slow hash types (bcrypt, scrypt, Argon2, phpass):** The cracking order above assumes fast hash types. For slow hashes like bcrypt (`$2*$`, mode 3200), each rule multiplies an already-slow base cost — large rule files (dive.rule, d3ad0ne.rule) are impractical. Adapt the strategy: use shorter wordlists (top-1000 passwords or target-custom from `cewl`), limit rules to `best64.rule`, prefer mask attacks when the password policy is known, and consider `john --incremental` for short passwords (8 characters or fewer).

---

## Wordlist Generation

**[cewl](tools/cewl.md)** — Target website custom wordlist
Crawls a target website to generate a customized password wordlist using target-related vocabulary. Useful when generic wordlists fail.

**[crunch](tools/crunch.md)** — Rule-based wordlist generation
Generates password wordlists based on specified character sets and length rules. Ideal for scenarios with known password patterns (e.g., "company name + 4 digits").

---

## Hash Identification & Rainbow Tables

**[hashid](tools/hashid.md)** — Hash type identification
Identifies hash types from raw hash strings and provides the corresponding hashcat mode and john format. An essential first step before cracking — using the wrong algorithm wastes time.

**[name-that-hash](tools/name-that-hash.md)** — Modern hash type identifier
A modern successor to `hashid` with improved accuracy, hashcat mode (`-m`) output, and john format (`--format`) suggestions. Provides confidence-ranked results and handles more hash formats. Use alongside or instead of `hashid` for faster hash identification workflows.

**[rainbowcrack](tools/rainbowcrack.md)** — Rainbow table hash cracking
Uses precomputed rainbow tables to crack unsalted hashes (NTLM, LM, MD5) near-instantaneously. Complements hashcat — use when precomputed tables are available for the target hash type.

---

## Network Hash Capture

**[responder](tools/responder.md)** — LLMNR/NBT-NS poisoning and capture
Captures internal network NetNTLM hashes through LLMNR/NBT-NS protocol poisoning. Combined with offline cracking via hashcat, this is a classic technique for obtaining credentials during internal network penetration. Requires being on the same LAN.

---

## Group Policy Credential Recovery

**[gpp-decrypt](tools/gpp-decrypt.md)** — Group Policy Preferences password decryption
Decrypts passwords stored in Group Policy Preferences (GPP) XML files found on SYSVOL shares. Uses the publicly known AES key that Microsoft published, making decryption instant. A quick win during internal network assessments when GPP XML files are discovered.

---

## Archive Password Cracking

**[fcrackzip](tools/fcrackzip.md)** — ZIP archive password cracker
A fast ZIP archive password cracker supporting dictionary attacks and brute-force with configurable character sets and length ranges. Validates cracked passwords using unzip (always use `-u` to avoid false positives). For RAR, 7z, and PDF archives use `john` or `hashcat` instead.

**[pdfcrack](tools/pdfcrack.md)** — PDF password recovery
Cracks PDF user and owner passwords via brute-force and wordlist attacks. Supports PDF versions up to 1.6 with various encryption strengths. Use for PDF files; for ZIP/RAR/7z use `fcrackzip` or `john`.

---

## Default Credential Scanning

**[changeme](tools/changeme.md)** — Default credential scanner
Scans network services for default and known credentials across HTTP, SSH, FTP, MySQL, MSSQL, PostgreSQL, Redis, MongoDB, SNMP, and other protocols. Automates the tedious process of checking for factory-default passwords on discovered services.

---

## Offline Windows Password Recovery

**[chntpw](tools/chntpw.md)** — Offline Windows SAM password reset
Edits Windows SAM database files directly to view or reset user passwords — no Windows login required. Requires physical or filesystem access (boot from Kali live media). Cannot access BitLocker-encrypted volumes.

---

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| Fast hash (NTLM, MD5, SHA-1) | `hashcat -a 0` with `rockyou.txt` → `best64.rule` → mask if policy known |
| Slow hash (bcrypt, scrypt, Argon2) | Short wordlist (top-1000) + `best64.rule` only; prefer mask if policy known; `john --incremental` for ≤8 chars |
| NetNTLMv2 captured via responder | `hashcat -m 5600`; dictionary + rules only (brute-force too slow for this hash type) |
| Kerberos TGS (krb5tgs) | `hashcat -m 13100` (RC4) or `-m 19700` (AES); dictionary + rules first |
| hydra fails or hangs on a protocol | `medusa` (more stable for MSSQL/VNC) or `patator` (custom response matching) |
| AD password spray, lockout policy unknown | `netexec smb --pass-pol` first to check lockout threshold before spraying |
| hashcat exhausts dictionary + rules, no crack | Escalate: mask attack with known policy pattern → hybrid (`-a 6`/`-a 7`) → `princeprocessor` piped into hashcat |
| Multiple hash types in one dump | Separate by type, identify each with `name-that-hash`, crack in parallel with correct `-m` modes |

---

## Cross-References

- **Password audit playbook**: `../playbooks/password-audit.md` -- full password audit scenario with policy review, hash extraction, cracking methodology, and reporting.
- **Active Directory playbook**: `../playbooks/active-directory.md` -- Kerberoasting, AS-REP roasting, password spraying, and credential relay workflows.
- **Post-exploitation credential tools**: `../post-exploitation/README.md` -- mimikatz, lsassy, dploot for credential harvesting after initial access.

---

## Official References

- [Kali Tools](https://www.kali.org/tools/all-tools/)
