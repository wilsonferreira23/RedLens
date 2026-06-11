# Digital Forensics

Digital forensics is used to collect, preserve, and analyze digital evidence. It is also an important capability in penetration testing for analyzing target systems and extracting valuable information.

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| Disk imaging | `dc3dd` (with hash verification) | Use `dd` when simple dd is sufficient |
| File recovery | `foremost` | Use `testdisk` for deep filesystem recovery |
| Memory analysis | `volatility3` | — |
| Traffic analysis | `tshark` (protocol filter) or `tcpdump` (BPF live capture) | Use Wireshark GUI for deep interactive analysis |
| Metadata extraction | `exiftool` | — |
| Steganography analysis | `stegseek` (JPEG brute-force) → `steghide` (extract) | — |
| Windows log analysis | `chainsaw` (EVTX + Sigma rules) | Use `grep`/`awk` for Linux logs |
| Bulk data extraction | `bulk-extractor` | — |
| Firmware analysis | `binwalk -eM` (recursive extract) | — |
| Timeline generation | `plaso` (log2timeline.py → psort.py) | Use `fls -m` + `mactime` for quick filesystem-only timeline |
| Malware triage | `yara -r` (rule-based scan) | — |
| Disk forensics | `sleuthkit` (mmls → fls → icat) | Use `foremost` for header-based carving |
| Damaged media recovery | `ddrescue` (image) → `foremost`/`sleuthkit` (analyze) | Use `dc3dd` when media is healthy |
| Windows registry analysis | `regripper` | — |
| Rootkit detection | `chkrootkit` + `rkhunter` | — |

---

## Memory Forensics

**[volatility3](tools/volatility.md)** — Memory image analysis  
The industry-standard memory forensics framework. Analyzes memory dump files to extract processes, network connections, registry entries, password hashes, malicious code, and more. An irreplaceable tool for memory analysis.  

---

## Disk Forensics

**[foremost](tools/foremost.md) / [scalpel](tools/scalpel.md)** — File recovery  
Recovers deleted files from disk images based on file header/footer signatures. Supports common formats such as JPEG, PNG, PDF, and ZIP.  

**[scalpel](tools/scalpel.md)** — Header/footer-based file carving  
Carves files from disk images or raw devices based on configurable header and footer signatures. More precise than foremost with user-defined carving rules. Useful for recovering specific file types from damaged or fragmented media.  

**[dc3dd](tools/dc3dd.md)** — Forensic disk imaging  
A patched version of GNU dd adding on-the-fly hashing (MD5/SHA256), split output, error recovery, and operation logging. The standard tool for creating forensically sound disk images with chain-of-custody hash verification.  

**[dcfldd](tools/dcfldd.md)** — Enhanced forensic disk imaging  
An enhanced version of dd with on-the-fly hashing (MD5/SHA-1/SHA-256/SHA-512), split output for large images, and hash verification. Provides status output during imaging and supports multiple simultaneous output files.  

**[sleuthkit](tools/sleuthkit.md)** — CLI disk forensics toolkit  
A collection of command-line tools (mmls, fls, icat, tsk_recover) for partition analysis, file listing, deleted file recovery, and timeline generation from disk images. The standard open-source toolkit for filesystem-level forensic examination.  

**[testdisk](tools/testdisk.md)** — Partition recovery and file restoration  
Recovers lost partitions, repairs boot sectors, and restores deleted files from FAT, NTFS, ext2/3/4, and other filesystems. Essential when disk corruption or accidental deletion has occurred and filesystem-level recovery is needed.  

**[ddrescue](tools/ddrescue.md)** — Data recovery from damaged media  
Copies data from damaged storage devices with mapfile-based progress tracking, automatic retry of failed sectors, and reverse-direction reads. Use when standard dd fails due to bad sectors or intermittent read errors on the source media.  

**[hashdeep](tools/hashdeep.md)** — Recursive multi-algorithm hash computation and audit  
Computes MD5, SHA-1, SHA-256, and other hashes recursively across directory trees and performs audit-mode integrity verification against known-good baselines. Essential for evidence integrity verification and detecting unauthorized file modifications.  

---

## Firmware Analysis

**[binwalk](../reverse-engineering/tools/binwalk.md)** — Firmware analysis and extraction  
Scans binary files for embedded file signatures, extracts firmware components (filesystems, compressed archives, bootloaders), and performs entropy analysis to detect encrypted or compressed sections. Essential for IoT and embedded device forensics.  

---

## Traffic Analysis

**[tcpdump](tools/tcpdump.md)** — Command-line packet capture  
A pre-installed command-line packet analyzer available on virtually every Linux system. Captures traffic in real time or reads pcap files. Ideal for headless/server/Docker environments.  

**[tshark](tools/tshark.md)** — Command-line protocol analyzer  
The CLI version of Wireshark. Supports Wireshark's powerful display filter syntax for protocol-aware filtering and field extraction from pcap files. More expressive than tcpdump for complex protocol analysis.  

**[tcpflow](tools/tcpflow.md)** — TCP stream reassembly  
Captures and reassembles TCP streams from live traffic or pcap files, saving each stream as a separate file. Useful for extracting transferred files, HTTP sessions, and other application-layer data from network captures.  

---

## Metadata & Steganography

**[exiftool](tools/exiftool.md)** — File metadata extraction  
Extracts metadata from 200+ file formats including images, PDFs, and Office documents. Can retrieve GPS coordinates, author information, device model, and more. Essential for OSINT and forensics scenarios.  

**[steghide](tools/steghide.md)** — Steganography analysis  
Detects and extracts hidden secret data from images and audio files (JPEG/BMP/WAV/AU). Commonly encountered in CTF and forensics scenarios.  

**[stegseek](tools/stegseek.md)** — Ultra-fast steghide passphrase cracker  
Brute-forces steghide passphrases in JPEG images using a wordlist. Can crack rockyou.txt in under 2 seconds — far faster than manual steghide attempts. The first tool to run against suspicious JPEG files in CTF scenarios.  

---

## Windows Event Log Analysis

**[chainsaw](tools/chainsaw.md)** — Windows event log threat hunting  
High-speed forensic tool for hunting threats in Windows EVTX logs using Sigma rules and custom detection rules. Processes thousands of event log files in seconds. Essential for incident response and red team evasion checking.  

---

## Windows Registry Analysis

**[regripper](tools/regripper.md)** — Windows Registry hive analysis  
Extracts forensically relevant data from Windows Registry hive files using plugin-based analysis. Retrieves user activity, installed software, USB device history, network connections, and other artifacts. Essential for offline Windows forensic examinations.  

---

## Bulk Artifact Extraction

**[bulk-extractor](tools/bulk-extractor.md)** — Raw forensic artifact extraction  
Scans disk images without mounting them, extracting emails, URLs, credit card numbers, domains, and other artifacts. Extremely fast and works on corrupted or fragmented storage where file system tools fail.  

---

## Malware Analysis

**[yara](tools/yara.md)** — Pattern-based malware identification  
Scans files, directories, and running processes against custom signature rules to identify malware families, suspicious patterns, and indicators of compromise. Supports regex, hex strings, and condition-based matching across signature databases.  

**[chkrootkit](tools/chkrootkit.md)** — Rootkit detection for Unix/Linux  
Scans local systems for signs of known rootkits, worms, and LKM trojans by checking system binaries, network interfaces, and log files. A quick first-pass tool for rootkit detection during incident response or post-compromise analysis.  

**[rkhunter](tools/rkhunter.md)** — Rootkit Hunter  
Scans for rootkits, backdoors, and suspicious system modifications by checking file properties, default directories, wrong permissions, hidden files, and kernel modules. More comprehensive than chkrootkit with additional checks for suspicious strings and startup file modifications.  

**[ssdeep](tools/ssdeep.md)** — Fuzzy hashing for file similarity detection  
Computes context-triggered piecewise hashes (fuzzy hashes) that identify files with similar content even when they are not identical. Useful for detecting malware variants, comparing document versions, and clustering related files in forensic investigations.  

---

## Evidence Handling and Timeline Construction

For evidence handling procedures and timeline construction methodology, see [forensics-triage playbook](../playbooks/forensics-triage.md).

**[plaso](tools/plaso.md)** — Super-timeline generation engine  
Automates timeline construction using log2timeline.py (extraction) and psort.py (sorting/filtering). Merges timestamped events from disk images, Windows registries, event logs, browser history, and other sources into a single unified timeline. Far more comprehensive than manual MAC-time correlation.  

---

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| Memory dump from unknown OS version | `volatility3 banners` to identify profile; if no match, try `strings` + `grep` for quick artifact extraction |
| Large pcap (>1GB), need specific protocol extraction | `tshark -Y <filter> -T fields` for targeted export; avoid loading full pcap into memory |
| Multiple evidence sources, need correlated timeline | `plaso` (log2timeline.py) merges all sources; `fls -m` + `mactime` only for quick filesystem-only timeline |
| Need to verify evidence integrity after transfer | `hashdeep -r` to compute recursive hashes; compare against acquisition-time hashes |
| Encrypted volume encountered | Check for BitLocker/LUKS/FileVault; extract keys from memory dump (`volatility3`) if available |

---

## Playbook

For a full scenario workflow covering phases, decision points, and risk gates, see `../playbooks/forensics-triage.md`.

---

## Official References

- [Kali Tools](https://www.kali.org/tools/all-tools/)
