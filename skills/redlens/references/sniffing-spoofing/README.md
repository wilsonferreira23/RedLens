# Sniffing & Spoofing

Intercept, manipulate, and forge network traffic on local and adjacent network segments. Covers ARP/DNS spoofing, credential sniffing, SSL stripping, MAC flooding, and custom packet crafting.

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|----|
| ARP cache poisoning / MITM | `bettercap` | Use `ettercap -T` for simple ARP spoofing on flat LANs |
| Credential sniffing (cleartext protocols) | `dsniff` | Use `bettercap` when SSL stripping is also needed |
| DNS spoofing | `dsniff` (dnsspoof) or `bettercap` | Use `dnschef` when only specific domains need spoofing |
| MAC flooding | `dsniff` (macof) | — |
| Custom packet crafting | `scapy` | Use `hping3` for quick single-packet tests |
| Firewall rule testing / TCP traceroute | `hping3` | Use `scapy` for complex multi-packet sequences |
| SSL stripping | `bettercap` | — |
| Pattern search in traffic | `ngrep` | Use `tshark` display filters for protocol-aware extraction |

---

## Network MITM

**[bettercap](tools/bettercap.md)** — Modern network MITM and attack framework
A fully-featured network attack framework and modern replacement for Ettercap. Supports ARP spoofing, DNS spoofing, SSL stripping, HTTP/HTTPS traffic interception, WiFi attacks, and BLE scanning. Provides an interactive console, Web UI, and REST API for automation.

**[ettercap](tools/ettercap.md)** — LAN man-in-the-middle attack suite
A comprehensive MITM attack suite for LAN environments. Supports ARP poisoning, ICMP redirect, and DHCP spoofing to intercept traffic between hosts; automatically dissects and displays credentials from HTTP, FTP, Telnet, POP3, and other protocols. Always use `-T` (text mode) for CLI/automated operation.

**[dsniff](tools/dsniff.md)** — Network sniffing and spoofing suite
A collection of network auditing tools including `arpspoof` (ARP poisoning), `dnsspoof` (DNS spoofing), `macof` (MAC flooding), `urlsnarf` (URL logging), `tcpkill` (connection termination), and passive password sniffing for 30+ cleartext protocols. Useful for targeted interception tasks when bettercap's full framework is not needed.

**[dnschef](tools/dnschef.md)** — Configurable DNS proxy for domain spoofing
A highly configurable DNS proxy that selectively spoofs DNS responses for specified domains while passing all other queries to a legitimate upstream resolver. Useful during MITM attacks for redirecting specific services without disrupting all DNS traffic.

**[sslstrip](tools/sslstrip.md)** — HTTPS downgrade attack tool
Strips SSL/TLS from HTTPS connections between the victim and the attacker proxy, presenting HTTP to the victim while maintaining HTTPS to the server. Used in MITM scenarios to capture credentials transmitted over supposedly secure connections.

---

## Packet Crafting

**[scapy](tools/scapy.md)** — Python packet manipulation framework
Crafts, sends, sniffs, and dissects packets at any protocol layer from Python. More flexible than hping3 for complex scenarios: ARP scanning, custom protocol fuzzing, PoC exploit development, and multi-step packet exchanges. Used both interactively and as a Python library.

**[hping3](tools/hping3.md)** — Custom TCP/IP packet crafting
An active network packet crafting tool supporting TCP, UDP, ICMP, and raw IP modes. Used for firewall rule testing, port scanning with custom TCP flags, TCP traceroute that bypasses ICMP filters, and DoS simulation. Irreplaceable for low-level network probing where fine-grained single-packet control is needed.

**[netsniff-ng](tools/netsniff-ng.md)** — High-performance zero-copy packet capture toolkit
A high-performance Linux networking toolkit featuring zero-copy packet capture (netsniff-ng), traffic generation (trafgen), stateless traceroute (astraceroute), and pcap manipulation. Suitable for high-throughput environments where tcpdump performance is insufficient.

**[ngrep](tools/ngrep.md)** — Network grep
Applies regex pattern matching against live network traffic or pcap files, displaying packets that match specified patterns. Useful for quickly finding cleartext credentials, specific protocol strings, or suspicious content in network streams.

---

## MAC Address Spoofing

**[macchanger](tools/macchanger.md)** — MAC address spoofing
Changes the network interface MAC address to prevent hardware identification in ARP tables, DHCP logs, and switch CAM tables. Use before any network scanning or MITM operation.

---

## Tool Selection Guide

| Tool | Best For | Key Advantage |
|------|----------|---------------|
| `bettercap` | Active MITM, credential capture, SSL stripping | Modern framework with REST API |
| `ettercap` | Simple ARP spoofing on flat LANs | Lightweight; use `-T` text mode |
| `dsniff` | Cleartext credential sniffing, DNS/ARP spoofing, MAC flooding | Multiple focused sub-tools |
| `scapy` | Custom protocol fuzzing, PoC development | Full Python programmability |
| `hping3` | Firewall rule testing, TCP traceroute | Fine-grained single-packet control |
| `dnschef` | Selective DNS spoofing during MITM | Configurable per-domain proxy |
| `sslstrip` | HTTPS downgrade attacks | Transparent SSL stripping |
| `netsniff-ng` | High-throughput packet capture | Zero-copy kernel-level performance |
| `ngrep` | Pattern search in network traffic | Regex matching on packet payloads |

---

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| HSTS prevents SSL stripping | `bettercap` with HSTS bypass caplet; note: modern browsers resist this — consider alternative attack vectors |
| Target uses 802.1X port authentication | ARP spoofing will fail; piggyback on an authenticated port (hub between device and switch) or wait for auth timeout to hijack the session |
| Need to capture NTLM hashes passively | Use `responder` (see `../password/README.md`) — LLMNR/NBT-NS poisoning, not ARP spoofing |
| Switched network, ARP spoofing ineffective | `dsniff` (macof) to overflow CAM table first, then sniff; or use `dnschef` for DNS-only interception |
| Need to intercept traffic without being on the same VLAN | Combine with VLAN hopping (see `../voip-ics/README.md` for `yersinia`) before MITM |
| Multiple targets simultaneously | `bettercap` with target list; `ettercap` limited to single target pair |

---

## Related Categories

- For HTTP(S) interception and web traffic analysis, see `../web/tools/mitmproxy.md`.
- For LLMNR/NBT-NS hash capture, see `../password/tools/responder.md`.
- For IPv6 DHCPv6 poisoning, see `../exploitation/tools/mitm6.md`.
- For passive traffic capture and forensic analysis, see `../forensics/README.md` (tcpdump, tshark).

---

## Playbook

For network interception workflows, see `../playbooks/internal-network.md`.

---

## Official References

- [Kali Tools](https://www.kali.org/tools/all-tools/)
