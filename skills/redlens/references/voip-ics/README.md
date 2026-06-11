# Specialized Protocols

Tools for authorized assessment of niche or high-sensitivity protocols such as VoIP and ICS/OT. Use conservative defaults and confirm protocol-specific safety constraints before active testing.

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| SIP service discovery | `sipvicious svmap` | Use nmap first for broad UDP/TCP discovery |
| SIP extension enumeration | `sipvicious svwar` | Confirm lockout and PBX monitoring before high volume |
| IAX user enumeration | `enumiax` | Only when UDP/4569 or Asterisk IAX is in scope |
| Voice VLAN discovery | `voiphopper` | Requires local switch-port access |
| PLC discovery | `plcscan` | Prefer passive discovery in fragile OT environments |
| Modbus read-only validation | `modbus-cli read` | Never write unless explicitly authorized by OT owners |
| Layer 2 attacks (STP/CDP/DTP/DHCP) | `yersinia` | Highly disruptive; isolated environment required |

---

## VoIP

**[sipvicious](tools/sipvicious.md)** — SIP discovery, enumeration, and credential testing
Discovers SIP services, enumerates extensions, and tests SIP credentials when authorized.

**[enumiax](tools/enumiax.md)** — IAX2 username enumeration
Enumerates IAX users on Asterisk systems.

**[voiphopper](tools/voiphopper.md)** — Voice VLAN discovery and hopping assessment
Tests CDP/LLDP-MED voice VLAN exposure from a local network port.

**[sippts](tools/sippts.md)** — Comprehensive SIP penetration testing suite
A full-featured SIP security testing toolkit covering service scanning, extension enumeration, authentication cracking, call simulation, and RTP stream testing. Provides deeper SIP-specific testing capabilities beyond sipvicious.

---

## ICS and OT

**[plcscan](tools/plcscan.md)** — PLC and ICS service discovery
Identifies PLC and industrial protocol exposure in authorized OT ranges.

**[modbus-cli](tools/modbus-cli.md)** — Modbus TCP client
Reads Modbus coils and registers for controlled validation.

---

## Layer 2 Protocols

**[yersinia](tools/yersinia.md)** — Layer 2 protocol attack framework
Attacks and tests Layer 2 protocols including STP (root bridge takeover), CDP (flooding/spoofing), DTP (VLAN trunk negotiation), DHCP (starvation/rogue server), HSRP (active router hijacking), 802.1Q (VLAN hopping), and 802.1X (EAP injection). Highly disruptive — use only in isolated, authorized test environments.

---

## IPMI / BMC

**[ipmitool](tools/ipmitool.md)** — IPMI/BMC management and security testing
Manages and tests Baseboard Management Controllers via the IPMI protocol. Enumerates BMC users, tests default credentials, retrieves RAKP hashes (IPMI v2.0 cipher zero vulnerability), and accesses Serial-over-LAN for remote console. Essential for any network containing server hardware with out-of-band management interfaces.

Common checks:

- `ipmitool -I lanplus -H <target> -U ADMIN -P ADMIN chassis status` — test default credentials
- `ipmitool -I lanplus -H <target> -U ADMIN -P ADMIN user list` — enumerate BMC users
- IPMI v2.0 RAKP hash retrieval is a known vulnerability (cipher zero / anonymous auth)

---

## SNMP Deep Dive

For SNMP community string testing and enumeration, use the tools documented in the vulnerability analysis category:

- [onesixtyone](../vulnerability/tools/onesixtyone.md) — fast SNMP community string brute-force
- [snmpwalk](../vulnerability/tools/snmpwalk.md) — full SNMP MIB tree walk with known community strings

SNMP often exposes system details, network configuration, running processes, and installed software that feed directly into further enumeration.

---

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| sipvicious svwar returns no extensions | Try `sippts enumerate` with different methods (REGISTER, OPTIONS); check if PBX requires authentication for enumeration |
| Need comprehensive SIP testing (call simulation, RTP) | `sippts` for deeper SIP-specific testing beyond sipvicious |
| IPMI/BMC on UDP/623 | `ipmitool` — test default creds, enumerate users, check cipher zero vulnerability for RAKP hash retrieval |
| SNMP on UDP/161, community string discovered | `snmpwalk` full MIB walk → look for VoIP/ICS-specific OIDs (interface configs, routing tables) |
| Fragile OT environment, safety critical | Passive discovery only (`nmap -sS` with low rate); avoid active PLC interaction; read-only Modbus only after OT owner approval |
| PLC responds to plcscan but Modbus reads fail | Check if PLC uses non-standard port or requires authentication; try `modbus-cli` with explicit unit ID |

---

## Related Categories

- Start broad port and service discovery with `../information-gathering/tools/nmap.md` and `../vulnerability/README.md` before using protocol-specific tools.

---

## Playbook

For a full scenario workflow covering phases, decision points, and risk gates, see `../playbooks/voip-ics.md`.

---

## Official References

- [SIPVicious GitHub](https://github.com/EnableSecurity/sipvicious)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
