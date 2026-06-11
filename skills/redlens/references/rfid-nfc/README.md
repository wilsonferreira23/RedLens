# Hardware Access Security

Tools for authorized RFID/NFC, Proxmark3, PC/SC smart-card, and physical credential assessment. Use this category only when the required hardware reader and explicit physical-access authorization are available.

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| RFID/NFC card identification | `proxmark3 -c "auto"` or `nfc-list` | Requires reader hardware and physical card authorization |
| MIFARE Classic assessment | `proxmark3` or `nfc-mfclassic` | Never clone or write without explicit approval |
| NFC tag polling | `nfc-poll` / `nfc-list` | Use Proxmark3 for deeper LF/HF testing |
| Smart-card inventory | `opensc-tool -l` | Requires PC/SC reader access |
| Certificate extraction | `pkcs15-tool` | Requires authorization to read token certificates |
| Custom APDU testing | `scriptor` | High caution; malformed APDUs may affect cards |

---

## RFID and NFC

**[proxmark3](tools/proxmark3.md)** — RFID/NFC research and card assessment platform
CLI tool for LF/HF card identification, MIFARE checks, dumps, simulation, and cloning workflows.

**[libnfc tools](tools/libnfc.md)** — NFC reader utilities
Includes `nfc-list`, `nfc-poll`, and `nfc-mfclassic` for NFC tag detection and MIFARE Classic reads.

---

## Smart Cards

**[opensc-tool](tools/opensc-tool.md)** — PC/SC smart-card inventory
Lists readers and cards, including ATR information.

**[pkcs15-tool](tools/pkcs15-tool.md)** — PKCS#15 smart-card data access
Reads certificates and token objects from supported smart cards.

**[scriptor](tools/scriptor.md)** — text-mode APDU script runner
Sends scripted APDU commands to smart cards through PC/SC.

---

## Related Categories

- For Wi-Fi, Bluetooth, and BLE radio assessment, read `../wireless/README.md`.

---

## Card Type Decision Tree

Match the identified card type to the appropriate attack methodology:

| Card Type | Action |
|-----------|--------|
| MIFARE Classic | darkside attack (no known keys) or nested attack (one known key) — `proxmark3 hf mf autopwn` / `nfc-mfclassic` |
| HID iCLASS | try standard/default keys first — dump if key found |
| MIFARE DESFire | read-only enumeration; full key recovery not practical |
| EM4100 (LF read) | `proxmark3 lf search` — read and record UID |
| T5577 (LF writable) | `proxmark3 lf search` — clone only with explicit approval |
| Unknown | `proxmark3 auto` — identify frequency and type first |

---

## Playbook

For a full scenario workflow covering phases, decision points, and risk gates, see `../playbooks/rfid-nfc.md`.

---

## Official References

- [Proxmark3 GitHub](https://github.com/RfidResearchGroup/proxmark3)
- [Proxmark3 command reference](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/commands.md)
- [libnfc](https://github.com/nfc-tools/libnfc)
- [OpenSC](https://github.com/OpenSC/OpenSC)
