# Wireless Security

A toolkit for security testing of Wi-Fi (802.11), Bluetooth, and other wireless networks. Testing wireless networks requires a wireless adapter that supports Monitor Mode (e.g., Alfa AWUS036ACH).

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| Adapter preparation | `airmon-ng start wlan0` | — |
| WiFi reconnaissance | `airodump-ng` | Use `kismet` for fully passive stealth |
| WPA handshake capture | `airodump-ng` + `aireplay-ng -0` (deauth) | Use `hcxtools` when PMKID is available (no client required) |
| WPA offline cracking | `aircrack-ng` or `hashcat -m 22000` | Use `john` or `cowpatty` when CPU-only |
| WPS PIN attack | `reaver` | Switch to `bully` when reaver stalls |
| Automated WiFi attack | `wifite` (fully automated batch) or `airgeddon` (structured step-by-step) | — |
| Evil Twin | `fluxion` (captive portal) or `airbase-ng` (manual control) | Use `wifiphisher` when social-engineering the password |
| PMKID/hash extraction | `hcxtools` (hcxdumptool → hcxpcapngtool) | — |
| Bluetooth reconnaissance | `hcitool` + `sdptool` + `btscanner` | Requires Bluetooth adapter |
| BLE characteristic testing | `gatttool` | — |
| BLE pairing analysis | `crackle` | Requires vulnerable legacy pairing capture |
| WPS Pixie Dust | `reaver -K` (calls pixiewps) | Only effective against vulnerable chipsets |
| 802.11 stress testing | `mdk4` | Highly disruptive; isolated environment required |
| WPA Enterprise evil twin | `eaphammer --creds` | Requires explicit authorization |

---

## aircrack-ng Suite — Standard Wi-Fi Security Testing Toolkit

The aircrack-ng suite is the core toolkit for Wi-Fi penetration testing, composed of several sub-tools, each with a specific role:

**[airmon-ng](tools/airmon-ng.md)** — Wireless adapter mode switching  
Switches the wireless adapter into Monitor Mode, a prerequisite for using other aircrack-ng tools. Can also detect and kill interfering processes.  

**[airodump-ng](tools/airodump-ng.md)** — Wireless network scanning and packet capture  
Scans nearby Wi-Fi networks, displaying BSSID, channel, encryption type, client list, and captures packets (for subsequent handshake cracking). The core tool for Wi-Fi reconnaissance.  

**[aireplay-ng](tools/aireplay-ng.md)** — Packet injection and replay  
Injects packets into target networks. Most commonly used to send Deauth frames to force clients to reconnect (triggering handshake capture), and also supports ARP injection (for WEP cracking).  

**[aircrack-ng](tools/aircrack-ng.md)** — WPA/WEP key cracking  
Performs offline password cracking on captured handshakes or WEP packets. Supports dictionary attacks (WPA/WPA2) and statistical attacks (WEP).  

**[airbase-ng](tools/airbase-ng.md)** — Create a fake AP (Evil Twin)  
Creates a spoofed wireless access point for man-in-the-middle attack testing. Can capture traffic from clients that connect to the fake AP.  

---

## Automated Attack Tools

**[wifite](tools/wifite.md)** — Automated Wi-Fi attacks  
An automated WPA/WPA2/WEP/WPS attack tool that wraps the full attack workflow of the aircrack-ng suite. Ideal for quick batch testing of all nearby networks with minimal effort.  

**[wifiphisher](tools/wifiphisher.md)** — Wi-Fi phishing attacks  
Creates an Evil Twin AP by forcibly disconnecting clients from a legitimate AP, then luring them to connect to the fake AP, where a phishing page captures the Wi-Fi password. No password dictionary required.  

**[wifipumpkin3](tools/wifipumpkin3.md)** — Rogue AP attack framework  
A comprehensive rogue access point framework for MITM attacks, captive portal credential harvesting, DNS spoofing, and traffic interception. Provides a modular plugin architecture and supports transparent proxy, SSL stripping, and credential capture.  

**[reaver](tools/reaver.md)** — WPS PIN brute-force  
Brute-forces the WPS (Wi-Fi Protected Setup) PIN code. Exploits a design flaw in the WPS protocol; typically cracks a WPS password in 4–10 hours. Some routers have WPS lockout protection.  

**[bully](tools/bully.md)** — Alternative WPS PIN brute-force  
An alternative WPS brute-force tool that handles edge cases and AP firmware quirks better than reaver in some environments. Use bully when reaver fails or stalls.  

**[pixiewps](tools/pixiewps.md)** — Offline WPS Pixie Dust attack  
Exploits weak random number generation in WPS implementations to recover the PIN offline. Typically invoked automatically via `reaver -K` or `bully -d`.  

---

## Wireless Surveillance

**[kismet](tools/kismet.md)** — Passive wireless network discovery  
Passively scans and logs all nearby wireless signals (Wi-Fi/Bluetooth/Zigbee, etc.) without transmitting any packets — completely covert. Provides a Web GUI; suitable for wireless network reconnaissance and compliance auditing.  

---

## Capture Processing

**[hcxtools](tools/hcxtools.md)** — Wireless capture file conversion  
Converts hcxdumptool/airodump-ng captures to hashcat-compatible format (mode 22000) for offline WPA cracking. Supports PMKID and EAPOL hash extraction and ESSID filtering. PMKID attacks do not require a connected client.  

**[cowpatty](tools/cowpatty.md)** — WPA/WPA2 PSK dictionary cracker  
Offline dictionary cracker for WPA/WPA2 PSK handshakes. Supports precomputed PMK hash tables for faster cracking of specific SSIDs. CPU-based; use when GPU is unavailable.  

**[asleap](tools/asleap.md)** — LEAP and MS-CHAPv2 credential cracking  
Cracks Cisco LEAP and MS-CHAPv2/PPTP credentials from captured challenge/response pairs. Use when wireless assessments encounter legacy LEAP authentication or when MS-CHAPv2 handshakes are captured from PPTP VPN or WPA Enterprise sessions.  

---

## Social Engineering Attacks

**[fluxion](tools/fluxion.md)** — Evil-twin captive portal attack  
Creates an evil-twin AP, deauthenticates clients from the legitimate AP, and serves a captive portal page to harvest the Wi-Fi password. Validates the captured password against the WPA handshake before reporting success.  

---

## Automated Auditing

**[airgeddon](tools/airgeddon.md)** — All-in-one wireless auditing  
A menu-driven script orchestrating monitor mode setup, handshake/PMKID capture, evil-twin attacks, captive portal credential harvesting, and WPS attacks. Ideal for structured wireless security assessments.  

---

## 802.11 Protocol Testing

**[mdk4](tools/mdk4.md)** — 802.11 stress testing framework  
Performs 802.11 protocol stress testing including beacon flooding, authentication DoS, Deauth attacks, EAPOL flooding, and MAC filter brute force. Useful for testing wireless IDS/IPS detection and AP resilience. Highly disruptive — use only in isolated, authorized test environments.  

---

## Bluetooth

Testing Bluetooth requires a Bluetooth adapter. All CLI tools are pre-installed with the `bluez` package.

**[hcitool](tools/hcitool.md)** — Bluetooth device discovery
Scans for nearby Bluetooth devices (inquiry scan), reads device information (LMP version, features), and manages connections. The starting point for Bluetooth reconnaissance.

**[sdptool](tools/sdptool.md)** — SDP service enumeration
Browses Service Discovery Protocol records to enumerate RFCOMM channels — file transfer, audio, serial port, and networking services on discovered devices.

**[gatttool](tools/gatttool.md)** — BLE GATT characteristic interaction
Reads from and writes to GATT characteristics on Bluetooth Low Energy devices. Tests whether sensitive operations (sensor data, lock commands) require authentication.

**[btscanner](tools/btscanner.md)** — Bluetooth reconnaissance report
Ncurses-based Bluetooth discovery tool that records nearby device metadata. Launch interactively and extract results from its config-defined log location.

**[blueranger](tools/blueranger.md)** — Bluetooth proximity estimation
Uses signal strength to estimate the proximity of a discovered Bluetooth device.

**[bluesnarfer](tools/bluesnarfer.md)** — Bluetooth OBEX access testing
Tests vulnerable OBEX services for unauthorized data access. High risk and device-specific authorization required.

**[crackle](tools/crackle.md)** — BLE legacy pairing key recovery
Attempts key recovery and traffic decryption from vulnerable BLE legacy pairing captures.

### Bluetooth Reconnaissance Workflow

```
1. hcitool scan: discover nearby devices (BD_ADDR + name)
2. hcitool info <BD_ADDR>: read device capabilities per discovered address
3. sdptool browse <BD_ADDR>: enumerate SDP services and RFCOMM channels
4. btscanner: interactive scan; extract results from log location
5. gatttool -b <BD_ADDR> --primary: list BLE services and characteristics
6. gatttool -b <BD_ADDR> --char-read -a <handle>: test unauthenticated reads
```

---

### WPA Enterprise (802.1X) Note

Enterprise wireless networks using 802.1X (EAP-TLS, PEAP, EAP-TTLS) require additional methodology beyond PSK attacks. Testing typically involves deploying a rogue RADIUS server (e.g., `hostapd-wpe` or `eaphammer`) to capture RADIUS credentials. This is a high-risk operation that requires explicit authorization and a controlled test environment.

**[eaphammer](tools/eaphammer.md)** — WPA2-Enterprise evil twin attacks  
Targeted evil twin attack tool for WPA2-Enterprise networks with EAP credential harvesting. Automates rogue AP creation, certificate generation, and credential capture for PEAP, EAP-TTLS, and other EAP methods.  

**[hostapd-mana](tools/hostapd-mana.md)** — Rogue AP with MANA/KARMA attacks  
A modified version of `hostapd` with MANA and KARMA attack capabilities for creating rogue access points. Responds to all probe requests, captures credentials from connecting clients, and supports targeted or opportunistic credential harvesting.  

## Hardware Requirements
- A wireless adapter that supports Monitor Mode and Packet Injection is required
- Recommended: Alfa AWUS036ACH (dual-band, good driver support)
- Verify support: use `airmon-ng` to list supported adapters

---

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| WPA2-PSK, no clients and PMKID capture fails | Wait for client association or use `mdk4` beacon flood to provoke reconnections (authorized only) |
| WPS attack fails (reaver + bully both stall) | AP has WPS lockout — fall back to handshake capture via deauth |
| Captured handshake, rockyou.txt exhausted | `cewl` target-specific wordlist → `hashcat -a 6` hybrid → mask if policy known |
| Multiple APs with same ESSID, need to isolate target | `airodump-ng --bssid <target-bssid> -c <channel>` to lock on specific AP |
| MS-CHAPv2 / LEAP credentials captured from Enterprise | `asleap` for offline cracking — faster than generic hashcat for this format |
| BLE device, need to test write operations | `gatttool --char-write-req -a <handle> -n <value>` — confirm authorization first |

---

## Related Categories

- For RFID/NFC, Proxmark3, PC/SC smart-card, and physical credential assessment, read `../rfid-nfc/README.md`.

---

## Playbook

For a full scenario workflow covering phases, decision points, and risk gates, see `../playbooks/wireless-assessment.md`.

---

## Official References

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [Kali Tools](https://www.kali.org/tools/all-tools/)
