# Reverse Engineering

CLI/headless binary analysis tools for pentest decisions: security-attribute checking, symbol/import analysis, targeted disassembly, and Android app decompilation.

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------| 
| Binary exploit mitigation check | `checksec` | — |
| Quick binary metadata | `rabin2 -I` | Use `readelf` for detailed ELF headers |
| Embedded strings/credentials | `strings` | — |
| Library dependencies / hijacking | `ldd` | Use `objdump` for untrusted binaries |
| ELF section/symbol analysis | `readelf` + `nm` | — |
| Targeted disassembly | `radare2 -q -c` (one-shot) | Interactive r2 sessions are out of scope |
| Scripted deep analysis | `Ghidra Headless` | Only for bounded, high-value analysis |
| Android APK decompilation | `apktool` (resources) + `jadx` (Java source) | — |
| Hex dump / magic byte check | `xxd` | — |

---

## Binary Security Triage

**[checksec](tools/checksec.md)** (pwntools) — Binary exploit mitigation checker
Checks PIE, NX, Stack Canary, RELRO, and FORTIFY for an ELF binary. The first triage step for evaluating SUID binary exploitability.

**[rabin2](tools/rabin2.md)** (radare2) — Fast binary metadata extraction
One-shot binary analysis: architecture, canary/PIC/NX/RELRO status, imports, exports, strings. Use in non-interactive mode only.

**[readelf](tools/readelf.md)** — ELF binary security inspection
Displays detailed ELF file information — stack permissions (GNU_STACK), RELRO status, RUNPATH, and symbol tables — to assess exploitability.

---

## Binary & Library Analysis

**[strings](tools/strings.md)** — Embedded credential and artifact extraction
Extracts printable strings from binary files to find hardcoded passwords, API keys, URLs, and file paths — without disassembly.

**[nm](tools/nm.md)** — Symbol table inspection
Lists imported and exported symbols. Identifies dangerous function calls (`system`, `exec`, `strcpy`) in binaries and shared libraries.

**[ldd](tools/ldd.md)** — Shared library dependency analysis
Prints shared library dependencies. Identifies library hijacking opportunities when libraries resolve to writable paths.

**[objdump](tools/objdump.md)** — Object file disassembly and analysis
Disassembles binary sections, examines ELF headers, checks dynamic symbols and relocations. For untrusted binaries, it can be used as a safe alternative to `ldd`.

**[xxd](tools/xxd.md)** — Hex dump and file format identification
Creates hex dumps of binary files. Used to check magic bytes, identify true file formats, and detect script-in-binary encapsulation (pyinstaller, shc).

---

## Targeted Disassembly

**[radare2](tools/radare2.md)** — Targeted one-shot disassembly
Use only non-interactive `r2 -q -c` commands for selected functions, imports, strings, and disassembly snippets.

**[Ghidra Headless](tools/ghidra-headless.md)** — Scripted headless binary analysis
Runs Ghidra imports, analysis, and post-scripts without GUI. Use only for bounded, high-value binary analysis tasks.

**[ropper](tools/ropper.md)** — ROP/JOP gadget finder
Searches ELF, PE, and Mach-O binaries for ROP, JOP, and SYS gadgets for exploit development. Generates ropchains for common targets and supports semantic gadget search. Essential for building return-oriented programming exploits against binaries with NX enabled.

---

## Firmware Analysis

**[binwalk](tools/binwalk.md)** — Firmware signature scanning and extraction
Scans firmware images for embedded file signatures, extracts components, and performs entropy analysis to identify encrypted or compressed regions. Essential for IoT and embedded device security assessments.

---

## Android Reverse Engineering

**[apktool](tools/apktool.md)** — APK unpacking and resource decoding
Decodes AndroidManifest.xml, resources, smali, certificates, and packaged files for static review.

**[jadx](tools/jadx.md)** — DEX to Java decompilation
Decompiles APK/DEX to Java-like source for automated grep and source review.

**[dex2jar](tools/dex2jar.md)** — DEX to JAR conversion
Converts Android DEX files to JAR format for decompilation and analysis with standard Java tools. Useful when jadx output is insufficient and alternative decompilers (JD-GUI, CFR, Procyon) are needed.

---

## Mobile / Runtime Analysis

**[frida](tools/frida.md)** — Dynamic instrumentation toolkit
Injects JavaScript into running processes for runtime analysis. Hooks functions, traces calls, and bypasses security checks on Android and iOS.

**[objection](tools/objection.md)** — Runtime mobile exploration
Powered by Frida, provides a REPL for exploring and testing mobile applications at runtime. Bypasses SSL pinning, dumps keychain data, and enumerates application storage without jailbreak or root.

---

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| SUID binary, need full exploitability assessment | `checksec` → `strings` for hardcoded paths → `nm` for dangerous imports (`system`, `exec`) → `ldd` for hijackable libs |
| Need ROP gadgets for exploit development | `ropper --file <binary> --search` for specific gadget patterns |
| Binary appears packed or obfuscated | `xxd` magic bytes → `rabin2 -I` for packer detection → unpack before further analysis |
| jadx decompilation incomplete or garbled | `dex2jar` → alternative decompilers (CFR, Procyon) for cleaner output |
| Mobile app has SSL pinning or root detection | `frida` or `objection` for runtime bypass without modifying the APK |
| Need to trace function calls at runtime | `frida-trace` for selective function hooking without full instrumentation setup |
| IoT firmware, filesystem extraction fails with binwalk | Check entropy (`binwalk -E`); if encrypted, look for keys in bootloader or companion flash dumps |

---

## Related Categories

- For privilege escalation using binary analysis findings, see `../post-exploitation/README.md`.
- For mobile app runtime testing (Frida, objection), see the Mobile / Runtime Analysis section above.
- For firmware extraction from forensic disk images, see `../forensics/README.md`.

---

## Playbook

For binary analysis during post-exploitation, see `../playbooks/post-exploitation.md`.
For Android app static analysis workflows, see `../playbooks/mobile-application.md`.

---

## Official References

- [Kali Tools](https://www.kali.org/tools/all-tools/)
