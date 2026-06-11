# bulk_extractor

- **Category**: Forensics / Artifact Extraction
- **Risk Level**: 🟢 Low

---

## Description

A high-speed forensic scanner that processes disk images, files, or directories without mounting them and extracts structured artifacts: email addresses, credit card numbers, URLs, phone numbers, MAC addresses, domain names, GPS coordinates, and more. Does not interpret the file system — scans raw bytes, making it effective even on corrupted or fragmented storage. Outputs results to text files organized by artifact type.

## Installation

```bash
sudo apt install bulk-extractor
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `<input>` | Input: disk image file, directory, or raw device |
| `-o <dir>` | Output directory (required) |
| `-E <scanner>` | Disable all scanners except the one specified (equivalent to `-x all -e <scanner>`) |
| `-x <scanner>` | Disable a scanner (can be repeated) |
| `-e <scanner>` | Enable a scanner (can be repeated) |
| `-j <n>` | Number of threads (default: 4) |
| `-q` | No status or performance output |
| `-G <n>` | Page size in bytes (default: 16777216) |
| `-R` | Treat image file as a directory to recursively explore |

### Common Scanners

`email`, `url`, `domain`, `telephone`, `credit_card`, `gps`, `elf`, `winpe`, `zip`, `pdf`, `json`, `base64`, `ntfsindx`

## Common Commands

```bash
# Extract all artifacts from a disk image
bulk_extractor -o ./output disk_image.dd

# Process a directory of files
bulk_extractor -o ./output -R /mnt/evidence/

# Only extract email addresses and URLs
bulk_extractor -o ./output -x all -e email -e url disk_image.dd

# Multi-threaded processing (faster on large images)
bulk_extractor -o ./output -j 8 disk_image.dd

# View extracted emails
cat ./output/email.txt

# View extracted URLs
cat ./output/url.txt

# View extracted credit card numbers
cat ./output/ccn.txt
```

## Notes & Tips

1. bulk_extractor is non-destructive and does not modify the source — safe to run directly against original evidence.
2. Output files are plain text with one artifact per line — easy to grep, sort, and deduplicate.
3. The `email.txt` and `url.txt` outputs frequently reveal credentials, internal systems, and attacker infrastructure in forensic investigations.
4. No file system mounting needed — works on corrupted images, encrypted volumes, and raw partitions where autopsy fails.
5. Use `bulk_extractor -e zip` to extract and examine compressed archives embedded in the disk image.

---

## Official References

- [bulk-extractor (GitHub)](https://github.com/simsong/bulk_extractor)
- [Kali bulk-extractor](https://www.kali.org/tools/bulk-extractor/)
