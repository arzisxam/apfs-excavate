# apfs-excavate

Recover files from a damaged, corrupted, or encrypted APFS disk image — even when the drive's filesystem is completely unreadable.

**apfs-excavate** is a high-performance command-line tool written entirely in C. It runs on both macOS and Linux.

> [!WARNING]
> **Use at your own risk.** Always work on a *copy* of your failing drive (use a tool like `dd` or `ddrescue` to extract a disk image to a `.dmg`, `.img`, or `.raw` file first). While this tool only reads the disk image and does not modify it, it is provided "as is", without warranty of any kind. We cannot be held liable for any data loss.

---

## Quick start

```bash
./apfs-excavate damaged.img /Volumes/ExternalDrive/recovery/
```

That's it. The script builds the tool automatically on first run — no installation or compilation needed.

> **Tip:** Always recover to a *different* drive than the damaged one. Recovery can take several hours depending on the source and destination drive speeds, the size of the image, and the amount of data being extracted.

---

## Common uses

```bash
# Basic recovery
./apfs-excavate damaged.dmg out/

# Encrypted volume (FileVault / APFS encryption)
./apfs-excavate encrypted.dmg out/ --password "your passphrase"

# See what's recoverable before extracting anything
./apfs-excavate damaged.dmg out/ --scan-only

# Recover only specific file types
./apfs-excavate damaged.dmg out/ --filter-ext jpg,pdf,mov,docx

# Speed up scanning on an SSD (use 4 threads)
./apfs-excavate damaged.dmg out/ --workers 4

# Resume an interrupted recovery (automatic by default)
./apfs-excavate damaged.dmg out/
```

---

## What you get

After a successful run, the output folder contains:

| Folder / File | Contents |
|---|---|
| `recovered_files/` | Your files with their original folder structure |
| `recovered_orphans/` | Files found without a path — renamed by type (jpg, pdf, …) |
| `recovered_unknown_format/` | Files that could not be identified or decoded |
| `recovered_deleted/` | Raw deleted file fragments (`--deleted` only) |
| `file_list.md` | Full list of every file found, with sizes |
| `recovery_summary.md` | Run statistics (files found, recovered, timing) |
| `unrecovered_files.md` | Files the tool found but couldn't extract |
| `logs/` | Full execution log, error log, and size-filter skip list |

---

## Requirements

- **macOS:** install OpenSSL — `brew install openssl`
- **Linux:** `apt install libssl-dev zlib1g-dev`

No other dependencies. Python is not required to run the tool.

---

## Further reading

| Document | What's in it |
|---|---|
| [User Guide](docs/user-guide.md) | All options, advanced usage, full examples |
| [Tools](docs/tools.md) | Helper scripts for diagnosing tricky images |
| [Terminal Output Reference](docs/terminal-output-reference.md) | Sample output for every run scenario (resume, Ctrl-C, scan-only, etc.) |
| [Architecture](docs/architecture.md) | Module breakdown, phase pipeline, checkpoint format |
| [Execution Flow](docs/execution-flow.md) | Step-by-step walkthrough of every phase |
| [Encryption Pipeline](docs/encryption.md) | AES-XTS decryption, key derivation, per-extent crypto |
| [Roadmap](ROADMAP.md) | Planned features and future enhancements |

---

## Current Status & Limitations

- **Untested functionality:** Linux compilation and execution have not yet been tested.
- **APFS Only:** This tool is strictly for the APFS filesystem. If you run it on an ExFAT, FAT32, or NTFS image, it will abort immediately with a "No valid APFS container superblock found" error.
- **Troubleshooting:** If you receive a "Permission denied" error when trying to run `./apfs-excavate`, you may need to make the script executable first: `chmod +x apfs-excavate`.

---

## License

MIT — see [LICENSE](LICENSE).

> **Note:** This tool is intended for personal use and data recovery. Although the MIT License permits commercial use, using this tool professionally to charge others for recovery services is heavily discouraged without first thoroughly auditing and testing the tool yourself.
