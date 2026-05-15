# Tools

Helper scripts for diagnosing tricky images, post-processing recovered files,
and comparing outputs across runs.

Full documentation: [docs/tools.md](../docs/tools.md)

| Script | Purpose |
|--------|---------|
| `find_superblock.py` | Find the correct `--block` value for apfs-excavate |
| `find_min_xid.py` | Find a sensible `--min-xid` value for apfs-excavate |
| `identify_orphans.py` | Identify and rename files in `recovered_orphans/` by type |
| `decompress_orphans.py` | Decompress APFS-compressed orphan blobs |
| `inspect_checkpoint.py` | Inspect scan and extraction checkpoint files |
| `dir_stats.py` | Snapshot per-file stats (SHA256, permissions, size, mtime) for a directory tree |
| `snapshot_recovery.sh` | Snapshot all `recovered_*` dirs and generate a SHA256 manifest for cross-run validation |

Python scripts are standalone — no pip installs required.
`snapshot_recovery.sh` requires bash and Python 3; uses `dot_clean` on macOS.
