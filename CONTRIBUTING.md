# Contributing to apfs-excavate

## Building

```bash
make          # release build
make debug    # debug build with AddressSanitizer and UBSan
make check    # run unit tests
make clean    # remove build/
```

The debug build is the right default for development — it catches memory errors and undefined behaviour immediately at runtime.

## Code style

- **C11**, `-Wall -Wextra -Wpedantic`, zero warnings required
- Public function names are module-prefixed snake_case: `crypto_derive_vek`, `bio_read_block`, `apfs_parse_btree_node`
- Internal (static) functions use short names
- All globals are defined in `src/globals.c` and declared `extern` in `include/apfs_globals.h` with a `g_` prefix
- `#pragma once` in all headers
- Include order per `.c`: own header → stdlib → POSIX → third-party → platform-conditional → project headers
- Block comments `/* */` for function docs; `//` for inline notes
- Comments explain *why*, not *what*

## Module layout

| File | Responsibility |
|------|---------------|
| `apfs_types.h` | All structs and `#define` constants — no `.c` counterpart |
| `globals.c` | Definitions of all `g_*` globals |
| `log.c` | Two-mode logger: normal (always stdout) and debug (file only) |
| `errors.c` | Thread-safe error/warning collection into `g_errors[]` |
| `util.c` | Timing, number formatting, progress bars, inode hash table, path helpers |
| `crypto.c` | AES-XTS, PBKDF2, RFC 3394 key unwrap, keybag parsing, VEK derivation |
| `block_io.c` | Raw block reads and decrypted block reads |
| `compress.c` | ZLIB, LZVN, LZFSE decompression; decmpfs dispatch |
| `checkpoint.c` | Binary checkpoint save/load for scan and extraction phases |
| `apfs_parse.c` | B-tree node parsing: drec, inode, extent, xattr, crypto state |
| `scan.c` | Multi-threaded block scanner; deleted inode heuristic |
| `recovery.c` | Path resolution, file extraction, orphan handling |
| `report.c` | Markdown report generation |
| `main.c` | CLI parsing, partition detection, volume feature detection, main pipeline |

## Error handling

- Functions that can fail return `bool` (true = success) or pointer (NULL = failure)
- `exit()` is only called from `main()`
- Errors are collected via `ERR_ADD_ERROR()` / `ERR_ADD_WARNING()` macros and written to `error.log` at the end of every run
- Do not add error handling for scenarios that cannot happen within the tool's own logic

## Platform notes

- LZFSE decompression uses the macOS `libcompression` framework, guarded by `#ifdef __APPLE__`
- On Linux, LZFSE-compressed files log a warning and are skipped; all other functionality is identical
- OpenSSL is required on both platforms — the Makefile uses `pkg-config` first, then falls back to `brew --prefix openssl` on macOS

## Submitting changes

1. Fork the repository and create a feature branch
2. `make debug && make check` must pass with zero warnings
3. Test against a real APFS image if the change touches parsing, extraction, or crypto
4. Open a pull request with a clear description of what changed and why
