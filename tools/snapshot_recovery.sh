#!/usr/bin/env bash
# snapshot_recovery.sh — Snapshot all recovered_* directories in an apfs-excavate output dir.
#
# For each recovered_* subdirectory found under <output_dir>:
#   1. Strips macOS metadata noise (.DS_Store, ._* AppleDouble files).
#   2. Captures per-file stats (SHA256, type, permissions, owner, size, mtime) via dir_stats.py.
#   3. Generates a sha256sum-compatible manifest (skipped with --no-checksum).
#
# Output files written to <output_dir>:
#   recovered_files_stats.txt          — full per-file stats for all recovered_* dirs
#   recovered_files_manifest.sha256    — sha256sum-compatible manifest (files only)
#
# To validate a future run against the manifest:
#   cd <output_dir> && sha256sum -c recovered_files_manifest.sha256   # Linux
#   cd <output_dir> && shasum -a 256 -c recovered_files_manifest.sha256  # macOS
#
# Usage:
#   snapshot_recovery.sh <output_dir> [--no-checksum] [--workers N]
#
# Options:
#   --no-checksum   Skip SHA256 computation (much faster; trades content-change detection)
#   --workers N     Parallel SHA256 workers passed to dir_stats.py (default: 2×CPU, max 16)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATS_PY="$SCRIPT_DIR/dir_stats.py"

usage() { echo "Usage: $0 <output_dir> [--no-checksum] [--workers N]" >&2; exit 1; }

[[ $# -lt 1 ]] && usage

OUTPUT_DIR="$1"; shift
NO_CHECKSUM=""
WORKERS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-checksum) NO_CHECKSUM="--no-checksum" ;;
        --workers)
            [[ $# -lt 2 ]] && { echo "Error: --workers requires a number" >&2; usage; }
            WORKERS="--workers $2"; shift ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
    shift
done

[[ -d "$OUTPUT_DIR" ]] || { echo "Error: not a directory: $OUTPUT_DIR" >&2; exit 1; }
[[ -f "$STATS_PY"   ]] || { echo "Error: dir_stats.py not found at $STATS_PY" >&2; exit 1; }

STATS_FILE="$OUTPUT_DIR/recovered_files_stats.txt"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Collect recovered_* subdirectories (sorted, direct children only)
DIRS=()
while IFS= read -r d; do
    [[ -n "$d" ]] && DIRS+=("$d")
done < <(find "$OUTPUT_DIR" -maxdepth 1 -type d -name 'recovered_*' | sort)

if [[ ${#DIRS[@]} -eq 0 ]]; then
    echo "No recovered_* directories found in $OUTPUT_DIR" >&2
    exit 1
fi

echo "Found ${#DIRS[@]} recovered_* director$([ ${#DIRS[@]} -eq 1 ] && echo y || echo ies)."
[[ -n "$NO_CHECKSUM" ]] && echo "  (SHA256 skipped — metadata only)"

# ── Step 1: clean macOS metadata noise from every recovered_* dir ─────────────

echo ""
echo "Cleaning macOS metadata files..."
for dir in "${DIRS[@]}"; do
    label=$(basename "$dir")
    echo "  $label"

    # Remove .DS_Store files (Finder window layout; meaningless outside macOS Finder)
    find "$dir" -type f -name ".DS_Store*" -delete 2>/dev/null || true

    # Remove ._* AppleDouble sidecar files (extended attributes stored as separate files,
    # written by macOS when copying to non-HFS+/APFS volumes like FAT or ExFAT drives).
    # dot_clean merges them back into xattrs where possible and deletes orphaned ones.
    if command -v dot_clean &>/dev/null; then
        dot_clean "$dir" 2>/dev/null || true
    else
        # Fallback if dot_clean is unavailable (Linux / non-standard macOS install)
        find "$dir" -type f -name "._*" -delete 2>/dev/null || true
    fi
done

# ── Step 2: snapshot stats for each recovered_* dir ───────────────────────────

echo ""
echo "Snapshotting stats → $STATS_FILE"

{
    echo "# apfs-excavate recovery snapshot"
    echo "# run_dir:   $OUTPUT_DIR"
    echo "# generated: $NOW"
    echo "# sections:  ${#DIRS[*]}"
    echo "#"

    for dir in "${DIRS[@]}"; do
        label=$(basename "$dir")
        echo ""
        echo "### $label ###"
        # shellcheck disable=SC2086
        python3 "$STATS_PY" "$dir" --label "$label" $NO_CHECKSUM $WORKERS
    done
} > "$STATS_FILE"

echo "Done: $STATS_FILE"

# ── Step 3: generate sha256sum-compatible manifest ────────────────────────────

if [[ -z "$NO_CHECKSUM" ]]; then
    MANIFEST_FILE="$OUTPUT_DIR/recovered_files_manifest.sha256"
    echo ""
    echo "Generating SHA256 manifest → $MANIFEST_FILE"

    # Parse the stats file: track the current section label from "### label ###" headers,
    # then emit "<sha256>  <label>/<path>" for every regular file (SHA256 != "-").
    # Paths are relative to OUTPUT_DIR so sha256sum -c runs correctly from there.
    awk -F'\t' '
        /^### /  { label = $0; sub(/^### /, "", label); sub(/ ###$/, "", label); next }
        /^#/     { next }
        /^$/     { next }
        $1 == "-" || substr($1, 1, 4) == "ERR:" { next }
        { print $1 "  " label "/" $8 }
    ' "$STATS_FILE" > "$MANIFEST_FILE"

    manifest_count=$(wc -l < "$MANIFEST_FILE" | tr -d ' ')
    echo "Done: $MANIFEST_FILE ($manifest_count files)"
fi
