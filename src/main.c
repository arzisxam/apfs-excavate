/*
 * main.c — CLI entry point for apfs-excavate.
 *
 * Handles:
 *   • Argument parsing
 *   • Image open + mmap
 *   • APFS partition / superblock detection
 *   • Encryption key derivation
 *   • Scan → build paths → extract → report pipeline
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <sys/statvfs.h>
#include <dirent.h>
#ifdef __APPLE__
#include <sys/mount.h>   /* statfs on macOS */
#include <spawn.h>
#include <sys/wait.h>
#endif

#include <openssl/crypto.h>

#include "apfs_types.h"
#include "apfs_globals.h"
#include "compat.h"
#include "apfs_parse.h"
#include "log.h"
#include "errors.h"
#include "util.h"
#include "crypto.h"
#include "block_io.h"
#include "checkpoint.h"
#include "scan.h"
#include "recovery.h"
#include "report.h"
#include "orphan_post.h"
#include "term.h"

#include "version.h"

/* ============================================================================
 * Usage
 * ============================================================================
 */

static void print_usage(const char *prog) {
    printf("apfs-excavate %s — deep recovery from damaged APFS images\n\n",
           TOOL_VERSION);
    printf("Usage: %s <image> [output_dir] [options]\n\n", prog);
    printf("Options:\n");
    printf("  --password PWD      Password for encrypted volumes\n");
    printf("  --workers N         Scan threads (1–64, default 1; SSD only —\n");
    printf("                      multiple workers hurt performance on HDD)\n");
    printf("  --no-resume         Ignore existing checkpoints, start fresh\n");
    printf("  --deleted           Also scan for deleted/orphaned file fragments\n");
    printf("                      (slower; off by default)\n");
    printf("  --scan-only         Scan + build paths + save checkpoint, then exit without\n");
    printf("                      extracting. Use to pre-scan on borrowed hardware.\n");
    printf("  --re-extract        Clear extraction checkpoint + archive output folders,\n");
    printf("                      re-run extraction from existing scan checkpoint.\n");
    printf("                      Requires a completed scan. Conflicts with --no-resume\n");
    printf("                      and --scan-only.\n");
    printf("  --debug             Write diagnostics to logs/debug_<timestamp>.log\n");
    printf("\n");
    printf("File filters:\n");
    printf("  --max-size N        Skip files larger than N (e.g. 500MB, 1.5GB, 2TB).\n");
    printf("                      Default: 50 GB cap. Raise if you have large valid files.\n");
    printf("  --min-size N        Skip files smaller than N (e.g. 1KB, 10MB)\n");
    printf("  --filter-ext EXTS   Only recover files with these extensions\n");
    printf("                      Comma-separated, no spaces: jpg,pdf,mov\n");
    printf("  --pilot FILTER      Only extract paths containing FILTER string\n");
    printf("\n");
    printf("Advanced options:\n");
    printf("  -b, --block LBA     Force container superblock at LBA\n");
    printf("  --min-xid XID       Ignore B-tree nodes older than transaction ID XID\n");
    printf("                      (higher XID = more recent snapshot state)\n");
    printf("  --case-sensitive    Override: treat volume as case-sensitive\n");
    printf("                      (auto-detected from APSB; use if superblock is damaged)\n");
    printf("  --skip-metadata     Skip all metadata restoration (timestamps, permissions,\n");
    printf("                      ownership, BSD flags). Use when metadata causes Finder\n");
    printf("                      display issues or on partially POSIX-compatible volumes.\n");
    printf("  --no-compression    Extract compressed files as raw data instead of\n");
    printf("                      decompressing (debugging only — output will be unreadable)\n");
    printf("  -h, --help          Show this help\n\n");
    printf("Reports written to output_dir after every run:\n");
    printf("  file_list.md          all recoverable files with sizes and resolved paths\n");
    printf("  recovery_summary.md   scan + extraction statistics\n");
    printf("  unrecovered_files.md  files not successfully extracted\n");
    printf("  logs/execution.log    full timestamped run log\n");
    printf("  logs/error.log        timestamped errors and warnings\n\n");
    printf("Examples:\n");
    printf("  %s damaged.dmg out/                            # basic recovery\n", prog);
    printf("  %s damaged.dmg out/ --scan-only               # pre-scan, no extraction\n", prog);
    printf("  %s damaged.dmg out/ --re-extract              # re-extract without re-scanning\n", prog);
    printf("  %s encrypted.dmg out/ --password secret --workers 4\n", prog);
    printf("  %s damaged.dmg out/ --filter-ext jpg,pdf,mov --min-size 1KB\n", prog);
    printf("  %s damaged.dmg out/ --debug\n", prog);
}

/* ============================================================================
 * Volume feature detection
 * ============================================================================
 */

/*
 * detect_volume_features() — scan the mapped image for an APSB (volume
 * superblock) and read Feature Bit 0x8 from apfs_incompatible_features.
 *
 * APFS volume superblock layout (all offsets from block start):
 *   0–31  obj_phys_t header
 *   32–35 magic "APSB"
 *   36–39 apfs_fs_index
 *   40–47 apfs_features               (uint64_t)
 *   48–55 apfs_readonly_compat_feat   (uint64_t)
 *   56–63 apfs_incompatible_features  (uint64_t)
 *           Bit 0x1 = APFS_INCOMPAT_CASE_INSENSITIVE
 *           Bit 0x8 = APFS_INCOMPAT_NORMALIZATION_INSENSITIVE (case-sensitive)
 *
 * Sets g_case_sensitive = true when Feature Bit 0x8 is present AND
 * the case-insensitive flag (0x1) is absent.
 * CLI --case-sensitive forces g_case_sensitive = true regardless.
 */
static void detect_volume_features(bool cli_case_sensitive) {
    if (g_data_size < 64) return;

    const uint8_t *p = g_data;
    const uint8_t *end = g_data + g_data_size - 64;

    while (p < end) {
        /* Look for "APSB" at offset+32 within aligned blocks. */
        const uint8_t *hit = memmem(p, (size_t)(end - p), "APSB", 4);
        if (!hit) break;

        /* The magic sits at offset 32 within the block. */
        const uint8_t *apsb = hit - 32;
        if (apsb >= g_data && apsb + 64 <= g_data + g_data_size) {
            uint64_t incompat = get_u64(apsb + 56);
            bool case_insensitive_bit = (incompat & 0x1) != 0;
            bool normalization_bit    = (incompat & 0x8) != 0;

            /* Volume is case-sensitive when bit 0x8 is set OR
             * the case-insensitive flag is absent. */
            bool detected = normalization_bit || !case_insensitive_bit;
            g_case_sensitive = detected || cli_case_sensitive;
            LOG_DEBUG("APSB incompat_features=0x%llx → case_sensitive=%s",
                      (unsigned long long)incompat,
                      g_case_sensitive ? "yes" : "no");
            return;
        }
        p = hit + 1;
    }

    /* APSB not found — fall back to CLI flag. */
    g_case_sensitive = cli_case_sensitive;
}

/* ============================================================================
 * Partition / superblock detection
 * ============================================================================
 */

/*
 * find_partition() — locate the APFS container superblock (NXSB) within the
 * mapped image and set g_partition_offset and g_block_size.
 *
 * Detection order:
 *   1. Manual --block override
 *   2. GPT partition table
 *   3. NXSB magic search (primary, then checkpoint inference)
 *   4. B-tree node scan (works when superblock is completely zeroed)
 *   5. Hard fallback: offset 0, block size 4096
 *
 * Returns a pointer to the active superblock (may be a checkpoint copy), or
 * NULL if none was found.
 */
static const uint8_t *find_partition(void) {
    const uint8_t *active_sb = NULL;
    bool found = false;

    /* ---- 1. Manual override -------------------------------------------- */
    if (g_override_sb_lba > 0) {
        uint64_t off = g_override_sb_lba * 512;
        if (off + 40 < g_data_size &&
            memcmp(g_data + off + 32, "NXSB", 4) == 0) {
            uint32_t bs = get_u32(g_data + off + 36);
            if (bs >= 4096 && bs <= 65536 && (bs & (bs - 1)) == 0) {
                g_block_size       = bs;
                g_partition_offset = off;   /* superblock IS block 0 of the container */
                active_sb          = g_data + off;
                found = true;
                LOG_NORMAL("MANUAL OVERRIDE: Container Superblock at LBA %llu",
                           (unsigned long long)g_override_sb_lba);
            }
        }
    }

    /* ---- 2. GPT ---------------------------------------------------------- */
    if (!found && g_data_size > 1024 &&
        memcmp(g_data + 512, "EFI PART", 8) == 0) {
        uint64_t entry_lba  = get_u64(g_data + 512 + 72);
        uint32_t entry_size = get_u32(g_data + 512 + 84);
        if (entry_size == 0) entry_size = 128;
        uint64_t entry_off = entry_lba * 512;

        for (int i = 0; i < 128 && !found; i++) {
            if (entry_off + (uint64_t)i * entry_size + entry_size > g_data_size)
                break;
            const uint8_t *ent = g_data + entry_off + (uint64_t)i * entry_size;
            /* APFS GUID: EF577347-... */
            if (ent[0] != 0xef || ent[1] != 0x57 ||
                ent[2] != 0x34 || ent[3] != 0x7c) continue;

            uint64_t first_lba  = get_u64(ent + 32);
            g_partition_offset  = first_lba * 512;

            if (g_partition_offset + 40 < g_data_size) {
                uint32_t bs = get_u32(g_data + g_partition_offset + 36);
                if (bs >= 4096 && bs <= 65536 && (bs & (bs - 1)) == 0)
                    g_block_size = bs;
            }

            if (memcmp(g_data + g_partition_offset + 32, "NXSB", 4) == 0) {
                active_sb = g_data + g_partition_offset;
            } else {
                /* Primary damaged — search first 20 blocks for a checkpoint. */
                for (uint64_t blk = 1; blk < 20 && !active_sb; blk++) {
                    uint64_t cp = g_partition_offset + blk * g_block_size;
                    if (cp + 36 < g_data_size &&
                        memcmp(g_data + cp + 32, "NXSB", 4) == 0) {
                        active_sb = g_data + cp;
                        LOG_EXEC_ONLY("Primary superblock damaged — using checkpoint at block %llu",
                                      (unsigned long long)blk);
                    }
                }
            }
            found = true;
        }
    }

    /* ---- 3. NXSB magic search ------------------------------------------ */
    if (!found) {
        const uint8_t *positions[16];
        int count = 0;

        const uint8_t *p = g_data;
        while (count < 16) {
            const uint8_t *hit = memmem(p, g_data_size - (size_t)(p - g_data),
                                        "NXSB", 4);
            if (!hit) break;
            positions[count++] = hit;
            p = hit + 1;
        }

        if (count > 0) {
            /* Detect block size from the first valid NXSB. */
            uint32_t det_bs = 4096;
            for (int c = 0; c < count; c++) {
                const uint8_t *nb = positions[c] - 32;
                if (nb < g_data || nb + 80 > g_data + g_data_size) continue;
                uint32_t bs = get_u32(nb + 36);
                if (bs >= 4096 && bs <= 65536 && (bs & (bs - 1)) == 0) {
                    det_bs = bs; break;
                }
            }

            /* Guard all strategies that subtract 32 from a hit pointer.
             * The subtraction is UB if the hit is within 32 bytes of the
             * mmap base; in practice superblocks never sit at byte 0, but
             * the compiler is entitled to assume no-wrap.  Hoist the check
             * before the first subtract and share it across all strategies. */
            bool hit0_safe = (positions[0] >= g_data + 32);

            /* Strategy A: first hit looks like block 0 (partition start). */
            if (hit0_safe) {
            const uint8_t *first_nb = positions[0] - 32;
            if (first_nb + 40 < g_data + g_data_size &&
                memcmp(first_nb + 32, "NXSB", 4) == 0) {
                uint32_t bs = get_u32(first_nb + 36);
                if (bs >= 4096 && bs <= 65536 && (bs & (bs - 1)) == 0) {
                    g_partition_offset = (uint64_t)(first_nb - g_data);
                    g_block_size       = bs;
                    active_sb          = first_nb;
                    found = true;
                }
            }
            } /* end hit0_safe guard */

            /* Strategy B: spacing analysis when primary not at first hit. */
            if (!found && count >= 2 && hit0_safe) {
                const uint8_t *nb1 = positions[0] - 32;
                uint64_t off1 = (uint64_t)(nb1 - g_data);

                for (int blk = 1; blk <= 10 && !found; blk++) {
                    if ((uint64_t)blk * det_bs > off1) continue;
                    uint64_t cand = off1 - (uint64_t)blk * det_bs;
                    if (cand % 512 != 0) continue;

                    const uint8_t *primary = g_data + cand;
                    bool has_nxsb = (memcmp(primary + 32, "NXSB", 4) == 0);
                    bool is_zero  = true;
                    for (int z = 0; z < 64 && is_zero; z++)
                        if (primary[z] != 0) is_zero = false;
                    uint32_t pbs = get_u32(primary + 36);
                    bool magic_corrupt = !has_nxsb && !is_zero &&
                                        (pbs == det_bs);

                    if (has_nxsb || is_zero || magic_corrupt) {
                        g_partition_offset = cand;
                        g_block_size       = det_bs;
                        active_sb          = has_nxsb ? primary : nb1;
                        found = true;
                        if (!has_nxsb)
                            LOG_EXEC_ONLY("Primary superblock %s — using checkpoint",
                                          is_zero ? "zeroed" : "corrupted");
                    }
                }
            }

            /* Strategy C: try each hit as a partition start. */
            for (int c = 0; c < count && !found; c++) {
                const uint8_t *nb = positions[c] - 32;
                if (nb < g_data || nb + 80 > g_data + g_data_size) continue;
                uint32_t bs = get_u32(nb + 36);
                if (bs < 4096 || bs > 65536 || (bs & (bs - 1)) != 0) continue;
                uint64_t off = (uint64_t)(nb - g_data);
                if (off % 512 != 0) continue;
                g_partition_offset = off;
                g_block_size       = bs;
                active_sb          = nb;
                found = true;
            }

            /* Strategy D: checkpoint-based inference (common spacing). */
            if (!found && count > 0 && hit0_safe) {
                const uint8_t *nb0 = positions[0] - 32;
                {
                    uint64_t cp_off = (uint64_t)(nb0 - g_data);
                    static const uint64_t before[] = {435, 871, 1307, 1743, 0};
                    for (int i = 0; before[i] && !found; i++) {
                        uint64_t tp = cp_off - before[i] * 4096;
                        if (tp > cp_off || tp + 40 >= g_data_size) continue;
                        uint32_t bs = get_u32(g_data + tp + 36);
                        if (bs >= 4096 && bs <= 65536 && (bs & (bs - 1)) == 0) {
                            g_partition_offset = tp;
                            g_block_size       = bs;
                            found = true;
                        }
                    }
                    /* Last-resort: assume checkpoint at block 435. */
                    if (!found) {
                        uint64_t tp = cp_off - 435 * det_bs;
                        if (tp < cp_off) {
                            g_partition_offset = tp;
                            g_block_size       = det_bs;
                            found = true;
                        }
                    }
                }
            }
        }
    }

    /* ---- 4. B-tree scan -------------------------------------------------- */
    if (!found) {
        LOG_EXEC_ONLY("Superblock not found — scanning for B-tree nodes...");
        static const uint32_t sizes[] = {4096, 8192, 16384, 32768, 65536};
        for (size_t s = 0; s < sizeof(sizes)/sizeof(sizes[0]) && !found; s++) {
            uint32_t  bs        = sizes[s];
            uint64_t  max_blk   = (g_data_size / bs) < 1000
                                ? (g_data_size / bs) : 1000;
            for (uint64_t blk = 0; blk < max_blk && !found; blk++) {
                uint64_t off = blk * bs;
                if (off + bs > g_data_size) break;
                const uint8_t *blkp = g_data + off;
                if (apfs_is_valid_btree_node_sz(blkp, bs) ||
                    apfs_is_partial_btree_node_sz(blkp, bs)) {
                    uint64_t common[] = {0, 20480, 40960};
                    g_partition_offset = 0;
                    for (size_t k = 0; k < 3; k++) {
                        if (common[k] < off) { g_partition_offset = common[k]; break; }
                    }
                    g_block_size = bs;
                    found = true;
                    LOG_EXEC_ONLY("Partition found via B-tree scan: offset=%llu block_size=%u",
                                  (unsigned long long)g_partition_offset, g_block_size);
                }
            }
        }
    }

    /* ---- 5. Hard fallback ------------------------------------------------ */
    if (!found) {
        g_partition_offset = 0;
        g_block_size       = 4096;
    }

    return active_sb;
}

/* ============================================================================
 * Drive type detection
 * ============================================================================
 */

/*
 * image_is_on_hdd() — returns true if the filesystem containing path is
 * backed by a rotational hard drive.
 *
 * macOS: uses `diskutil info` on the underlying device and looks for the
 *        "Solid State: Yes" line.  Returns false (assume SSD) on any error.
 * Linux: reads /sys/block/<dev>/queue/rotational (1 = HDD, 0 = SSD).
 */
static bool image_is_on_hdd(const char *path) {
#ifdef __APPLE__
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) return false;

    /* f_mntfromname is e.g. "/dev/disk3s2" — strip the partition suffix. */
    char dev[64];
    snprintf(dev, sizeof(dev), "%s", sfs.f_mntfromname);
    /* Truncate trailing slice (s[0-9]+) to get the whole-disk device. */
    char *s = dev + strlen(dev) - 1;
    while (s > dev && *s >= '0' && *s <= '9') s--;
    if (*s == 's' && s > dev) *s = '\0';

    /* #55: validate dev contains only safe characters before shell expansion. */
    for (const char *p = dev; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '/' || *p == '_' || *p == '-'))
            return false;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) return false;

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addclose(&fa, pipefd[0]);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, pipefd[1]);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        posix_spawn_file_actions_adddup2(&fa, devnull, STDERR_FILENO);
        posix_spawn_file_actions_addclose(&fa, devnull);
    }

    extern char **environ;
    const char *argv_spawn[] = { "diskutil", "info", dev, NULL };
    pid_t pid;
    int rc = posix_spawnp(&pid, "diskutil", &fa, NULL,
                          (char *const *)argv_spawn, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (devnull >= 0) close(devnull);
    close(pipefd[1]);

    if (rc != 0) { close(pipefd[0]); return false; }

    bool is_hdd = true;   /* assume HDD until "Solid State: Yes" found */
    char line[256];
    FILE *fp = fdopen(pipefd[0], "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "Solid State") && strstr(line, "Yes")) {
                is_hdd = false;
                break;
            }
        }
        fclose(fp);
    } else {
        close(pipefd[0]);
    }

    int status;
    waitpid(pid, &status, 0);
    return is_hdd;

#elif defined(__linux__)
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) return false;

    /* Get the device via stat(). */
    struct stat st;
    if (stat(path, &st) != 0) return false;
    unsigned int major_num = (unsigned int)((st.st_dev >> 8) & 0xff);
    unsigned int minor_num = (unsigned int)(st.st_dev & 0xff);

    /* Find the block device name in /sys/dev/block/<major>:<minor>/. */
    char sysfs[128], target[256];
    snprintf(sysfs, sizeof(sysfs), "/sys/dev/block/%u:%u", major_num, minor_num);
    ssize_t len = readlink(sysfs, target, sizeof(target) - 1);
    if (len <= 0) return false;
    target[len] = '\0';

    /* The link is something like ../../block/sda/sda1 — extract the disk name. */
    char *slash = strrchr(target, '/');
    char *disk  = slash ? slash + 1 : target;
    /* Strip trailing digits to get the base device (sda1 → sda). */
    char base[64];
    snprintf(base, sizeof(base), "%s", disk);
    char *p = base + strlen(base) - 1;
    while (p > base && *p >= '0' && *p <= '9') p--;
    p[1] = '\0';

    char rot_path[128];
    snprintf(rot_path, sizeof(rot_path), "/sys/block/%s/queue/rotational", base);
    FILE *f = fopen(rot_path, "r");
    if (!f) return false;
    int rotational = 0;
    if (fscanf(f, "%d", &rotational) != 1) rotational = 0;
    fclose(f);
    return (rotational == 1);

#else
    (void)path;
    return false;   /* unknown platform — assume SSD, don't warn */
#endif
}

/* ============================================================================
 * Signal handler
 * ============================================================================
 */

static void handle_signal(int sig) {
    (void)sig;
    g_interrupted = 1;
}

/* ============================================================================
 * Run archival
 * ============================================================================
 */

/*
 * parse_size_arg() — parse a human-readable size string such as "500", "500B",
 * "500KB", "500MB", "1.5GB", "2TB" (case-insensitive suffix) into bytes.
 * Returns 0 on parse failure.
 */
static uint64_t parse_size_arg(const char *s) {
    char *end;
    double val = strtod(s, &end);
    if (end == s) return 0;
    while (*end == ' ') end++;
    char u = (char)toupper((unsigned char)*end);
    if (u == '\0' || u == 'B') return (uint64_t)val;
    if (u == 'K') return (uint64_t)(val * 1024.0);
    if (u == 'M') return (uint64_t)(val * 1024.0 * 1024.0);
    if (u == 'G') return (uint64_t)(val * 1024.0 * 1024.0 * 1024.0);
    if (u == 'T') return (uint64_t)(val * 1024.0 * 1024.0 * 1024.0 * 1024.0);
    return (uint64_t)val;
}

/*
 * backup_logs_and_summaries() — called at the start of every run, before
 * log_init() opens the log files for writing.  Renames existing log files and
 * summary reports to timestamped copies so prior-run data is never silently
 * overwritten.  Summary .md files are moved into logs/ to keep the output
 * root clean.
 */
static void backup_logs_and_summaries(const char *output_dir,
                                      const char *logs_dir) {
    char exec_path[MAX_PATH_LEN];
    snprintf(exec_path, sizeof(exec_path), "%s/execution.log", logs_dir);

    struct stat st;
    if (stat(exec_path, &st) != 0) return;   /* no prior log — first run */

    /* Use the existing log's modification time as the backup timestamp so it
     * reflects when that run happened, not when this new run starts. */
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&st.st_mtime, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm_info);

    char dst[MAX_PATH_LEN];

    /* Rotate log files */
    snprintf(dst, sizeof(dst), "%s/execution_%s.log", logs_dir, ts);
    rename(exec_path, dst);

    char err_path[MAX_PATH_LEN];
    snprintf(err_path, sizeof(err_path), "%s/error.log", logs_dir);
    if (stat(err_path, &st) == 0) {
        snprintf(dst, sizeof(dst), "%s/error_%s.log", logs_dir, ts);
        rename(err_path, dst);
    }

    /* Move summary .md files into logs/ */
    char md_path[MAX_PATH_LEN];
    snprintf(md_path, sizeof(md_path), "%s/recovery_summary.md", output_dir);
    if (stat(md_path, &st) == 0) {
        snprintf(dst, sizeof(dst), "%s/recovery_summary_%s.md", logs_dir, ts);
        rename(md_path, dst);
    }

    snprintf(md_path, sizeof(md_path), "%s/unrecovered_files.md", output_dir);
    if (stat(md_path, &st) == 0) {
        snprintf(dst, sizeof(dst), "%s/unrecovered_files_%s.md", logs_dir, ts);
        rename(md_path, dst);
    }
}

/*
 * archive_previous_run() — called when --no-resume is requested or when the
 * output directory already contains data from a previous run that we do not
 * want to mix with the current run.
 *
 * All files and directories under output_dir are moved into a new subdirectory
 * named previous_run.<timestamp>/ using rename(2), which is instant on the
 * same filesystem regardless of content size.  Existing previous_run.*
 * subdirectories are left in place (they are already archives).
 */
static void archive_previous_run(const char *output_dir) {
    /* Generate timestamp for the archive directory name */
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm_info);

    char archive_dir[MAX_PATH_LEN];
    snprintf(archive_dir, sizeof(archive_dir),
             "%s/previous_run.%s", output_dir, ts);

    /* Scan directory for items to move */
    DIR *d = opendir(output_dir);
    if (!d) return;

    bool any_moved = false;
    struct dirent *ent;
    /* First pass: check if there's actually anything to archive */
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        if (name[0] == '.') continue;                      /* ., .. hidden */
        if (strncmp(name, "previous_run.", 13) == 0) continue; /* old archives */
        any_moved = true;
        break;
    }
    closedir(d);

    if (!any_moved) return;   /* nothing to archive */

    /* Create the archive directory before moving items into it */
    mkdir(archive_dir, 0755);

    d = opendir(output_dir);
    if (!d) return;

    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        if (name[0] == '.') continue;
        if (strncmp(name, "previous_run.", 13) == 0) continue;

        char src[MAX_PATH_LEN], dst[MAX_PATH_LEN];
        snprintf(src, sizeof(src), "%s/%s", output_dir, name);
        snprintf(dst, sizeof(dst), "%s/%s", archive_dir, name);
        rename(src, dst);   /* O(1) on same filesystem */
    }
    closedir(d);

    LOG_EXEC_ONLY("Archived previous run to: %s", archive_dir);
}

/*
 * archive_extraction_output() — called by --re-extract before clearing the
 * extracted IDs checkpoint.  Moves the three recovered subdirectories into
 * previous_extraction.TIMESTAMP/ if they are non-empty, and backs up
 * recovery_summary.md and unrecovered_files.md to logs/.
 */
static void archive_extraction_output(const char *output_dir) {
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", tm_info);

    /* Move recovered subdirectories */
    char archive_dir[MAX_PATH_LEN];
    snprintf(archive_dir, sizeof(archive_dir),
             "%s/previous_extraction.%s", output_dir, ts);

    static const char * const subdirs[] = {
        "recovered_files", "recovered_orphans", "recovered_unknown_format",
        "recovered_deleted", NULL
    };

    bool any = false;
    for (int i = 0; subdirs[i]; i++) {
        char src[MAX_PATH_LEN];
        snprintf(src, sizeof(src), "%s/%s", output_dir, subdirs[i]);
        struct stat st;
        if (stat(src, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        DIR *d = opendir(src);
        if (!d) continue;
        bool has_files = false;
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL)
            if (ent->d_name[0] != '.') { has_files = true; break; }
        closedir(d);
        if (!has_files) continue;
        if (!any) { mkdir(archive_dir, 0755); any = true; }
        char dst[MAX_PATH_LEN];
        snprintf(dst, sizeof(dst), "%s/%s", archive_dir, subdirs[i]);
        rename(src, dst);
    }
    if (any)
        LOG_EXEC_ONLY("Archived previous extraction output to: %s", archive_dir);

    /* Back up report .md files (excluding file_list.md) to logs/ */
    static const char * const reports[] = {
        "recovery_summary.md", "unrecovered_files.md", NULL
    };
    for (int i = 0; reports[i]; i++) {
        char src[MAX_PATH_LEN], dst[MAX_PATH_LEN];
        snprintf(src, sizeof(src), "%s/%s", output_dir, reports[i]);
        struct stat st;
        if (stat(src, &st) != 0) continue;
        /* Strip .md suffix, append _TIMESTAMP.md */
        char base[64];
        strncpy(base, reports[i], sizeof(base) - 1);
        base[sizeof(base) - 1] = '\0';
        char *dot = strrchr(base, '.');
        if (dot) *dot = '\0';
        snprintf(dst, sizeof(dst), "%s/%s_%s.md", g_logs_dir, base, ts);
        rename(src, dst);
        LOG_EXEC_ONLY("Backed up %s to logs/", reports[i]);
    }
}

/* ============================================================================
 * --list mode output
 * ============================================================================
 */

/*
 * count_scan_files() — count named files, orphan inodes, and total byte size
 * from the in-memory scan results.  Used to populate the scan summary box.
 */
static void count_scan_files(int *out_named, int *out_orphans, uint64_t *out_size) {
    int named = 0, orphans = 0;
    uint64_t sz = 0;

    /* Deduplicate named drecs by inode ID: allocate a seen-flag array the same
     * way deduplicate_drecs() does, so this count matches the extraction work
     * list that will be built later.  Without dedup, hard-linked or
     * corruption-duplicated drecs inflate the scan-box count above the real
     * extraction total.
     *
     * Also build a drec-based is_dir array so the orphan section uses the same
     * directory classification as recovery_extract_files(), avoiding a mismatch
     * when the APFS inode is_dir bit disagrees with the drec is_dir field. */
    bool *seen       = calloc(g_max_inodes, sizeof(bool));
    bool *is_dir_drec = calloc(g_max_inodes, sizeof(bool));

    if (is_dir_drec) {
        /* Bug fix: use hash index (not linear array index) for inode-level dirs */
        for (int i = 0; i < g_inode_count; i++) {
            if (g_inodes[i].is_dir) {
                int64_t ix = get_inode_idx(g_inodes[i].inode_id);
                if (ix >= 0) is_dir_drec[ix] = true;
            }
        }
        for (int i = 0; i < g_drec_count; i++) {
            if (g_drecs[i].is_dir) {
                int64_t ix = get_inode_idx(g_drecs[i].file_inode);
                if (ix >= 0) is_dir_drec[ix] = true;
            }
        }
    }

    for (int i = 0; i < g_drec_count; i++) {
        if (g_drecs[i].is_dir) continue;
        inode_t *ino = find_inode(g_drecs[i].file_inode);
        if (!ino) continue;
        int64_t idx = get_inode_idx(g_drecs[i].file_inode);
        if (idx < 0) continue;
        /* Bug fix: also exclude inodes marked as directories in the inode table */
        if (is_dir_drec && is_dir_drec[idx]) continue;
        if (seen) {
            if (seen[idx]) continue;   /* already counted this inode */
            seen[idx] = true;
        }
        named++; sz += ino->size;
    }
    /* NOTE: seen[] is kept alive so the orphan loop can skip inodes already
     * counted in the named section (those with a drec but no resolved path). */

    for (int i = 0; i < g_inode_count; i++) {
        inode_t *ino = &g_inodes[i];
        if (ino->inode_id == 0 || ino->extent_count == 0) continue;
        int64_t idx = get_inode_idx(ino->inode_id);
        if (idx < 0) continue;
        /* Use drec-based directory classification (same as extraction work list) */
        if (is_dir_drec && is_dir_drec[idx]) continue;
        if (!g_paths || g_paths[idx]) continue;   /* skip if path resolved */
        /* Skip if already counted in the named section */
        if (seen && seen[idx]) continue;
        orphans++; sz += ino->size;
    }

    free(seen);
    free(is_dir_drec);
    *out_named = named; *out_orphans = orphans; *out_size = sz;
}

/*
 * write_file_list() — write a full list of recoverable files to
 * output_dir/file_list.md after every normal extraction run.
 *
 * Written directly to a file (not via LOG_NORMAL) so it does not flood the
 * execution log with hundreds of thousands of lines.
 */
static void write_file_list(const char *output_dir) {
    char list_path[MAX_PATH_LEN];
    snprintf(list_path, sizeof(list_path), "%s/file_list.md", output_dir);
    FILE *f = fopen(list_path, "w");
    if (!f) return;

    int      named_count  = 0;
    int      orphan_count = 0;
    uint64_t total_size   = 0;

    /* Count pass */
    for (int i = 0; i < g_drec_count; i++) {
        if (g_drecs[i].is_dir) continue;
        uint64_t  fi  = g_drecs[i].file_inode;
        inode_t  *ino = find_inode(fi);
        if (!ino) continue;
        int64_t idx = get_inode_idx(fi);
        if (idx < 0) continue;
        const char *path = (g_paths && g_paths[idx]) ? g_paths[idx] : NULL;
        if (g_pilot_filter && (!path || !strstr(path, g_pilot_filter))) continue;
        if (!util_matches_filter_ext(g_drecs[i].name)) continue;
        if (g_min_file_size > 0 && ino->size < g_min_file_size) continue;
        if (ino->size > g_max_file_size) continue;
        named_count++;
        total_size += ino->size;
    }
    if (g_filter_ext_count == 0) {
        for (int i = 0; i < g_inode_count; i++) {
            inode_t *ino = &g_inodes[i];
            if (ino->inode_id == 0 || ino->is_dir || ino->extent_count == 0) continue;
            if (g_paths && g_paths[i]) continue;
            if (g_min_file_size > 0 && ino->size < g_min_file_size) continue;
            if (ino->size > g_max_file_size) continue;
            orphan_count++;
            total_size += ino->size;
        }
    }

    /* Header */
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);
    char snf[32], soc[32], ssz[32];
    fprintf(f, "# Recovered File List\n\n");
    fprintf(f, "Generated: %s  \n", ts);
    fprintf(f, "Named files: %s  \n", util_format_num((uint64_t)named_count, snf));
    fprintf(f, "Orphans:     %s  \n", util_format_num((uint64_t)orphan_count, soc));
    fprintf(f, "Total size:  ~%s  \n", util_format_size(total_size, ssz));
    if (g_filter_ext_count > 0 || g_pilot_filter)
        fprintf(f, "Filters: %s%s  \n",
                g_pilot_filter        ? "--pilot "       : "",
                g_filter_ext_count > 0 ? "--filter-ext"  : "");
    fprintf(f, "\n## Named Files\n\n```\n");

    /* Named files */
    for (int i = 0; i < g_drec_count; i++) {
        if (g_drecs[i].is_dir) continue;
        uint64_t  fi  = g_drecs[i].file_inode;
        inode_t  *ino = find_inode(fi);
        if (!ino) continue;
        int64_t idx = get_inode_idx(fi);
        if (idx < 0) continue;
        const char *path = (g_paths && g_paths[idx]) ? g_paths[idx] : NULL;
        if (g_pilot_filter && (!path || !strstr(path, g_pilot_filter))) continue;
        if (!util_matches_filter_ext(g_drecs[i].name)) continue;
        if (g_min_file_size > 0 && ino->size < g_min_file_size) continue;
        if (ino->size > g_max_file_size) continue;
        char s[32];
        fprintf(f, "%12s  %s\n",
                util_format_num(ino->size, s),
                path ? path : g_drecs[i].name);
    }
    fprintf(f, "```\n");

    /* Orphan summary */
    if (orphan_count > 0) {
        fprintf(f, "\n## Orphans (no resolved path)\n\n");
        fprintf(f, "%s files with no directory entry → `recovered_orphans/`  \n",
                util_format_num((uint64_t)orphan_count, snf));
    }

    fclose(f);
    LOG_EXEC_ONLY("File list written: %s", list_path);
}

/* ============================================================================
 * Terminal UI helpers
 * ============================================================================
 */

/*
 * print_banner() — styled tool header on terminal; plain format in log file.
 */
static void print_banner(const char *image_path, const char *output_dir) {
    /* Log file gets the classic ==== format */
    LOG_EXEC_ONLY("======================================================================");
    LOG_EXEC_ONLY("apfs-excavate %s", TOOL_VERSION);
    LOG_EXEC_ONLY("======================================================================");
    LOG_EXEC_ONLY("Disk Image:    %s", image_path);
    LOG_EXEC_ONLY("Output Folder: %s", output_dir);

    /* Terminal gets a clean styled banner with tagline */
    const char *tagline = "Excavating your lost files";
    /* Display width: "apfs-excavate " (14) + version + "  —  " (5 display cols,
     * — is U+2014 = 1 col) + tagline */
    int line_len = 14 + (int)strlen(TOOL_VERSION) + 5 + (int)strlen(tagline);
    if (g_term_color) {
        printf("%s%sapfs-excavate %s%s  \xe2\x80\x94  %s%s%s\n",
               T_BCYAN, T_BOLD, TOOL_VERSION, T_RESET,
               T_BYELLOW, tagline, T_RESET);
        for (int i = 0; i < line_len; i++) fputs("\xe2\x94\x81", stdout); /* ━ */
        printf("\n");
        printf("%sDisk Image:    %s%s\n", T_DIM, image_path, T_RESET);
        printf("%sOutput Folder: %s%s\n", T_DIM, output_dir, T_RESET);
    } else {
        printf("apfs-excavate %s  \xe2\x80\x94  %s\n", TOOL_VERSION, tagline);
        for (int i = 0; i < line_len; i++) fputs("\xe2\x94\x81", stdout); /* ━ */
        printf("\n");
        printf("Disk Image:    %s\n", image_path);
        printf("Output Folder: %s\n", output_dir);
    }
    printf("\n");
    fflush(stdout);
}

/*
 * print_scan_summary_box() — compact Unicode box after scanning.
 * Always green border and "SCANNING COMPLETE — SUCCESS" title.
 * scan_only=true  → shows the "To extract..." hint in the footer
 * scan_only=false → "List of files saved" only (normal run or interrupted-path-resolution)
 */
static void print_scan_summary_box(int total_files, uint64_t total_sz,
                                   bool scan_only) {
    char sf[32], ss_fmt[48];
    util_format_num((uint64_t)total_files, sf);

    /* Integer-rounded size estimate with * footnote marker */
    {
        double d = (double)total_sz;
#ifdef __APPLE__
        if      (d >= 1e12) snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f TB", d / 1e12);
        else if (d >= 1e9)  snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f GB", d / 1e9);
        else if (d >= 1e6)  snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f MB", d / 1e6);
        else if (d >= 1e3)  snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f KB", d / 1e3);
        else                snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f B",  d);
#else
        if      (d >= 1099511627776.0) snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f TiB", d / 1099511627776.0);
        else if (d >= 1073741824.0)    snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f GiB", d / 1073741824.0);
        else if (d >= 1048576.0)       snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f MiB", d / 1048576.0);
        else if (d >= 1024.0)          snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f KiB", d / 1024.0);
        else                           snprintf(ss_fmt, sizeof(ss_fmt), "~%.0f B",   d);
#endif
    }

    const char *title = "SCANNING COMPLETE \xe2\x80\x94 SUCCESS";

    /* Log file: plain ==== format */
    LOG_EXEC_ONLY("======================================================================");
    LOG_EXEC_ONLY("%s", title);
    LOG_EXEC_ONLY("Files found : %s", sf);
    LOG_EXEC_ONLY("Est. size   : %s", ss_fmt);
    LOG_EXEC_ONLY("======================================================================");

    /* Terminal: Unicode box
     * title: — is U+2014 (3 UTF-8 bytes, 1 display col)
     * data_w = 2 (margin) + 13 (label) + 3 (" : ") + 11 (number right-aligned) + 2 = 31
     * interior = max(data_w, title_display + 4) */
    int title_display = (int)strlen(title) - 2; /* — is 3 bytes, 1 display col */
    int data_w        = 31;
    int interior      = title_display + 4;
    if (interior < data_w) interior = data_w;
    int max_interior  = g_term_width - 2;
    if (max_interior > 54) max_interior = 54;
    if (interior > max_interior) interior = max_interior;
    int extra = interior - data_w;  /* extra right padding for data rows */

    const char *bordcol = g_term_color ? T_BGREEN : "";
    const char *starcol = g_term_color ? T_BRED : "";
    const char *msgcol = g_term_color ? T_CYAN : "";
    const char *boldcol = g_term_color ? T_BOLD : "";
    const char *dimcol = g_term_color ? T_DIM : "";
    const char *reset   = g_term_color ? T_RESET  : "";

    printf("\n");

    /* Top border */
    printf("  %s" BOX_TL, bordcol);
    for (int i = 0; i < interior; i++) printf(BOX_H);
    printf(BOX_TR "%s\n", reset);

    /* Title line */
    printf("  %s" BOX_V "%s  %s%s%s%s",
           bordcol, reset,
           g_term_color ? T_BCYAN : "", title,
           g_term_color ? T_RESET : "",
           g_term_color ? bordcol : "");
    int pad = interior - 4 - title_display;
    for (int i = 0; i < pad; i++) printf(" ");
    printf("  " BOX_V "%s\n", reset);

    /* Blank interior line */
    printf("  %s" BOX_V "%s", bordcol, reset);
    for (int i = 0; i < interior; i++) printf(" ");
    printf("%s" BOX_V "%s\n", bordcol, reset);

    /* Data rows: ║  %-13s : %10s<extra>  ║ */
#define SCAN_ROW(label, num_str) do { \
    printf("  %s" BOX_V "%s  %-13s : %10s%s*%s%*s  %s" BOX_V "%s\n", \
           bordcol, reset, (label), (num_str), starcol, reset, extra, "", bordcol, reset); \
} while (0)

    SCAN_ROW("Files found", sf);
    SCAN_ROW("Est. size", ss_fmt);

#undef SCAN_ROW

    /* Bottom border */
    printf("  %s" BOX_BL, bordcol);
    for (int i = 0; i < interior; i++) printf(BOX_H);
    printf(BOX_BR "%s\n", reset);

    /* Post-box lines */
    printf("  %s*%s%s Initial Estimate; actual recovered file count and size may vary.%s\n", starcol, reset, dimcol, reset);
    printf("\n  %sList of files found saved in %sfile_list.md%s %sunder the output folder%s\n", msgcol, boldcol, reset, msgcol, reset);
    if (scan_only)
        printf("\nTo extract all the files, run the same command without --scan-only\n\n");
    fflush(stdout);
}

/*
 * print_summary_box() — compact Unicode box; exec log keeps full ==== format.
 *
 * interrupted=false: normal completion box (green=success, red=no files)
 * interrupted=true:  red "EXCAVATION INTERRUPTED — PARTIAL" box showing only
 *                    Files found + Files recovered (no skipped/failed mid-run)
 *
 * Counts:
 *   files_found     = result.files_found + result.orphans_identified
 *   files_recovered = extracted + result.previously_extracted
 *   files_skipped   = result.skipped_size_count  (hidden when 0)
 *   files_failed    = g_unrecovered_count - skipped  (hidden when 0)
 */
static void print_summary_box(const result_t *r, int extracted, bool interrupted) {
    /* Prefer checkpoint-based cumulative stats (available whenever extraction has
     * run at least once).  Fallback to per-run globals when checkpoint has no
     * stats yet (e.g. very early Ctrl-C before the first file was saved). */
    int files_found, files_recovered, files_skipped, zero_byte_removed, files_deduped;

    if (g_cp_extract_stats.files_found > 0) {
        files_found       = (int)g_cp_extract_stats.files_found;
        files_recovered   = (int)g_cp_extract_stats.files_recovered;
        files_skipped     = (int)g_cp_extract_stats.files_skipped;
        zero_byte_removed = (int)g_cp_extract_stats.files_zero_byte;
        files_deduped     = (int)g_cp_extract_stats.files_deduped;
    } else {
        /* Fallback: extraction hasn't run or was interrupted before any save. */
        if (g_work_count > 0 || r->previously_extracted > 0)
            files_found = (int)g_work_count + (int)r->previously_extracted;
        else
            files_found = r->files_found
                        + (int)r->orphans_identified
                        + (int)r->orphans_unrecoverable;

        if (r->total_extracted > 0) {
            files_recovered = (int)r->total_extracted
                            - (int)r->skipped_size_count
                            - (int)r->zero_byte_removed;
            if (files_recovered < 0) files_recovered = 0;
        } else {
            files_recovered = extracted + (int)r->previously_extracted;
        }
        files_skipped     = (int)r->skipped_size_count;
        zero_byte_removed = (int)r->zero_byte_removed;
        files_deduped     = 0;
    }

    int files_removed = zero_byte_removed + files_deduped;

    bool success = files_recovered > 0;

    /* "—" is U+2014 (3 UTF-8 bytes, 1 display column) */
    const char *title = interrupted
        ? "EXCAVATION INTERRUPTED \xe2\x80\x94 PARTIAL"
        : (success
            ? "EXCAVATION COMPLETE \xe2\x80\x94 SUCCESS"
            : "EXCAVATION COMPLETE \xe2\x80\x94 NO FILES EXTRACTED");
    int title_display = (int)strlen(title) - 2; /* — is 3 bytes but 1 display col */

    int files_failed = g_unrecovered_count - files_skipped;
    if (files_failed < 0) files_failed = 0;

    /* Box interior width:
     *   data_w   = 2 (margin) + 15 (label) + 3 (" : ") + 11 (num) + 2 (margin) = 33
     *   interior = max(data_w, title_display + 4), clamped to [30, min(54, term-2)] */
    int data_w   = 33;
    int interior = title_display + 4;
    if (interior < data_w) interior = data_w;
    if (interior < 30)     interior = 30;
    int max_interior = g_term_width - 2;
    if (max_interior > 54) max_interior = 54;
    if (interior > max_interior) interior = max_interior;
    int extra = interior - data_w;   /* extra right padding for data rows */

    /* ---- Log file: full detail in plain ==== format ---- */
    {
        char b1[32], b2[32], b3[32], b4[32], b5[32], b6[32], b7[32], b8[32], b9[32];
        LOG_EXEC_ONLY("======================================================================");
        LOG_EXEC_ONLY("EXCAVATION COMPLETE \xe2\x80\x94 %s",
                      success ? "SUCCESS" : "NO FILES EXTRACTED");
        LOG_EXEC_ONLY("Files found     : %s", util_format_num((uint64_t)files_found, b1));
        LOG_EXEC_ONLY("Files recovered : %s", util_format_num((uint64_t)files_recovered, b2));
        if (files_skipped > 0)
            LOG_EXEC_ONLY("Files skipped   : %s", util_format_num((uint64_t)files_skipped, b3));
        if (files_failed > 0)
            LOG_EXEC_ONLY("Files failed    : %s", util_format_num((uint64_t)files_failed, b4));
        if (files_removed > 0)
            LOG_EXEC_ONLY("Files removed   : %s", util_format_num((uint64_t)files_removed, b9));
        LOG_EXEC_ONLY("Directories     : %s", util_format_num((uint64_t)r->directories_found, b5));
        LOG_EXEC_ONLY("Compressed      : %s", util_format_num((uint64_t)r->compressed_files, b6));
        if (r->previously_extracted > 0)
            LOG_EXEC_ONLY("  (this run: %s  prior: %s)",
                util_format_num((uint64_t)extracted, b7),
                util_format_num((uint64_t)r->previously_extracted, b8));
        if (r->deleted_files_found > 0) {
            LOG_EXEC_ONLY("Deleted found   : %s", util_format_num((uint64_t)r->deleted_files_found, b7));
            LOG_EXEC_ONLY("Deleted recov.  : %s", util_format_num((uint64_t)r->deleted_files_recovered, b8));
        }
        if (r->orphans_identified > 0 || r->orphans_unrecoverable > 0)
            LOG_EXEC_ONLY("Orphans         : %s  (unknown format: %s)",
                util_format_num((uint64_t)r->orphans_identified, b7),
                util_format_num((uint64_t)r->orphans_unrecoverable, b8));
        char t1[32], t2[32], t3[32], t4[32], t5[32];
        LOG_EXEC_ONLY("Scan            : %s", util_format_time(r->scan_time, t1));
        LOG_EXEC_ONLY("Build paths     : %s", util_format_time(r->build_time, t2));
        LOG_EXEC_ONLY("Extraction      : %s", util_format_time(r->extract_time, t3));
        LOG_EXEC_ONLY("Post-processing : %s", util_format_time(r->orphan_time, t4));
        LOG_EXEC_ONLY("Total           : %s", util_format_time(r->total_time, t5));
        LOG_EXEC_ONLY("======================================================================");
    }

    /* ---- Terminal: compact Unicode box ---- */
    /* interrupted → red; completed+success → green; completed+no files → red */
    const char *bordcol = g_term_color
        ? ((!interrupted && success) ? T_BGREEN : T_BRED) : "";
    const char *reset   = g_term_color ? T_RESET : "";

    printf("\n");

    /* Top border */
    printf("%s" BOX_TL, bordcol);
    for (int i = 0; i < interior; i++) printf(BOX_H);
    printf(BOX_TR "%s\n", reset);

    /* Title line */
    printf("%s" BOX_V "%s  %s%s%s%s",
           bordcol, reset,
           g_term_color ? T_BCYAN : "", title,
           g_term_color ? T_RESET : "",
           g_term_color ? bordcol : "");
    int pad = interior - 4 - title_display;
    for (int i = 0; i < pad; i++) printf(" ");
    printf("  " BOX_V "%s\n", reset);

    /* Blank interior line */
    printf("%s" BOX_V "%s", bordcol, reset);
    for (int i = 0; i < interior; i++) printf(" ");
    printf("%s" BOX_V "%s\n", bordcol, reset);

    /* Data rows: ║  %-15s : %11s<extra>  ║ */
#define BOX_ROW(label, num_str) do { \
    printf("%s" BOX_V "%s  %-15s : %11s%*s  %s" BOX_V "%s\n", \
           bordcol, reset, (label), (num_str), extra, "", bordcol, reset); \
} while (0)

    char b1[32], b2[32], b3[32], b4[32], b5[32], b6[32], b7[32];
    BOX_ROW("Files found", util_format_num((uint64_t)files_found, b1));
    BOX_ROW("Files recovered", util_format_num((uint64_t)files_recovered, b2));
    if (!interrupted) {
        if (files_skipped > 0)
            BOX_ROW("Files skipped", util_format_num((uint64_t)files_skipped, b3));
        if (files_failed > 0)
            BOX_ROW("Files failed", util_format_num((uint64_t)files_failed, b4));
        if (files_removed > 0)
            BOX_ROW("Files removed", util_format_num((uint64_t)files_removed, b5));
        if (r->deleted_files_found > 0) {
            BOX_ROW("Deleted found", util_format_num((uint64_t)r->deleted_files_found, b6));
            BOX_ROW("Deleted recov.", util_format_num((uint64_t)r->deleted_files_recovered, b7));
        }
    }

#undef BOX_ROW

    /* Bottom border */
    printf("%s" BOX_BL, bordcol);
    for (int i = 0; i < interior; i++) printf(BOX_H);
    printf(BOX_BR "%s\n", reset);

    fflush(stdout);
}

/*
 * print_post_box_section() — recovered file folders + report filenames shown
 * below the summary box.  Headers and arrows in magenta; names in dim.
 *
 * When g_interrupted: recovered folders + file_list.md only (partial run).
 * When not interrupted: full section with all three reports.
 */
static void print_post_box_section(const result_t *r, const char *output_dir) {
    bool interrupted = g_interrupted;
    const char *mag   = g_term_color ? T_MAGENTA : "";
    const char *dim   = g_term_color ? T_DIM     : "";
    const char *reset = g_term_color ? T_RESET   : "";

    /* "→" is U+2192 (UTF-8: 0xe2 0x86 0x92) */
    printf("\n%sRecovered files:%s\n", mag, reset);
    printf("  %s\xe2\x86\x92%s %srecovered_files/%s\n", mag, reset, dim, reset);

    /* Show recovered_orphans/ only when the directory actually has content. */
    bool show_orphans = (r->orphans_identified > 0 || r->orphan_fail_count > 0);
    if (!show_orphans && output_dir) {
        char orph_path[MAX_PATH_LEN];
        snprintf(orph_path, sizeof(orph_path), "%s/recovered_orphans", output_dir);
        DIR *od = opendir(orph_path);
        if (od) {
            struct dirent *oe;
            while ((oe = readdir(od)) != NULL)
                if (oe->d_name[0] != '.') { show_orphans = true; break; }
            closedir(od);
        }
    }
    if (show_orphans)
        printf("  %s\xe2\x86\x92%s %srecovered_orphans/%s\n", mag, reset, dim, reset);

    /* Show recovered_unknown_format/ if this run moved files there, or if the
     * directory is non-empty from a prior run. */
    bool show_unknown = (r->orphans_unrecoverable > 0);
    if (!show_unknown && output_dir) {
        char unrec_path[MAX_PATH_LEN];
        snprintf(unrec_path, sizeof(unrec_path),
                 "%s/recovered_unknown_format", output_dir);
        DIR *ud = opendir(unrec_path);
        if (ud) {
            struct dirent *ue;
            while ((ue = readdir(ud)) != NULL)
                if (ue->d_name[0] != '.') { show_unknown = true; break; }
            closedir(ud);
        }
    }
    if (show_unknown)
        printf("  %s\xe2\x86\x92%s %srecovered_unknown_format/%s\n",
               mag, reset, dim, reset);

    /* Show recovered_deleted/ only when the directory is non-empty. */
    if (output_dir) {
        char del_path[MAX_PATH_LEN];
        snprintf(del_path, sizeof(del_path), "%s/recovered_deleted", output_dir);
        DIR *dd = opendir(del_path);
        if (dd) {
            struct dirent *de;
            bool has_del = false;
            while ((de = readdir(dd)) != NULL)
                if (de->d_name[0] != '.') { has_del = true; break; }
            closedir(dd);
            if (has_del)
                printf("  %s\xe2\x86\x92%s %srecovered_deleted/%s\n",
                       mag, reset, dim, reset);
        }
    }

    printf("\n%sReports:%s\n", mag, reset);
    printf("  %s\xe2\x86\x92%s %sfile_list.md%s\n", mag, reset, dim, reset);
    if (!interrupted) {
        printf("  %s\xe2\x86\x92%s %srecovery_summary.md%s\n", mag, reset, dim, reset);
        if (g_unrecovered_count > 0)
            printf("  %s\xe2\x86\x92%s %sunrecovered_files.md%s\n", mag, reset, dim, reset);
    }
    printf("\n");
    fflush(stdout);
}

/* ============================================================================
 * main()
 * ============================================================================
 */

int main(int argc, char *argv[]) {
    /* Terminal capability detection — must come before any output. */
    term_init();

    /* Help flag — check before anything else. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    if (argc < 2) { print_usage(argv[0]); return 1; }

    /* Register signal handlers so Ctrl-C saves the scan checkpoint. */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_signal;
        sigaction(SIGINT,  &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
    }

    const char *image_path = argv[1];
    const char *output_dir = NULL;
    char        default_output[MAX_PATH_LEN];
    char        files_dir[MAX_PATH_LEN];    /* output_dir/recovered_files  — named files */
    char        orphan_dir[MAX_PATH_LEN];  /* output_dir/recovered_orphans — no-path files */
    char        deleted_dir[MAX_PATH_LEN]; /* output_dir/recovered_deleted — deleted frags */

    /* ---- Parse arguments ------------------------------------------------- */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            g_password = argv[++i];
        } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            g_workers = atoi(argv[++i]);
            if (g_workers < 1)  g_workers = 1;
            if (g_workers > 64) g_workers = 64;
        } else if (strcmp(argv[i], "--skip-metadata") == 0) {
            g_skip_metadata = true;
        } else if (strcmp(argv[i], "--no-compression") == 0) {
            g_enable_compression = false;
        } else if (strcmp(argv[i], "--deleted") == 0) {
            g_enable_deleted_recovery = true;
        } else if (strcmp(argv[i], "--no-resume") == 0) {
            g_no_resume = true;
        } else if (strcmp(argv[i], "--scan-only") == 0) {
            g_scan_only = true;
        } else if (strcmp(argv[i], "--filter-ext") == 0 && i + 1 < argc) {
            char *spec = strdup(argv[++i]);
            if (spec) {
                /* Count tokens to pre-allocate. */
                int count = 1;
                for (char *p = spec; *p; p++) if (*p == ',') count++;
                g_filter_exts = calloc((size_t)count, sizeof(char *));
                if (g_filter_exts) {
                    char *tok = strtok(spec, ",");
                    while (tok && g_filter_ext_count < count) {
                        /* Strip leading dot, lowercase the extension. */
                        char *ext = (tok[0] == '.') ? tok + 1 : tok;
                        char *lower = strdup(ext);
                        if (lower) {
                            for (char *p = lower; *p; p++)
                                *p = (char)tolower((unsigned char)*p);
                            g_filter_exts[g_filter_ext_count++] = lower;
                        }
                        tok = strtok(NULL, ",");
                    }
                }
                free(spec);
            }
        } else if (strcmp(argv[i], "--re-extract") == 0) {
            g_re_extract = true;
        } else if (strcmp(argv[i], "--max-size") == 0 && i + 1 < argc) {
            g_max_file_size = parse_size_arg(argv[++i]);
            if (g_max_file_size == 0) {
                fprintf(stderr, "Warning: --max-size value could not be parsed; using default (50 GB)\n");
                g_max_file_size = 50ULL * 1024 * 1024 * 1024;
            }
        } else if (strcmp(argv[i], "--min-size") == 0 && i + 1 < argc) {
            g_min_file_size = parse_size_arg(argv[++i]);
        } else if (strcmp(argv[i], "--debug") == 0) {
            g_debug_mode = true;
        } else if ((strcmp(argv[i], "-b") == 0 ||
                    strcmp(argv[i], "--block") == 0) && i + 1 < argc) {
            g_override_sb_lba = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--pilot") == 0 && i + 1 < argc) {
            g_pilot_filter = argv[++i];
        } else if (strcmp(argv[i], "--min-xid") == 0 && i + 1 < argc) {
            g_min_xid = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--case-sensitive") == 0) {
            g_case_sensitive = true;  /* CLI override; also checked in detect_volume_features() */
        } else if (argv[i][0] != '-' && !output_dir) {
            output_dir = argv[i];
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Warning: unknown option '%s' (ignored)\n", argv[i]);
        }
    }

    if (!output_dir) {
        snprintf(default_output, sizeof(default_output),
                 "%s_recovered", image_path);
        output_dir = default_output;
    }

    /* ---- Conflict checks -------------------------------------------------- */
    if (g_re_extract && g_no_resume) {
        fprintf(stderr, "%sError: --re-extract and --no-resume cannot be used together.%s\n\n",
                g_term_color ? T_BRED : "", g_term_color ? T_RESET : "");
        return 1;
    }
    if (g_re_extract && g_scan_only) {
        fprintf(stderr, "%sError: --re-extract has no effect with --scan-only.%s\n\n",
                g_term_color ? T_BRED : "", g_term_color ? T_RESET : "");
        return 1;
    }

    snprintf(files_dir,   sizeof(files_dir),   "%s/recovered_files",   output_dir);
    snprintf(orphan_dir,  sizeof(orphan_dir),  "%s/recovered_orphans", output_dir);
    snprintf(deleted_dir, sizeof(deleted_dir), "%s/recovered_deleted", output_dir);

    /* ---- Allocate global buffers ----------------------------------------- */
    g_error_capacity = 1024;
    g_errors = calloc(g_error_capacity, sizeof(error_record_t));
    if (!g_errors) { fprintf(stderr, "ERROR: out of memory\n"); return 1; }

    g_drec_capacity = 1024;
    g_drecs = calloc(g_drec_capacity, sizeof(drec_t));
    if (!g_drecs) { fprintf(stderr, "ERROR: out of memory\n"); return 1; }

    g_deleted_capacity = 1024;
    g_deleted = calloc(g_deleted_capacity, sizeof(deleted_file_t));
    if (!g_deleted) { fprintf(stderr, "ERROR: out of memory\n"); return 1; }

    g_inodes = calloc(g_max_inodes, sizeof(inode_t));
    if (!g_inodes) { fprintf(stderr, "ERROR: out of memory\n"); return 1; }

    g_inode_hash = calloc(g_inode_hash_capacity, sizeof(inode_t *));
    if (!g_inode_hash) { fprintf(stderr, "ERROR: out of memory\n"); return 1; }

    /* ---- HDD warning ----------------------------------------------------- */
    if (g_workers > 1 && image_is_on_hdd(image_path)) {
        fprintf(stderr,
                "Warning: image appears to be on a rotational HDD — multiple\n"
                "workers (%d) will hurt performance due to random seek overhead.\n"
                "--workers is only beneficial for SSD reads. Consider --workers 1.\n\n",
                g_workers);
    }

    /* ---- Create output directory ----------------------------------------- */
    mkdir(output_dir, 0755);

    /* On --no-resume: archive the entire previous run to previous_run.TS/ */
    if (g_no_resume) archive_previous_run(output_dir);

    /* Set up the logs/ subdirectory — all log files and checkpoint binaries
     * live here; only .md report files stay in the output root. */
    {
        char ld[MAX_PATH_LEN];
        snprintf(ld, sizeof(ld), "%s/logs", output_dir);
        mkdir(ld, 0755);
        g_logs_dir = strdup(ld);
    }

    backup_logs_and_summaries(output_dir, g_logs_dir);
    log_init(g_logs_dir, g_debug_mode);

    /* Clear screen on real terminals for a clean start */
    if (g_term_color) {
        printf("\033[2J\033[H");
        fflush(stdout);
    }

    print_banner(image_path, output_dir);

    /* ====================================================================== */
    /* Phase 0: Pre-flight checks                                              */
    /* ====================================================================== */
    LOG_PHASE(0, "Pre-flight checks");

    /* ---- Detect non-POSIX output filesystem (ExFAT/FAT/NTFS) ------------ *
     * Metadata restoration (chmod/chown/timestamps/BSD flags) will silently  *
     * fail or produce wrong results on these filesystems.  Warn early so the  *
     * user can choose a POSIX destination if metadata matters to them.        *
     * Skipped for --scan-only runs (no files are written in that mode).       */
    if (!g_scan_only) {
#ifdef __APPLE__
        {
            struct statfs sfs;
            const char *fstype = "non-POSIX";
            if (statfs(output_dir, &sfs) == 0) {
                fstype = sfs.f_fstypename;
                if (strcasecmp(fstype, "exfat") == 0 ||
                    strcasecmp(fstype, "msdos") == 0 ||
                    strcasecmp(fstype, "ntfs")  == 0) {
                    g_output_nonposix = true;
                }
            }
            if (g_skip_metadata)
                LOG_EXEC_ONLY("--skip-metadata: timestamps, permissions, ownership and BSD flags will not be restored");
            if (g_output_nonposix) {
                if (g_term_color)
                    fprintf(stdout,
                            "  %s⚠  Output drive is %s — file ownership, permissions, and\n"
                            "     timestamps cannot be restored on this filesystem.%s\n",
                            T_BMAGENTA, fstype, T_RESET);
                else
                    fprintf(stdout,
                            "  [WARN] Output drive is non-POSIX (%s) — file ownership, "
                            "permissions, and timestamps cannot be restored.\n", fstype);
                LOG_EXEC_ONLY("Output drive is non-POSIX (%s) — metadata restoration skipped",
                              fstype);
                fflush(stdout);
            }
        }
#endif
    }

    /* ---- Open image ------------------------------------------------------ */
    LOG_EXEC_ONLY("Opening image: %s", image_path);
    int exit_code = 0;
    int fd = open(image_path, O_RDONLY);
    if (fd < 0) {
        LOG_ERROR("Cannot open '%s': %s", image_path, strerror(errno));
        return 1;
    }
    g_fd = fd;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        LOG_ERROR("fstat failed: %s", strerror(errno));
        close(fd); return 1;
    }
    if (st.st_size < 0) {
        LOG_ERROR("Image file reports negative size.");
        close(fd); return 1;
    }
    g_data_size = (size_t)st.st_size;
    if (g_data_size == 0) {
        LOG_ERROR("Image file is empty.");
        close(fd); return 1;
    }

    /* ---- Memory-map image ------------------------------------------------ */
    {
        char sz[32];
        LOG_EXEC_ONLY("Mapping %s image into memory", util_format_size((uint64_t)g_data_size, sz));
    }
    g_data = mmap(NULL, g_data_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (g_data == MAP_FAILED) {
        LOG_ERROR("mmap failed: %s", strerror(errno));
        close(fd); return 1;
    }
    madvise(g_data, g_data_size, MADV_SEQUENTIAL);

    result_t result      = {0};
    double   total_start = util_get_time_ms();
    bool     is_encrypted = false;
    bool     resumed      = false;

    /* ---- Try to load scan results early ---------------------------------- *
     * If scan_results.bin exists it contains the image geometry, encryption  *
     * flag, and case-sensitivity — everything Phase 0 steps 3-6 would find.  *
     * Skip those steps entirely and go straight to Phase 1 (if encrypted).   */
    if (!g_no_resume && cp_load_scan()) {
        resumed      = true;
        is_encrypted = g_encryption_enabled;
        result.keybag_found = is_encrypted;
        LOG_EXEC_ONLY("Scan results loaded — partition and encryption checks skipped");
        LOG_DEBUG("Partition offset: %llu bytes", (unsigned long long)g_partition_offset);
        LOG_DEBUG("Container offset: %llu bytes", (unsigned long long)g_container_offset);
        LOG_DEBUG("Block size:       %u bytes",   g_block_size);
        if (is_encrypted)
            LOG_INFO("Volume is ENCRYPTED — key derivation required");
        LOG_OK("Pre-flight passed (resumed from checkpoint)");
    } else {
        /* ---- Quick APFS signature check ---------------------------------- */
        LOG_EXEC_ONLY("Checking for APFS signatures...");
        bool sig_warning_pending = false;
        {
            bool has_nxsb = (memmem(g_data,
                                    g_data_size < 64*1024*1024 ? g_data_size : 64*1024*1024,
                                    "NXSB", 4) != NULL);
            bool has_apsb = (memmem(g_data,
                                    g_data_size < 64*1024*1024 ? g_data_size : 64*1024*1024,
                                    "APSB", 4) != NULL);
            if (!has_nxsb && !has_apsb)
                sig_warning_pending = true;
        }

        /* ---- Detect volume features (case sensitivity from APSB) --------- */
        LOG_EXEC_ONLY("Reading volume features...");
        detect_volume_features(g_case_sensitive);
        LOG_EXEC_ONLY("Volume case-sensitive: %s",
                      g_case_sensitive ? "yes" : "no (default APFS behaviour)");

        /* ---- Locate partition --------------------------------------------- */
        LOG_EXEC_ONLY("Locating APFS container...");
        const uint8_t *active_sb = find_partition();

        if (active_sb && active_sb != g_data + g_partition_offset) {
            uint64_t desc_base   = get_u64(active_sb + 48);
            uint32_t desc_blocks = get_u32(active_sb + 56);
            uint64_t data_base   = get_u64(active_sb + 64);
            uint32_t data_blocks = get_u32(active_sb + 72);
            LOG_DEBUG("Checkpoint superblock: desc_base=%llu desc_blocks=%u "
                      "data_base=%llu data_blocks=%u",
                      (unsigned long long)desc_base, desc_blocks,
                      (unsigned long long)data_base, data_blocks);
        }

        if (g_container_offset == 0)
            g_container_offset = g_partition_offset;

        LOG_DEBUG("Partition offset: %llu bytes", (unsigned long long)g_partition_offset);
        LOG_DEBUG("Container offset: %llu bytes", (unsigned long long)g_container_offset);
        LOG_DEBUG("Block size:       %u bytes",   g_block_size);

        /* #5: Validate block size before any stack/heap buffers are sized from it. */
        if (g_block_size == 0 || g_block_size > 65536 ||
            (g_block_size & (g_block_size - 1)) != 0) {
            fprintf(stderr, "%sError: unsupported block size %u (must be power-of-2, 512–65536).%s\n",
                    g_term_color ? T_BRED : "", g_block_size,
                    g_term_color ? T_RESET : "");
            return 1;
        }

        /* ---- Encryption --------------------------------------------------- */
        {
            LOG_EXEC_ONLY("Checking encryption status...");
            uint8_t *kdata = NULL; size_t klen = 0;
            if (crypto_find_and_decrypt_keybag(&kdata, &klen)) {
                is_encrypted        = true;
                result.keybag_found = true;
                free(kdata);
            }
        }

        /* Emit the deferred signature warning only for unencrypted images;
         * on encrypted volumes NXSB/APSB may not be visible in plaintext. */
        if (sig_warning_pending && !is_encrypted)
            LOG_WARN("No APFS signature (NXSB/APSB) in first 64 MB — "
                     "may not be an APFS image. Continuing anyway.");
        if (is_encrypted && !g_password)
            LOG_INFO("Volume is ENCRYPTED — use --password to decrypt");
        else if (is_encrypted && g_password)
            LOG_INFO("Volume is ENCRYPTED — key derivation required");
        if (!is_encrypted || g_password)
            LOG_OK("Pre-flight passed");
    }

    if (is_encrypted) {
        if (!g_password) {
            LOG_ERROR("Password required for encrypted volume. Use --password <pwd>");
            exit_code = 1; goto cleanup;
        }
        LOG_PHASE(1, "Deriving encryption key");
        crypto_find_volume_uuid();

        uint8_t *kdata = NULL; size_t klen = 0;
        if (!crypto_find_and_decrypt_keybag(&kdata, &klen)) {
            LOG_ERROR("Failed to locate keybag.");
            exit_code = 1; goto cleanup;
        }
        keybag_t keybag = {0};
        if (crypto_parse_keybag(kdata, klen, &keybag)) {
            if (crypto_derive_vek_from_password(&keybag)) {
                result.vek_derived = true;
                LOG_OK("Encryption key derived");
            } else {
                LOG_ERROR("Failed to derive encryption key — wrong password?");
                crypto_free_keybag(&keybag); free(kdata);
                exit_code = 1; goto cleanup;
            }
            crypto_free_keybag(&keybag);
        }
        free(kdata);
        LOG_NORMAL("");
    } else {
        if (g_password)
            LOG_WARN("--password provided but volume is not encrypted (ignoring)");
    }

    /* ---- Scan phase ------------------------------------------------------- */
    if (resumed) {
        int comp = 0;
        for (int i = 0; i < g_inode_count; i++)
            if (g_inodes[i].is_compressed) comp++;
        char b1[32], b2[32], b3[32];
        LOG_EXEC_ONLY("Resumed: %s drecs, %s inodes (%s compressed)",
                      util_format_num((uint64_t)g_drec_count, b1),
                      util_format_num((uint64_t)g_inode_count, b2),
                      util_format_num((uint64_t)comp, b3));
        /* Count paths loaded from checkpoint for recovery_summary.md */
        if (g_paths) {
            int cnt = 0;
            for (uint32_t i = 0; i < (uint32_t)g_max_inodes; i++)
                if (g_paths[i]) cnt++;
            result.paths_resolved = cnt;
        }
    }

    /* ---- --re-extract: archive previous output, clear extraction checkpoint - */
    if (g_re_extract) {
        if (!resumed) {
            LOG_ERROR("--re-extract requires a completed scan checkpoint.");
            LOG_NORMAL("  Run without --re-extract first to scan the disk image.");
            goto cleanup;
        }
        archive_extraction_output(output_dir);
        char ext_cp[MAX_PATH_LEN];
        snprintf(ext_cp, sizeof(ext_cp), "%s/extracted_ids.bin", g_logs_dir);
        unlink(ext_cp);
        char del_done_cp[MAX_PATH_LEN];
        snprintf(del_done_cp, sizeof(del_done_cp), "%s/deleted_done.flag", g_logs_dir);
        unlink(del_done_cp);
        char pt_coll_cp[MAX_PATH_LEN];
        snprintf(pt_coll_cp, sizeof(pt_coll_cp), "%s/pt_collisions.bin", g_logs_dir);
        unlink(pt_coll_cp);
        LOG_EXEC_ONLY("--re-extract: cleared extracted_ids.bin, deleted_done.flag, pt_collisions.bin, re-running extraction");
    }

    if (!resumed) {
        LOG_PHASE(2, "Scanning disk image for files");
        double scan_start = util_get_time_ms();
        int nodes = scan_image(true);
        result.scan_time = (util_get_time_ms() - scan_start) / 1000.0;

        if (g_interrupted) {
            util_progress_newline();
            LOG_EXEC_ONLY("Interrupted during scan — saving checkpoint...");
            cp_save_scan(false);
            {
                char t[32];
                util_format_time(result.scan_time, t);
                if (g_term_color) {
                    fprintf(stdout, "  %sScanning interrupted after %s%s\n",
                            T_BRED, t, T_RESET);
                    fprintf(stdout, "  Run again to continue. "
                            "Run with --no-resume to restart the scan.\n");
                } else {
                    fprintf(stdout, "  Scanning interrupted after %s\n", t);
                    fprintf(stdout, "  Run again to continue. "
                            "Run with --no-resume to restart the scan.\n");
                }
                LOG_EXEC_ONLY("Scanning interrupted after %s", t);
                LOG_EXEC_ONLY("Run again to continue. "
                              "Run with --no-resume to restart the scan.");
                fflush(stdout);
            }
            goto cleanup;
        }

        int comp = 0;
        for (int i = 0; i < g_inode_count; i++)
            if (g_inodes[i].is_compressed) comp++;

        char b1[32], b2[32], b3[32], b4[32], b5[32], t1[32];
        LOG_EXEC_ONLY("Found %s B-tree nodes", util_format_num((uint64_t)nodes, b1));
        LOG_EXEC_ONLY("Found %s directory records",
                      util_format_num((uint64_t)g_drec_count, b2));
        LOG_EXEC_ONLY("Found %s inodes (%s compressed)",
                      util_format_num((uint64_t)g_inode_count, b3),
                      util_format_num((uint64_t)comp, b4));
        LOG_EXEC_ONLY("Found %s potential deleted files",
                      util_format_num((uint64_t)g_deleted_count, b5));
        LOG_OK("Scanning completed in %s", util_format_time(result.scan_time, t1));

        LOG_PHASE(3, "Resolving folder paths of the files");
        double build_start = util_get_time_ms();
        int paths = recovery_build_paths(false);   /* no progress bar — too fast */
        result.build_time    = (util_get_time_ms() - build_start) / 1000.0;
        result.paths_resolved = paths;

        char n_p[32], t2[32];
        LOG_EXEC_ONLY("Resolved %s paths", util_format_num((uint64_t)paths, n_p));
        LOG_OK("Folder paths resolved in %s", util_format_time(result.build_time, t2));

        cp_save_scan(true);

        {
            int named_sc = 0, orphans_sc = 0;
            uint64_t total_sz_sc = 0;
            count_scan_files(&named_sc, &orphans_sc, &total_sz_sc);
            result.scan_estimate_files = named_sc + orphans_sc;

            /* Ctrl-C during path resolution: checkpoint is saved complete.
             * Show green scan box, then print the interruption notice and exit. */
            if (g_interrupted) {
                write_file_list(output_dir);
                print_scan_summary_box(named_sc + orphans_sc, total_sz_sc, false);
                {
                    char t[32];
                    util_format_time((util_get_time_ms() - total_start) / 1000.0, t);
                    if (g_term_color) {
                        printf("  %sExcavation interrupted after %s%s\n",
                               T_BRED, t, T_RESET);
                        printf("  Run the same command again to start extraction.\n\n");
                    } else {
                        printf("  Excavation interrupted after %s\n", t);
                        printf("  Run the same command again to start extraction.\n\n");
                    }
                    LOG_EXEC_ONLY("Excavation interrupted after %s", t);
                    fflush(stdout);
                }
                goto cleanup;
            }

            /* ---- Scan-only mode ------------------------------------------ */
            if (g_scan_only) {
                write_file_list(output_dir);
                print_scan_summary_box(named_sc + orphans_sc, total_sz_sc, true);
                goto cleanup;
            }

            /* ---- Normal run: show scan box + file list before extraction --- */
            write_file_list(output_dir);
            print_scan_summary_box(named_sc + orphans_sc, total_sz_sc, false);
        }
    }   /* end if (!resumed) */

    /* For resumed runs (scan done in a prior session), show the scan summary
     * box now so the user sees what was found before extraction begins. */
    if (resumed && !g_scan_only) {
        int named_sc = 0, orphans_sc = 0;
        uint64_t total_sz_sc = 0;
        count_scan_files(&named_sc, &orphans_sc, &total_sz_sc);
        result.scan_estimate_files = named_sc + orphans_sc;
        print_scan_summary_box(named_sc + orphans_sc, total_sz_sc, false);
    }

    /* ---- Scan-only mode (also handles resumed + --scan-only) ------------- */
    if (g_scan_only) {
        int named_sc = 0, orphans_sc = 0;
        uint64_t total_sz_sc = 0;
        count_scan_files(&named_sc, &orphans_sc, &total_sz_sc);
        result.scan_estimate_files = named_sc + orphans_sc;
        if (resumed) write_file_list(output_dir);  /* fresh scan already wrote it above */
        print_scan_summary_box(named_sc + orphans_sc, total_sz_sc, true);
        goto cleanup;
    }

    /* ---- Extraction phase ------------------------------------------------ */

    /* Load persisted possibly-truncated and collision records from prior runs
     * so recovery_summary.md consolidates data across all resumed extractions.
     * Skipped on --re-extract (file is unlinked above) and --no-resume
     * (archive_previous_run moved the whole logs/ directory). */
    if (!g_re_extract && !g_no_resume)
        cp_load_pt_collisions();

    madvise(g_data, g_data_size, MADV_RANDOM);
    mkdir(files_dir, 0755);
    if (g_enable_deleted_recovery)
        mkdir(deleted_dir, 0755);

    /* Disk space check moved inside recovery_extract_files() — it now runs after
     * the work list is built, so it only counts PENDING files (not already
     * extracted ones), giving an accurate figure on resumed runs. */

    const char *interrupted_phase = NULL;   /* set when Ctrl-C fires in Phase 4 or 6 */

    int comp_count = 0;
    double extract_start = util_get_time_ms();
    int extracted = recovery_extract_files(files_dir, orphan_dir,
                                           output_dir, true, &comp_count);
    result.extract_time = (util_get_time_ms() - extract_start) / 1000.0;
    result.files_extracted = extracted;
    result.compressed_files = comp_count;
    {
        char t[32];
        util_format_time(result.extract_time, t);
        if (g_interrupted) {
            interrupted_phase = "Extraction";
            if (g_term_color)
                fprintf(stdout, "  %sExtraction interrupted after %s%s\n",
                        T_BRED, t, T_RESET);
            else
                fprintf(stdout, "  Extraction interrupted after %s\n", t);
            LOG_EXEC_ONLY("Extraction interrupted after %s", t);
            fflush(stdout);
        } else if (g_work_count == 0 && g_cp_extract_stats.files_found > 0) {
            /* "Nothing left to extract" was already printed inside recovery_extract_files.
             * Still restore directory metadata so timestamps are always applied. */
            recovery_restore_dir_metadata(files_dir);
        } else {
            LOG_OK("Extraction completed in %s", t);
            /* Restore directory timestamps/permissions AFTER the extraction
             * LOG_OK line and BEFORE the next phase, so the terminal reads:
             *   ✓ Extraction completed …
             *   ▶ Restoring folder metadata
             *   ✓ Folder metadata restored for N folders */
            recovery_restore_dir_metadata(files_dir);
        }
    }

    /* ---- Deleted file recovery ------------------------------------------- */
    /* Checkpoint flag so resume runs skip this phase (deleted blocks don't     *
     * change between runs, so re-extraction would just overwrite the same       *
     * files and discard any already-applied type-detection renames).            */
    char del_done_path[MAX_PATH_LEN];
    snprintf(del_done_path, sizeof(del_done_path), "%s/deleted_done.flag", g_logs_dir);
    int del_rec = 0;

    if (g_enable_deleted_recovery && g_deleted_count > 0) {
        if (access(del_done_path, F_OK) == 0) {
            FILE *df = fopen(del_done_path, "r");
            if (df) { (void)fscanf(df, "%d", &del_rec); fclose(df); }
            LOG_EXEC_ONLY("Deleted recovery already done (resume) — %d fragments", del_rec);
        } else {
            LOG_PHASE(5, "Recovering deleted files");
            double del_start = util_get_time_ms();
            del_rec = recovery_extract_deleted(deleted_dir);
            double del_elapsed = (util_get_time_ms() - del_start) / 1000.0;
            {
                char t[32], n[32];
                LOG_OK("Deleted files recovery completed in %s (%s fragments)",
                       util_format_time(del_elapsed, t),
                       util_format_num((uint64_t)del_rec, n));
            }
            FILE *df = fopen(del_done_path, "w");
            if (df) { fprintf(df, "%d\n", del_rec); fclose(df); }
            else LOG_WARN("Could not write deleted_done.flag — resume will re-run deleted phase: %s",
                          strerror(errno));
        }
        result.deleted_files_recovered = del_rec;
    }
    result.deleted_files_found    = g_deleted_count;
    /* Include both size-filtered and ext-filtered in the skipped total. */
    result.skipped_size_count     = (uint64_t)g_cp_extract_stats.files_skipped;
    result.zero_byte_removed      = g_zero_byte_removed_count;
    result.previously_extracted   = g_previously_extracted_count;
    result.total_extracted        = g_total_extracted_count;

    /* ---- Phase 6: Post-processing (orphan classification + deleted type detection)
     *      Runs only when there is actual work to do; skipped entirely otherwise.  */
    bool nothing_to_extract = (g_work_count == 0 && g_cp_extract_stats.files_found > 0);
    if (!g_interrupted && !nothing_to_extract) {
        int orphan_dat_count = 0;
        {
            DIR *od = opendir(orphan_dir);
            if (od) {
                struct dirent *oe;
                while ((oe = readdir(od)) != NULL) {
                    size_t l = strlen(oe->d_name);
                    if (l > 4 && strcmp(oe->d_name + l - 4, ".dat") == 0)
                        orphan_dat_count++;
                }
                closedir(od);
            }
        }
        bool has_pp_work = (orphan_dat_count > 0 || del_rec > 0);

        if (has_pp_work) {
            LOG_PHASE(6, "Post-processing files");
            double orphan_start = util_get_time_ms();
            bool orphan_did_work = false;

            if (orphan_dat_count > 0)
                orphan_did_work = orphan_post_process(orphan_dir, output_dir, &result);

            /* Deleted fragment type detection: rename .raw → .<ext> via magic.
             * Idempotent — already-renamed files don't have .raw extension. */
            if (del_rec > 0) {
                DIR *dd = opendir(deleted_dir);
                if (dd) {
                    struct dirent *de;
                    while ((de = readdir(dd)) != NULL) {
                        if (de->d_name[0] == '.') continue;
                        char *dot = strrchr(de->d_name, '.');
                        if (!dot || strcasecmp(dot, ".raw") != 0) continue;
                        char fpath[MAX_PATH_LEN];
                        snprintf(fpath, sizeof(fpath), "%s/%s",
                                 deleted_dir, de->d_name);
                        FILE *fc = fopen(fpath, "rb");
                        if (!fc) continue;
                        uint8_t magic[512] = {0};
                        size_t  nr = fread(magic, 1, sizeof(magic), fc);
                        fclose(fc);
                        if (nr < 3) continue;
                        const char *type_ext = orphan_classify_content(magic, nr);
                        if (type_ext) {
                            char new_path[MAX_PATH_LEN];
                            size_t base_len = (size_t)(dot - de->d_name);
                            snprintf(new_path, sizeof(new_path), "%s/%.*s.%s",
                                     deleted_dir, (int)base_len, de->d_name, type_ext);
                            rename(fpath, new_path);
                        }
                    }
                    closedir(dd);
                }
            }

            result.orphan_time = (util_get_time_ms() - orphan_start) / 1000.0;
            char t[32];
            util_format_time(result.orphan_time, t);
            if (g_interrupted) {
                interrupted_phase = "Post-processing";
                if (g_term_color)
                    fprintf(stdout, "  %sPost-processing interrupted after %s%s\n",
                            T_BRED, t, T_RESET);
                else
                    fprintf(stdout, "  Post-processing interrupted after %s\n", t);
                LOG_EXEC_ONLY("Post-processing interrupted after %s", t);
                fflush(stdout);
            } else {
                LOG_OK("Post-processing completed in %s", t);
                if (orphan_did_work && result.orphan_fail_count > 0)
                    LOG_WARN("%d orphan file(s) could not be processed — "
                             "see error.log for details", result.orphan_fail_count);
            }
        }
    }

    /* ---- Finalise result stats ------------------------------------------- */
    result.total_time = (util_get_time_ms() - total_start) / 1000.0;

    int dirs = 0, files = 0;
    for (int i = 0; i < g_drec_count; i++) {
        if (g_drecs[i].is_dir) dirs++; else files++;
    }
    result.directories_found = dirs;
    /* files_found here is the raw (pre-dedup) drec file count used only for
     * the fallback path in print_summary_box when total_extracted == 0.
     * The normal path uses total_extracted + skipped_size_count instead. */
    result.files_found       = files;
    result.error_count   = g_error_count;
    /* Count warnings separately from the shared error buffer. */
    int warn_count = 0;
    for (int i = 0; i < g_error_count; i++)
        if (g_errors[i].severity == ERR_WARNING) warn_count++;
    result.warning_count = warn_count;

    uint64_t blocks = g_data_size > g_partition_offset
                    ? (g_data_size - g_partition_offset) / g_block_size : 0;
    result.blocks_scanned    = blocks;
    result.blocks_per_second = result.scan_time > 0
                             ? (double)blocks / result.scan_time : 0;

    /* ---- Landmark line (normal completion only) -------------------------- */
    if (!g_interrupted) {
        char t[32];
        util_format_time(result.total_time, t);
        printf("\n");
        if (g_term_color)
            printf("\n  %s%sExcavation completed in %s%s\n",
                   T_BOLD, T_BGREEN, t, T_RESET);
        else
            printf("\n  Excavation completed in %s\n", t);
        LOG_EXEC_ONLY("Excavation completed in %s", t);
        fflush(stdout);
    }

    /* ---- Console summary ------------------------------------------------- */
    print_summary_box(&result, extracted, g_interrupted);
    print_post_box_section(&result, output_dir);

    /* ---- Possibly-truncated terminal warning ------------------------------ */
    if (!g_interrupted) {
        int kept = 0;
        for (int i = 0; i < g_possibly_truncated_count; i++)
            if (!g_possibly_truncated[i].discarded) kept++;
        if (kept > 0) {
            const char *warn  = g_term_color ? T_BMAGENTA : "";
            const char *rst   = g_term_color ? T_RESET   : "";
            char nb[32];
            printf("  %s\xe2\x9a\xa0  %s file(s) may be truncated. "
                   "Expanded versions saved as _EXPANDED.%s\n",
                   warn, util_format_num((uint64_t)kept, nb), rst);
            printf("     See recovery_summary.md \xe2\x86\x92 "
                   "\"Possibly Truncated Files\".\n\n");
            fflush(stdout);
        }
    }

    /* ---- Post-box interrupted notice -------------------------------------- */
    if (g_interrupted && interrupted_phase) {
        char t[32];
        util_format_time(result.total_time, t);
        const char *resume_hint = g_re_extract
            ? "Run the same command (without --re-extract) to resume"
            : "Run the same command again to resume";
        if (g_term_color) {
            printf("  %sExcavation interrupted after %s%s\n",
                   T_BRED, t, T_RESET);
            printf("  %s %s.\n\n", resume_hint, interrupted_phase);
        } else {
            printf("  Excavation interrupted after %s\n", t);
            printf("  %s %s.\n\n", resume_hint, interrupted_phase);
        }
        LOG_EXEC_ONLY("Excavation interrupted after %s", t);
        fflush(stdout);
    }

    /* ---- Always-on reports ----------------------------------------------- */
    LOG_EXEC_ONLY("Writing reports...");
    if (resumed) write_file_list(output_dir); /* fresh scans write it before extraction */
    report_write_summary(output_dir, &result, image_path);
    report_write_unrecovered(output_dir);
    if (g_cp_extract_stats.files_skipped > 0)
        report_write_skipped_files(output_dir);
    report_write_error_log(output_dir);

    /* Persist possibly-truncated and collision data for future resumed runs
     * so recovery_summary.md is always a consolidated view.  Not saved when
     * interrupted — the prior run's file (if any) is left intact. */
    if (!g_interrupted)
        cp_save_pt_collisions();

    /* ---- Cleanup --------------------------------------------------------- */
cleanup:
    OPENSSL_cleanse(g_vek, sizeof(g_vek));
    log_shutdown();
    if (g_data) munmap(g_data, g_data_size);
    if (fd >= 0) close(fd);

    free(g_logs_dir);
    g_logs_dir = NULL;
    free(g_drecs);

    for (int i = 0; i < g_inode_count; i++) {
        free(g_inodes[i].decmpfs_data);
        free(g_inodes[i].extents);
    }
    free(g_inodes);
    free(g_deleted);

    if (g_paths) {
        for (uint32_t i = 0; i < g_max_inodes; i++) free(g_paths[i]);
        free(g_paths);
    }

    free(g_errors);
    free(g_inode_hash);
    free(g_unrecovered);
    free(g_possibly_truncated);
    free(g_collisions);

    for (int i = 0; i < g_filter_ext_count; i++) free(g_filter_exts[i]);
    free(g_filter_exts);

    return exit_code;
}
