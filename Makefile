# apfs-excavate — Makefile
#
# Targets:
#   make          — optimised release build  (-O3)
#   make debug    — debug build with ASan/UBSan (-O0 -g)
#   make check    — build + run unit tests
#   make install  — install to $(PREFIX)/bin  (default /usr/local)
#   make clean    — remove build artefacts

CC      ?= cc
PREFIX  ?= /usr/local
BUILDDIR       = build
BUILDDIR_DEBUG = build/debug

# ----------------------------------------------------------------------------
# Source files
# ----------------------------------------------------------------------------

SRCS = src/globals.c   \
       src/term.c      \
       src/log.c       \
       src/errors.c    \
       src/util.c      \
       src/crypto.c    \
       src/block_io.c  \
       src/compress.c  \
       src/checkpoint.c \
       src/apfs_parse.c \
       src/scan.c      \
       src/recovery.c  \
       src/orphan_post.c \
       src/report.c    \
       src/main.c

OBJS       = $(SRCS:src/%.c=$(BUILDDIR)/%.o)
OBJS_DEBUG = $(SRCS:src/%.c=$(BUILDDIR_DEBUG)/%.o)

TEST_SRCS = tests/test_lzvn.c tests/test_aes_xts.c tests/test_orphan_type.c tests/test_checkpoint.c
TEST_BINS = $(TEST_SRCS:tests/%.c=$(BUILDDIR)/%)

# Shared objects for tests (everything except main.o)
TEST_OBJS = $(filter-out $(BUILDDIR)/main.o, $(OBJS))

# Dependency files for automatic header tracking (-MMD -MP)
DEPS       = $(OBJS:.o=.d)
DEPS_DEBUG = $(OBJS_DEBUG:.o=.d)

# ----------------------------------------------------------------------------
# Compiler flags
# ----------------------------------------------------------------------------

CFLAGS_COMMON = -std=c11 -Wall -Wextra -Wpedantic -I include

CFLAGS_RELEASE = $(CFLAGS_COMMON) -O3
CFLAGS_DEBUG   = $(CFLAGS_COMMON) -O0 -g -DDEBUG -fsanitize=address,undefined
LDFLAGS_DEBUG  = -fsanitize=address,undefined

# CFLAGS from the environment is appended as extra user flags.
# Do not use CFLAGS ?= for our required flags — environment CFLAGS would
# silently override them.
LDFLAGS ?=

# ----------------------------------------------------------------------------
# Platform-specific crypto / compression libraries
# ----------------------------------------------------------------------------

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    # Try pkg-config first (works with both Homebrew and MacPorts).
    OPENSSL_CFLAGS  := $(shell pkg-config --cflags openssl 2>/dev/null)
    OPENSSL_LDFLAGS := $(shell pkg-config --libs   openssl 2>/dev/null)

    # Fall back to brew --prefix if pkg-config didn't find it.
    ifeq ($(OPENSSL_LDFLAGS),)
        OPENSSL_PREFIX  := $(shell brew --prefix openssl 2>/dev/null)
        ifneq ($(OPENSSL_PREFIX),)
            OPENSSL_CFLAGS  = -I$(OPENSSL_PREFIX)/include
            OPENSSL_LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lcrypto
        else
            OPENSSL_LDFLAGS = -lcrypto
        endif
    endif

    PLATFORM_CFLAGS  = $(OPENSSL_CFLAGS)
    PLATFORM_LDFLAGS = $(OPENSSL_LDFLAGS) -lz -lcompression
else
    # Linux — use pkg-config or fall back to bare -lcrypto
    OPENSSL_CFLAGS  := $(shell pkg-config --cflags openssl 2>/dev/null)
    OPENSSL_LDFLAGS := $(shell pkg-config --libs   openssl 2>/dev/null)
    ifeq ($(OPENSSL_LDFLAGS),)
        OPENSSL_LDFLAGS = -lcrypto
    endif
    # -lcompression is Apple-only; LZFSE is stubbed out on Linux.
    # -pthread is needed at both compile and link time on Linux.
    PLATFORM_CFLAGS  = $(OPENSSL_CFLAGS) -pthread
    PLATFORM_LDFLAGS = $(OPENSSL_LDFLAGS) -lz -lpthread
endif

# ----------------------------------------------------------------------------
# Rules
# ----------------------------------------------------------------------------

.PHONY: all debug check install clean

all: $(BUILDDIR)/apfs-excavate

debug: $(BUILDDIR_DEBUG)/apfs-excavate

# Release binary
$(BUILDDIR)/apfs-excavate: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(PLATFORM_LDFLAGS)

# Debug binary (separate directory — never reuses release .o files)
$(BUILDDIR_DEBUG)/apfs-excavate: $(OBJS_DEBUG)
	$(CC) $(LDFLAGS_DEBUG) -o $@ $^ $(PLATFORM_LDFLAGS)

# Release objects (-MMD -MP generates .d files for header dependency tracking)
$(BUILDDIR)/%.o: src/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS_RELEASE) $(CFLAGS) $(PLATFORM_CFLAGS) -MMD -MP -c -o $@ $<

# Debug objects (separate directory, ASan/UBSan flags)
$(BUILDDIR_DEBUG)/%.o: src/%.c | $(BUILDDIR_DEBUG)
	$(CC) $(CFLAGS_DEBUG) $(CFLAGS) $(PLATFORM_CFLAGS) -MMD -MP -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR_DEBUG):
	mkdir -p $(BUILDDIR_DEBUG)

# Automatic header dependency inclusion (leading - silences missing-file errors)
-include $(DEPS)
-include $(DEPS_DEBUG)

# ----------------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------------

check: $(TEST_BINS)
	@echo "Running unit tests..."
	@for t in $(TEST_BINS); do \
	    echo "  $$t"; \
	    $$t || exit 1; \
	done
	@echo "All tests passed."

$(BUILDDIR)/test_%: tests/test_%.c $(TEST_OBJS) | $(BUILDDIR)
	$(CC) $(CFLAGS_RELEASE) $(CFLAGS) $(PLATFORM_CFLAGS) -o $@ $< $(TEST_OBJS) $(LDFLAGS) $(PLATFORM_LDFLAGS)

# ----------------------------------------------------------------------------
# Install / clean
# ----------------------------------------------------------------------------

install: $(BUILDDIR)/apfs-excavate
	install -d "$(PREFIX)/bin"
	install -m 755 $(BUILDDIR)/apfs-excavate "$(PREFIX)/bin/apfs-excavate"

clean:
	rm -rf $(BUILDDIR)
