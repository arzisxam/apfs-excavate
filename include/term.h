#pragma once
/*
 * term.h — terminal capability detection and ANSI color helpers.
 *
 * Call term_init() once at the very start of main() before any output.
 * g_term_color is false when stdout is not a tty, NO_COLOR is set, or TERM=dumb.
 * g_term_width is the detected terminal column count (default 80).
 */

#include <stdbool.h>

void        term_init(void);
extern bool g_term_color;      /* stdout is a color-capable terminal */
extern bool g_term_color_err;  /* stderr is a color-capable terminal (#26) */
extern int  g_term_width;

/* ---- SGR codes (standard 16-color — work everywhere) ---- */
#define T_RESET    "\033[0m"
#define T_BOLD     "\033[1m"
#define T_DIM      "\033[2m"
#define T_GREEN    "\033[32m"
#define T_YELLOW   "\033[33m"
#define T_CYAN     "\033[36m"
#define T_MAGENTA  "\033[35m"
#define T_BRED     "\033[1;31m"
#define T_BGREEN   "\033[1;32m"
#define T_BYELLOW  "\033[1;33m"
#define T_BCYAN    "\033[1;36m"
#define T_BMAGENTA "\033[1;35m"

/* ---- Unicode icons (UTF-8) ---- */
#define ICON_OK    "  \xe2\x9c\x93 "   /* ✓  */
#define ICON_WARN  "  \xe2\x9a\xa0 "   /* ⚠  */
#define ICON_ERR   "  \xe2\x9c\x97 "   /* ✗  */
#define ICON_INFO  "  \xc2\xb7 "       /* ·  */
#define PHASE_MARK "\xe2\x96\xb6 "     /* ▶  */

/* ---- Box-drawing chars (UTF-8, each 3 bytes / 1 display col) ---- */
#define BOX_TL  "\xe2\x95\x94"   /* ╔ */
#define BOX_TR  "\xe2\x95\x97"   /* ╗ */
#define BOX_BL  "\xe2\x95\x9a"   /* ╚ */
#define BOX_BR  "\xe2\x95\x9d"   /* ╝ */
#define BOX_H   "\xe2\x95\x90"   /* ═ */
#define BOX_V   "\xe2\x95\x91"   /* ║ */
