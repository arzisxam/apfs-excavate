/*
 * term.c — terminal capability detection.
 *
 * term_init() is called once at the start of main().  It sets g_term_color and
 * g_term_width from the environment and the kernel's window-size ioctl.
 *
 * Color is suppressed when:
 *   • stdout is not a tty (piped output)
 *   • NO_COLOR env var is set (https://no-color.org/)
 *   • TERM=dumb
 */

#define _GNU_SOURCE
#include "term.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

bool g_term_color     = false;
bool g_term_color_err = false;
int  g_term_width     = 80;

void term_init(void) {
    /* stderr color: independent of stdout (#26) */
    const char *no_color = getenv("NO_COLOR");
    const char *term     = getenv("TERM");
    bool env_ok = (no_color == NULL) && !(term && strcmp(term, "dumb") == 0);
    if (isatty(STDERR_FILENO) && env_ok)
        g_term_color_err = true;

    if (!isatty(STDOUT_FILENO)) return;
    if (!env_ok) return;

    g_term_color = true;

    /* Get terminal column count */
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col >= 40)
        g_term_width = (int)ws.ws_col;
}
