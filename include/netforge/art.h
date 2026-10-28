#ifndef NETFORGE_ART_H
#define NETFORGE_ART_H
#include <ncurses.h>
#include <stdbool.h>
#include <signal.h>
int nf_art_header_height(int terminal_rows);
void nf_art_draw_header(WINDOW *window, int height, bool colors);
/* Returns true to open the menu, false for Q or a shutdown signal. */
bool nf_art_splash(volatile sig_atomic_t *interrupted, bool colors);
#endif
