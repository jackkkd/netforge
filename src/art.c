/* ASCII art is embedded: binaries work from any current directory. */
#include "netforge/art.h"
#include <stddef.h>
#include <string.h>

typedef struct {
    const char *const *lines;
    int width, height;
} NfAsciiLogo;
#include "art_data.h"

static void write_clipped(WINDOW *window, int row, int column, const char *text)
{
    int height, width;
    getmaxyx(window, height, width);
    if (row >= 0 && row < height && column >= 0 && column < width - 1)
        mvwaddnstr(window, row, column, text, width - column - 1);
}

static void logo_at(WINDOW *window, const NfAsciiLogo *logo, int row, int column)
{
    for (int i = 0; i < logo->height; ++i)
        write_clipped(window, row + i, column, logo->lines[i]);
}

int nf_art_header_height(int terminal_rows)
{
    return terminal_rows >= 46 ? 14 : terminal_rows >= 36 ? 10 : 5;
}

void nf_art_draw_header(WINDOW *window, int height, bool colors)
{
    const NfAsciiLogo *logo = height >= 14 ? &header_large :
                              height >= 10 ? &header_medium : &header_small;
    int title_column = logo->width + 5;
    int title_row = height >= 10 ? height / 2 - 2 : 0;
    if (colors) wattron(window, COLOR_PAIR(1));
    logo_at(window, logo, 0, 2);
    wattron(window, A_BOLD);
    write_clipped(window, title_row, title_column, "N E T F O R G E");
    wattroff(window, A_BOLD);
    write_clipped(window, title_row + 1, title_column, "C / LINUX NETWORK LABORATORY");
    if (colors) wattroff(window, COLOR_PAIR(1));
    write_clipped(window, title_row + 2, title_column, "TCP scanner | HTTP server | Packet simulation");
    write_clipped(window, title_row + 3, title_column, "v3.0 | Modular C11 | No root required");
}

bool nf_art_splash(volatile sig_atomic_t *interrupted, bool colors)
{
    const NfAsciiLogo *const choices[] = {
        &splash_large, &splash_medium, &splash_small, &splash_tiny, &header_small
    };
    while (!*interrupted) {
        int rows, columns;
        getmaxyx(stdscr, rows, columns);
        erase();
        const NfAsciiLogo *logo = NULL;
        for (size_t i = 0; i < sizeof choices / sizeof choices[0]; ++i) {
            if (choices[i]->width + 4 <= columns && choices[i]->height + 6 <= rows) {
                logo = choices[i];
                break;
            }
        }
        if (logo) {
            int top = (rows - logo->height - 5) / 2;
            if (colors) attron(COLOR_PAIR(1));
            logo_at(stdscr, logo, top, (columns - logo->width) / 2);
            attron(A_BOLD);
            const char *title = "N E T F O R G E";
            write_clipped(stdscr, top + logo->height + 1,
                          (columns - (int)strlen(title)) / 2, title);
            attroff(A_BOLD);
            if (colors) attroff(COLOR_PAIR(1));
            const char *subtitle = "C11 / LINUX / TCP / HTTP / PACKET LAB";
            write_clipped(stdscr, top + logo->height + 2,
                          columns > (int)strlen(subtitle) ? (columns - (int)strlen(subtitle)) / 2 : 0,
                          subtitle);
        } else {
            write_clipped(stdscr, 0, 0, "NETFORGE - enlarge the terminal to see the logo.");
        }
        const char *prompt = "Enter: open main menu | Q: quit";
        write_clipped(stdscr, rows - 1,
                      columns > (int)strlen(prompt) ? (columns - (int)strlen(prompt)) / 2 : 0,
                      prompt);
        refresh();
        int key = getch();
        if (key == 'q' || key == 'Q') return false;
        if (key == '\n' || key == '\r' || key == KEY_ENTER || key == ' ') return true;
    }
    return false;
}
