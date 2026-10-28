#include "netforge/job.h"
#include "netforge/log.h"
#include "netforge/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "netforge/ui.h"
#include "netforge/art.h"
#include "netforge/scanner.h"
#include "netforge/http_server.h"
#include "netforge/packet_parser.h"
#include <ncurses.h>
#include <signal.h>
#define MIN_ROWS 28
#define MIN_COLS 80
enum { HOME, SCAN, HTTP, PACKETS, HELP };
static NfJob scan_job, http_job, packet_job;
static NfLogEntry view_logs[NF_LOG_CAPACITY];
static size_t view_count, scroll_offset;
static bool logs_paused, colors, verbose_scan, editing;
static volatile sig_atomic_t interrupted;
static WINDOW *panel, *activity;
static int rows, cols, header_height, page = HOME, home_choice, field, previous_page = HOME;
static char notice[160] = "Welcome. Choose a tool below to begin.";
static char scan_fields[5][32] = {
    "127.0.0.1", "127.0.0.1", "8075", "8085", "250"
};
static char http_fields[2][32] = { "127.0.0.1", "8080" };
static char packet_fields[3][32] = { "500", "0", "8" };
static const char *scan_labels[] = {
    "First IPv4 address", "Last IPv4 address", "First TCP port",
    "Last TCP port", "Timeout per port (ms)"
};
static const char *http_labels[] = { "Listen IPv4 address", "Listen TCP port" };
static const char *packet_labels[] = {
    "Interval (ms)", "Packet limit (0=continuous)", "Malformed every N (0=off)"
};

static void set_notice(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    (void)vsnprintf(notice, sizeof notice, format, args);
    va_end(args);
}

static NfJob *selected_job(void)
{ return page == SCAN ? &scan_job : page == HTTP ? &http_job : page == PACKETS ? &packet_job : NULL; }

static bool settings_error(const char *message)
{
    set_notice("%s Press E to edit settings.", message);
    nf_log_emit(NF_WARNING, "INPUT", "%s", message);
    return false;
}


static void start_selected(void)
{
    NfJob *job = selected_job();
    if (!job) return;
    if (job->live) { nf_job_stop(job); set_notice("Stopping %s...", job->name); return; }
    char error[160]; bool okay;
    if (page == SCAN) {
        NfScanSettings settings;
        okay = nf_scanner_parse_settings(scan_fields[0], scan_fields[1], scan_fields[2],
            scan_fields[3], scan_fields[4], verbose_scan, &settings, error, sizeof error);
        if (!okay) { settings_error(error); return; }
        okay = nf_scanner_start(job, &settings);
    } else if (page == HTTP) {
        NfHttpSettings settings;
        okay = nf_http_parse_settings(http_fields[0], http_fields[1], &settings, error, sizeof error);
        if (!okay) { settings_error(error); return; }
        okay = nf_http_start(job, &settings);
    } else {
        NfPacketSettings settings;
        okay = nf_packets_parse_settings(packet_fields[0], packet_fields[1], packet_fields[2],
            &settings, error, sizeof error);
        if (!okay) { settings_error(error); return; }
        okay = nf_packets_start(job, &settings);
    }
    set_notice(okay ? "%s started. Watch the activity log below." :
               "%s could not start. See the activity log.", job->name);
}
static char (*current_fields(int *count))[32]
{
    if (page == SCAN) { *count = 5; return scan_fields; }
    if (page == HTTP) { *count = 2; return http_fields; }
    *count = 3; return packet_fields;
}

static void edit_key(int key)
{
    int count;
    char (*fields)[32] = current_fields(&count);
    char *text = fields[field];
    size_t length = strlen(text);
    if (key == 27) { editing = false; set_notice("Settings kept. Press Enter to start."); }
    else if (key == '\t' || key == '\n' || key == '\r' || key == KEY_ENTER) {
        if (++field == count) {
            field = 0; editing = false;
            set_notice("Settings kept. Press Enter to validate and start.");
        }
    } else if (key == KEY_BTAB) field = (field + count - 1) % count;
    else if (key == 21) text[0] = '\0';
    else if (key == KEY_BACKSPACE || key == 127 || key == '\b') {
        if (length) text[length - 1U] = '\0';
    } else {
        bool ip_field = (page == SCAN && field < 2) || (page == HTTP && field == 0);
        if (((key >= '0' && key <= '9') || (ip_field && key == '.')) && length < 31) {
            text[length] = (char)key; text[length + 1U] = '\0';
        }
    }
}

static void save_log(void)
{
    NfLogEntry copy[NF_LOG_CAPACITY];
    size_t count = nf_log_snapshot(copy, NF_LOG_CAPACITY);
    char filename[96], stamp[32];
    struct tm local;
    time_t now = time(NULL);
    if (now == (time_t)-1 || !localtime_r(&now, &local) ||
        !strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &local)) {
        set_notice("Could not create a timestamp for the log file."); return;
    }
    (void)snprintf(filename, sizeof filename, "netforge-%s.log", stamp);
    FILE *file = fopen(filename, "wx"); /* Never overwrite an existing file. */
    if (!file) { set_notice("Could not save log: %s", strerror(errno)); return; }
    bool okay = true;
    for (size_t i = 0; i < count; ++i)
        if (fprintf(file, "%s\n", copy[i].text) < 0) okay = false;
    if (fclose(file)) okay = false;
    if (okay) {
        set_notice("Saved %zu recent entries to %s", count, filename);
        nf_log_emit(NF_SUCCESS, "LOG", "Saved %zu recent entries to %s", count, filename);
    } else set_notice("Log write failed; the output file may be incomplete.");
}

/* ---------------------------- Ncurses display --------------------------- */
static void free_windows(void)
{
    if (panel) { delwin(panel); panel = NULL; }
    if (activity) { delwin(activity); activity = NULL; }
}

static bool layout(void)
{
    free_windows();
    getmaxyx(stdscr, rows, cols);
    if (rows < MIN_ROWS || cols < MIN_COLS) return true;
    header_height = nf_art_header_height(rows);
    panel = newwin(12, cols, header_height + 2, 0);
    activity = newwin(rows - header_height - 16, cols, header_height + 14, 0);
    if (!panel || !activity) { free_windows(); return false; }
    return true;
}

static void line(WINDOW *window, int row, const char *format, ...)
{
    char text[256];
    va_list args;
    va_start(args, format);
    (void)vsnprintf(text, sizeof text, format, args);
    va_end(args);
    mvwaddnstr(window, row, 2, text, getmaxx(window) - 4);
}

static void draw_fields(const char *const *labels, char (*fields)[32], int count)
{
    for (int i = 0; i < count; ++i) {
        if (editing && field == i) wattron(panel, A_REVERSE);
        line(panel, i + 2, "%-27s [%s%s]", labels[i], fields[i],
             editing && field == i ? "_" : "");
        if (editing && field == i) wattroff(panel, A_REVERSE);
    }
}

static void refresh_log_view(void)
{
    if (logs_paused) return;
    view_count = nf_log_snapshot(view_logs, NF_LOG_CAPACITY);
    scroll_offset = 0;
}

static void draw(void)
{
    static const char *titles[] = { "MAIN MENU", "TCP PORT SCANNER", "HTTP WEB SERVER",
                                  "PACKET HEADER SIMULATION", "HELP / QUICK START" };
    erase();
    if (rows < MIN_ROWS || cols < MIN_COLS) {
        if (rows > 0 && cols > 1)
            mvaddnstr(0, 0, "Please resize to 80x28 or larger. Q quits.", cols - 1);
        refresh(); return;
    }
    nf_art_draw_header(stdscr, header_height, colors);
    mvprintw(header_height, 2, "Main menu%s%s", page == HOME ? "" : " > ", page == HOME ? "" : titles[page]);
    mvaddnstr(header_height + 1, 2, notice, cols - 4);
    char bottom[160];
    (void)snprintf(bottom, sizeof bottom, "Scanner: %s | HTTP: %s | Packets: %s | Log: %s",
         nf_job_status(&scan_job), nf_job_status(&http_job), nf_job_status(&packet_job), logs_paused ? "PAUSED" : "LIVE");
    mvaddnstr(rows - 2, 1, bottom, cols - 2);
    mvaddnstr(rows - 1, 1, editing ?
        "EDIT: Ctrl-U clear | Backspace delete | Tab/Enter next | Esc done" :
        "B menu | H help | P pause log | PgUp/PgDn scroll | W save | C clear | Q quit", cols - 2);
    wnoutrefresh(stdscr);
    werase(panel); box(panel, 0, 0);
    mvwprintw(panel, 0, 2, " %s ", titles[page]);
    if (page == HOME) {
        static const char *names[] = { "TCP port scanner", "HTTP web server",
                                       "Packet header simulation", "Help and quick start" };
        static const char *descriptions[] = {
            "Find TCP ports accepting connections in an IPv4 range.",
            "Serve a webpage and see which clients connect.",
            "Decode IPv4/TCP/UDP headers from generated examples.",
            "Learn the controls and run a localhost demonstration."
        };
        line(panel, 1, "Choose a tool. Review its settings, then press Enter to start it.");
        for (int i = 0; i < 4; ++i) {
            if (home_choice == i) wattron(panel, A_REVERSE);
            line(panel, 2 + i * 2, "%s [%d] %s", home_choice == i ? ">" : " ", i + 1, names[i]);
            if (home_choice == i) wattroff(panel, A_REVERSE);
            line(panel, 3 + i * 2, "      %s", descriptions[i]);
        }
        line(panel, 10, "Up/Down: choose | Enter: open | 1-4: open directly | Q: exit");
    } else if (page == SCAN) {
        NfMetrics metrics = nf_job_snapshot(&scan_job);
        line(panel, 1, "TCP connect scan | Only scan systems you are authorized to test.");
        draw_fields(scan_labels, scan_fields, 5);
        unsigned percent = metrics.total ? (unsigned)((uint64_t)metrics.checked * 100U / metrics.total) : 0;
        char bar[21];
        for (int i = 0; i < 20; ++i) bar[i] = i < (int)(percent / 5U) ? '#' : '-';
        bar[20] = '\0';
        line(panel, 7, "[%s] %3u%% | Checked: %u/%u", bar, percent, metrics.checked, metrics.total);
        line(panel, 8, "Open: %u | Closed/refused: %u | Uncertain: %u", metrics.good, metrics.bad, metrics.other);
        line(panel, 9, "Result detail: %s | No reply is inconclusive.", verbose_scan ? "ALL PORTS" : "OPEN PORTS + SUMMARY");
        line(panel, 10, "Enter/Space: %s | E: edit | V: detail | B: menu", scan_job.live ? "stop scan" : "start scan");
    } else if (page == HTTP) {
        NfMetrics metrics = nf_job_snapshot(&http_job);
        line(panel, 1, "Serve a static webpage. State: %s", nf_job_status(&http_job));
        draw_fields(http_labels, http_fields, 2);
        line(panel, 4, "127.0.0.1 = Kali only; 0.0.0.0 = all IPv4 interfaces.");
        line(panel, 5, "Clients: %u | Completed 200 responses: %u | Other/incomplete: %u",
             metrics.checked, metrics.good, metrics.bad);
        line(panel, 6, "Page: ./index.html if present; otherwise the built-in page.");
        line(panel, 7, "Inside Kali: curl -i http://%s:%s/",
             !strcmp(http_fields[0], "0.0.0.0") ? "127.0.0.1" : http_fields[0], http_fields[1]);
        line(panel, 8, "From the VM host: use Kali's IPv4 address and a reachable VM network.");
        line(panel, 9, "GET/HEAD supported. Stop and restart to reload index.html.");
        line(panel, 10, "Enter/Space: %s | E: edit | B: menu", http_job.live ? "stop server" : "start server");
    } else if (page == PACKETS) {
        NfMetrics metrics = nf_job_snapshot(&packet_job);
        line(panel, 1, "SIMULATED packets: no live capture, no transmitted traffic.");
        draw_fields(packet_labels, packet_fields, 3);
        line(panel, 5, "Samples: %u | Decoded: %u | Rejected: %u", metrics.checked, metrics.good, metrics.bad);
        line(panel, 6, "Shows protocol, source/destination IPv4 addresses, and ports.");
        line(panel, 7, "Checks lengths and IPv4 checksums; rejects fragments.");
        line(panel, 8, "Transport checksums and fragment reassembly are not implemented.");
        line(panel, 9, "Malformed examples are intentional learning samples.");
        line(panel, 10, "Enter/Space: %s | E: edit | B: menu", packet_job.live ? "stop simulation" : "start simulation");
    } else {
        line(panel, 1, "QUICK DEMONSTRATION");
        line(panel, 2, "1. Main menu > HTTP server > Enter to start the server.");
        line(panel, 3, "2. Open http://127.0.0.1:8080 in Firefox inside Kali.");
        line(panel, 4, "3. B > TCP scanner > Enter: default range includes port 8080.");
        line(panel, 5, "4. B > Packet simulation > Enter: inspect decoded headers.");
        line(panel, 6, "E edits settings. Ctrl-U clears a field. Tab moves forward.");
        line(panel, 7, "Returning to the menu keeps running tools active.");
        line(panel, 8, "W saves the latest 512 log entries in the current directory.");
        line(panel, 9, "P pauses/resumes the log. Q stops all workers and exits.");
        line(panel, 10, "B/Esc: main menu | H: return to the previous screen");
    }
    wnoutrefresh(panel);
    refresh_log_view();
    werase(activity); box(activity, 0, 0);
    mvwprintw(activity, 0, 2, " RECENT ACTIVITY [%s] ", logs_paused ? "PAUSED" : "LIVE");
    size_t visible = (size_t)(getmaxy(activity) - 2);
    size_t width = (size_t)(cols - 4), visual_rows = 0;
    for (size_t i = 0; i < view_count; ++i)
        visual_rows += (strlen(view_logs[i].text) + width - 1U) / width;
    size_t max_offset = visual_rows > visible ? visual_rows - visible : 0;
    if (scroll_offset > max_offset) scroll_offset = max_offset;
    size_t end = visual_rows - scroll_offset;
    size_t start = end > visible ? end - visible : 0;
    size_t visual_row = 0;
    for (size_t i = 0; i < view_count && visual_row < end; ++i) {
        int color = view_logs[i].level == NF_SUCCESS ? 2 : view_logs[i].level == NF_WARNING ? 3 :
                    view_logs[i].level == NF_FAILURE ? 4 : 1;
        if (colors) wattron(activity, COLOR_PAIR(color));
        size_t length = strlen(view_logs[i].text);
        for (size_t offset = 0; offset < length && visual_row < end; offset += width, ++visual_row) {
            if (visual_row >= start)
                mvwaddnstr(activity, (int)(visual_row - start) + 1, 2,
                          view_logs[i].text + offset, (int)width);
        }
        if (colors) wattroff(activity, COLOR_PAIR(color));
    }
    wnoutrefresh(activity);
    doupdate();
}

static void key_action(int key, bool *quit)
{
    if (editing) { edit_key(key); return; }
    if (key == 'q' || key == 'Q') { *quit = true; return; }
    if (key == 'b' || key == 'B' || key == 27) {
        page = HOME; set_notice("Choose a tool. Running workers remain active."); return;
    }
    if (key == 'h' || key == 'H') {
        if (page == HELP) page = previous_page;
        else { previous_page = page; page = HELP; }
        return;
    }
    if (key == 'w' || key == 'W') { save_log(); return; }
    if (key == 'c' || key == 'C') {
        nf_log_clear();
        view_count = scroll_offset = 0; logs_paused = false;
        set_notice("Activity history cleared. Running tools continue logging."); return;
    }
    if (key == 'p' || key == 'P') { logs_paused = !logs_paused; scroll_offset = 0; return; }
    if (key == KEY_PPAGE || key == KEY_NPAGE) {
        logs_paused = true;
        size_t step = (size_t)(getmaxy(activity) - 2);
        if (key == KEY_PPAGE) scroll_offset += step;
        else if (scroll_offset > step) scroll_offset -= step;
        else { scroll_offset = 0; logs_paused = false; }
        return;
    }
    if (page == HOME) {
        if (key == KEY_UP) home_choice = (home_choice + 3) % 4;
        else if (key == KEY_DOWN) home_choice = (home_choice + 1) % 4;
        else if (key >= '1' && key <= '4') {
            home_choice = key - '1'; page = home_choice + 1;
            if (page == HELP) previous_page = HOME;
            set_notice(page == HELP ? "Follow the quick-start steps below." :
                       "Review settings. Enter starts the tool; E edits settings.");
        } else if (key == '\n' || key == '\r' || key == KEY_ENTER || key == ' ') {
            page = home_choice + 1;
            if (page == HELP) previous_page = HOME;
            set_notice(page == HELP ? "Follow the quick-start steps below." :
                       "Review settings. Enter starts the tool; E edits settings.");
        }
        return;
    }
    NfJob *job = selected_job();
    if (!job) return;
    if (key == '\n' || key == '\r' || key == KEY_ENTER || key == ' ') start_selected();
    else if (key == 'e' || key == 'E') {
        if (job->live) set_notice("Stop this tool with Enter before editing its settings.");
        else { editing = true; field = 0; set_notice("Ctrl-U clears a field. Tab advances. Esc keeps edits and leaves editing."); }
    } else if (page == SCAN && (key == 'v' || key == 'V')) {
        if (job->live) set_notice("Stop the scan before changing result detail.");
        else { verbose_scan = !verbose_scan; set_notice("Result detail changed for the next scan."); }
    }
}

static void signal_handler(int signal_number)
{ (void)signal_number; interrupted = 1; }

int nf_ui_run(bool skip_splash)
{
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        fprintf(stderr, "Please run NETFORGE inside an interactive terminal.\n");
        return EXIT_FAILURE;
    }
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) == -1 || sigaction(SIGTERM, &action, NULL) == -1) {
        perror("Cannot install signal handlers"); return EXIT_FAILURE;
    }
    NfJob *jobs[] = { &scan_job, &http_job, &packet_job };
    const char *names[] = { "SCAN", "HTTP", "SIM" };
    for (size_t i = 0; i < 3; ++i) {
        if (!nf_job_init(jobs[i], names[i])) {
            fprintf(stderr, "Cannot initialize the %s worker.\n", names[i]);
            while (i) nf_job_destroy(jobs[--i]);
            return EXIT_FAILURE;
        }
    }
    SCREEN *screen = newterm(NULL, stdout, stdin);
    if (!screen) {
        fprintf(stderr, "Cannot start ncurses. Check TERM and your terminal configuration.\n");
        for (size_t i = 0; i < 3; ++i) nf_job_destroy(jobs[i]);
        return EXIT_FAILURE;
    }
    set_term(screen);
    if (cbreak() == ERR || noecho() == ERR || keypad(stdscr, TRUE) == ERR) {
        endwin(); delscreen(screen);
        for (size_t i = 0; i < 3; ++i) nf_job_destroy(jobs[i]);
        fprintf(stderr, "Cannot configure terminal input.\n"); return EXIT_FAILURE;
    }
    (void)curs_set(0); timeout(100);
    if (has_colors() && start_color() != ERR) {
        short background = use_default_colors() == ERR ? COLOR_BLACK : -1;
        colors = init_pair(1, COLOR_CYAN, background) != ERR &&
                 init_pair(2, COLOR_GREEN, background) != ERR &&
                 init_pair(3, COLOR_YELLOW, background) != ERR &&
                 init_pair(4, COLOR_RED, background) != ERR;
    }
    bool quit = !skip_splash && !nf_art_splash(&interrupted, colors);
    bool window_error = !layout();
    int result = window_error ? EXIT_FAILURE : EXIT_SUCCESS;
    nf_log_emit(NF_INFO, "SYSTEM", "Welcome to NETFORGE. Choose a tool; nothing starts automatically.");
    nf_log_emit(NF_INFO, "SYSTEM", "For a guided demonstration, open Help from the main menu.");
    while (!quit && !interrupted && !window_error) {
        for (size_t i = 0; i < 3; ++i) if (!nf_job_reap(jobs[i])) interrupted = 1;
        int current_rows, current_cols;
        getmaxyx(stdscr, current_rows, current_cols);
        if (current_rows != rows || current_cols != cols) {
            if (!layout()) { window_error = true; result = EXIT_FAILURE; break; }
        }
        draw();
        int key = getch();
        if (key == ERR || key == KEY_RESIZE) continue;
        if (rows < MIN_ROWS || cols < MIN_COLS) {
            if (key == 'q' || key == 'Q') quit = true;
        } else key_action(key, &quit);
    }
    for (size_t i = 0; i < 3; ++i) atomic_store(&jobs[i]->stop, true);
    if (!window_error && rows >= MIN_ROWS && cols >= MIN_COLS) {
        editing = false;
        set_notice("Shutting down: stopping workers and closing sockets...");
        draw();
    }
    for (size_t i = 0; i < 3; ++i)
        if (!nf_job_join(jobs[i])) result = EXIT_FAILURE;
    free_windows(); endwin(); delscreen(screen);
    if (window_error) fprintf(stderr, "Not enough memory to create terminal windows.\n");
    for (size_t i = 0; i < 3; ++i)
        if (!jobs[i]->live && !nf_job_destroy(jobs[i])) result = EXIT_FAILURE;
    if (result == EXIT_SUCCESS) puts("NETFORGE closed. All networking workers have stopped.");
    else fprintf(stderr, "NETFORGE exited with an initialization or cleanup error.\n");
    return result;
}
