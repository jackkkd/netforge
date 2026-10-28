#include "netforge/job.h"
#include "netforge/log.h"
#include "netforge/util.h"
#include "netforge/text.h"
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
static WINDOW *header, *panel, *activity;
static bool expanded;
static int body_width, body_left, panel_height, layout_page;
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
    "Delay per packet (ms)", "Packets (0 = continuous)", "Invalid every N (0 = off)"
};


static const char *const scan_hints[] = {
    "The first device address to check; 127.0.0.1 is this VM.",
    "The last device address; use the same IP for one device.",
    "Start of the TCP port range (1-65535).",
    "End of the TCP port range; both endpoints are included.",
    "Maximum wait for each connection (50-3000 ms)."
};
static const char *const http_hints[] = {
    "127.0.0.1 = this VM; 0.0.0.0 = all IPv4 interfaces.",
    "Use 8080 for the demo; allowed range is 1024-65535."
};
static const char *const packet_hints[] = {
    "Time between generated examples (100-5000 ms).",
    "How many examples to generate; 0 runs until stopped.",
    "Every Nth example is invalid on purpose; 0 disables this."
};
static const char *const *field_hints(void)
{
    return page == SCAN ? scan_hints : page == HTTP ? http_hints : packet_hints;
}

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
        if (editing) set_notice("%s", field_hints()[field]);
    } else if (key == KEY_BTAB) {
        field = (field + count - 1) % count;
        set_notice("%s", field_hints()[field]);
    }
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
    if (header) { delwin(header); header = NULL; }
    if (panel) { delwin(panel); panel = NULL; }
    if (activity) { delwin(activity); activity = NULL; }
}

static bool layout(void)
{
    free_windows();
    getmaxyx(stdscr, rows, cols);
    if (rows < MIN_ROWS || cols < MIN_COLS) return true;
    header_height = nf_art_header_height(rows);
    body_width = cols > 128 ? 128 : cols;
    body_left = (cols - body_width) / 2;
    expanded = rows >= 42;
    panel_height = expanded ? (page == SCAN ? 20 : 18) : 12;
    layout_page = page;
    int activity_top = header_height + 2 + panel_height;
    header = newwin(header_height, body_width, 0, body_left);
    panel = newwin(panel_height, body_width, header_height + 2, body_left);
    activity = newwin(rows - activity_top - 2, body_width, activity_top, body_left);
    if (!header || !panel || !activity) { free_windows(); return false; }
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

static void section(int row, const char *title)
{
    wattron(panel, A_BOLD);
    line(panel, row, "%s", title);
    wattroff(panel, A_BOLD);
}

static void draw_fields(const char *const *labels, char (*fields)[32], int count)
{
    const char *const *hints = field_hints();
    bool side_help = expanded && body_width >= 112;
    if (side_help) mvwaddstr(panel, 3, 64, "FIELD HELP");
    for (int i = 0; i < count; ++i) {
        int row = expanded ? 4 + i * 2 : i + 2;
        int room = (side_help ? 59 : body_width - 4) - 32;
        size_t length = strlen(fields[i]);
        const char *value = length > (size_t)room ? fields[i] + length - (size_t)room : fields[i];
        if (editing && field == i) wattron(panel, A_REVERSE);
        line(panel, row, "%-27s [%s%s]", labels[i], value, editing && field == i ? "_" : "");
        if (editing && field == i) wattroff(panel, A_REVERSE);
        if (side_help) {
            wattron(panel, A_DIM);
            mvwaddnstr(panel, row, 64, hints[i], body_width - 66);
            wattroff(panel, A_DIM);
        }
    }
}

static int activity_first_row(void)
{
    return getmaxy(activity) >= 11 ? 4 : 2;
}

static const char *activity_key(void)
{
    if (page == PACKETS)
        return "Source = sender | Destination = receiver | IP bytes = IPv4 packet size";
    if (page == SCAN)
        return "OPEN = accepted | CLOSED = refused | UNCERTAIN = no clear answer";
    if (page == HTTP)
        return "Client = connecting device | 200 = page sent | 404 = page not found";
    return "Time | Tool | Level: INFO / OK / WARN / ERROR | Event details";
}

typedef struct {
    size_t current, start, end;
    int first_row;
    bool continuation;
} LogPaint;

static void paint_log_line(const char *text, size_t length, void *context)
{
    LogPaint *paint = context;
    if (paint->current >= paint->start && paint->current < paint->end) {
        int row = paint->first_row + (int)(paint->current - paint->start);
        mvwaddnstr(activity, row, paint->continuation ? 4 : 2, text, (int)length);
    }
    ++paint->current;
    paint->continuation = true;
}

static void refresh_log_view(void);

static void draw_activity(void)
{
    refresh_log_view();
    werase(activity); box(activity, 0, 0);
    mvwprintw(activity, 0, 2, " RECENT ACTIVITY - ALL TOOLS [%s] ", logs_paused ? "PAUSED" : "LIVE");
    int first_row = activity_first_row();
    wattron(activity, A_DIM);
    if (first_row == 4) {
        line(activity, 1, "Time | Tool | Level: INFO / OK / WARN / ERROR | Event details");
        line(activity, 2, "%s", activity_key());
    } else line(activity, 1, "%s", activity_key());
    wattroff(activity, A_DIM);
    size_t visible = (size_t)(getmaxy(activity) - first_row - 1);
    size_t width = (size_t)(body_width - 6), visual_rows = 0;
    bool spacing = getmaxy(activity) >= 12;
    for (size_t i = 0; i < view_count; ++i) {
        visual_rows += nf_text_wrap(view_logs[i].text, width, NULL, NULL);
        if (spacing && i + 1 < view_count) ++visual_rows;
    }
    size_t max_offset = visual_rows > visible ? visual_rows - visible : 0;
    if (scroll_offset > max_offset) scroll_offset = max_offset;
    size_t end = visual_rows - scroll_offset;
    LogPaint paint = { .start = end > visible ? end - visible : 0,
                       .end = end, .first_row = first_row };
    for (size_t i = 0; i < view_count && paint.current < end; ++i) {
        int color = view_logs[i].level == NF_SUCCESS ? 2 : view_logs[i].level == NF_WARNING ? 3 :
                    view_logs[i].level == NF_FAILURE ? 4 : 1;
        if (colors) wattron(activity, COLOR_PAIR(color));
        paint.continuation = false;
        nf_text_wrap(view_logs[i].text, width, paint_log_line, &paint);
        if (spacing && i + 1 < view_count) paint_log_line("", 0, &paint);
        if (colors) wattroff(activity, COLOR_PAIR(color));
    }
    wnoutrefresh(activity);
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
                                  "PACKET STREAM / HEADER PARSER", "HELP / QUICK START" };
    erase();
    if (rows < MIN_ROWS || cols < MIN_COLS) {
        if (rows > 0 && cols > 1)
            mvaddnstr(0, 0, "Please resize to 80x28 or larger. Q quits.", cols - 1);
        refresh(); return;
    }
    werase(header);
    nf_art_draw_header(header, header_height, colors);
    mvprintw(header_height, body_left + 2, "Main menu%s%s", page == HOME ? "" : " > ", page == HOME ? "" : titles[page]);
    mvaddnstr(header_height + 1, body_left + 2, notice, body_width - 4);
    char bottom[160];
    (void)snprintf(bottom, sizeof bottom, "Scanner: %s | HTTP: %s | Packets: %s | Log: %s",
         nf_job_status(&scan_job), nf_job_status(&http_job), nf_job_status(&packet_job), logs_paused ? "PAUSED" : "LIVE");
    mvaddnstr(rows - 2, body_left + 1, bottom, body_width - 2);
    mvaddnstr(rows - 1, body_left + 1, editing ?
        "EDIT: Ctrl-U clear | Backspace delete | Tab/Enter next | Esc done" :
        "B menu | H help | P pause log | PgUp/PgDn scroll | W save | C clear | Q quit", body_width - 2);
    wnoutrefresh(stdscr);
    wnoutrefresh(header);
    werase(panel); box(panel, 0, 0);
    mvwprintw(panel, 0, 2, " %s ", titles[page]);
    int controls = panel_height - 2;
    if (page == HOME) {
        static const char *names[] = { "TCP port scanner", "HTTP web server",
                                       "Packet stream and header parser", "Help and quick start" };
        static const char *descriptions[] = {
            "Check which TCP ports accept connections on selected devices.",
            "Host a webpage inside Kali and see who connects to it.",
            "Learn packet fields with simulated IPv4, TCP, and UDP examples.",
            "Follow a step-by-step demo and learn the keyboard controls."
        };
        line(panel, 1, "Choose a tool, review its settings, then press Enter to start.");
        for (int i = 0; i < 4; ++i) {
            int row = expanded ? 3 + i * 3 : 2 + i * 2;
            if (home_choice == i) wattron(panel, A_REVERSE);
            line(panel, row, "%s [%d] %s", home_choice == i ? ">" : " ", i + 1, names[i]);
            if (home_choice == i) wattroff(panel, A_REVERSE);
            line(panel, row + 1, "      %s", descriptions[i]);
        }
        line(panel, controls, "Up/Down: choose | Enter: open | 1-4: open directly | Q: quit");
    } else if (page == SCAN) {
        NfMetrics m = nf_job_snapshot(&scan_job);
        line(panel, 1, "Check TCP ports on IPv4 devices you are allowed to test.");
        if (expanded) {
            line(panel, 2, "Both address and port ranges include their first and last values.");
            section(3, "SCAN SETTINGS");
        }
        draw_fields(scan_labels, scan_fields, 5);
        unsigned percent = m.total ? (unsigned)((uint64_t)m.checked * 100U / m.total) : 0;
        char bar[21];
        for (int i = 0; i < 20; ++i) bar[i] = i < (int)(percent / 5U) ? '#' : '-';
        bar[20] = '\0';
        line(panel, expanded ? 14 : 7, "Progress [%s] %3u%% | Connections checked: %u/%u", bar, percent, m.checked, m.total);
        line(panel, expanded ? 15 : 8, "Open: %u | Closed/refused: %u | Uncertain: %u", m.good, m.bad, m.other);
        if (expanded) line(panel, 16, "OPEN = connected | CLOSED = refused | UNCERTAIN = timeout or unreachable");
        line(panel, expanded ? 17 : 9, "Log detail: %s. V changes this before a scan.", verbose_scan ? "all checked ports" : "open ports and summary");
        line(panel, controls, "Enter/Space: %s | E: edit | V: result detail | B: menu", scan_job.live ? "stop scan" : "start scan");
    } else if (page == HTTP) {
        NfMetrics m = nf_job_snapshot(&http_job);
        bool listening = atomic_load(&http_job.state) == NF_RUNNING && !atomic_load(&http_job.stop);
        const char *host = !strcmp(http_fields[0], "0.0.0.0") ? "127.0.0.1" : http_fields[0];
        line(panel, 1, "Host a simple webpage and see the devices connecting to it.");
        if (expanded) {
            line(panel, 2, "Server status: %s", nf_job_status(&http_job));
            section(3, "SERVER SETTINGS");
        }
        draw_fields(http_labels, http_fields, 2);
        if (expanded) section(9, "CONNECTION SUMMARY");
        line(panel, expanded ? 10 : 5, "Clients: %u | Responses (200): %u | Other/incomplete: %u", m.checked, m.good, m.bad);
        if (expanded) section(12, "OPEN IN YOUR KALI BROWSER");
        line(panel, expanded ? 13 : 7, "URL: http://%s:%s/", host, http_fields[1]);
        if (colors) wattron(panel, COLOR_PAIR(listening ? 2 : 3));
        line(panel, expanded ? 14 : 8, "%s", listening ? "Server is running. You can open the URL now." :
             "Start the server with Enter; wait for Running before opening the URL.");
        if (colors) wattroff(panel, COLOR_PAIR(listening ? 2 : 3));
        line(panel, expanded ? 15 : 6, "Page: ./index.html if present; otherwise the built-in welcome page.");
        if (!expanded) {
            line(panel, 4, "127.0.0.1 = this VM | 0.0.0.0 = all IPv4 interfaces");
            line(panel, 9, "Stop/restart after editing index.html. Clients are logged below.");
        }
        line(panel, controls, "Enter/Space: %s | E: edit | B: menu", http_job.live ? "stop server" : "start server");
    } else if (page == PACKETS) {
        NfMetrics m = nf_job_snapshot(&packet_job);
        line(panel, 1, "SIMULATED packets: learn to read IPv4, TCP, and UDP headers.");
        if (expanded) {
            line(panel, 2, "Runs locally. No live traffic is captured or transmitted.");
            section(3, "SIMULATION SETTINGS");
        }
        draw_fields(packet_labels, packet_fields, 3);
        if (expanded) section(11, "PARSER RESULTS");
        line(panel, expanded ? 12 : 6, "Generated: %u | Parsed: %u | Rejected: %u", m.checked, m.good, m.bad);
        line(panel, expanded ? 13 : 7, "Parsed = valid headers. Rejected = invalid or incomplete headers.");
        if (expanded) line(panel, 15, "Source = sender | Destination = receiver | Ports = app endpoints");
        else {
            line(panel, 8, "Source = sender | Destination = receiver | Ports = app endpoints");
            line(panel, 9, "Invalid examples are intentional. No real traffic is involved.");
        }
        line(panel, controls, "Enter/Space: %s | E: edit | B: menu", packet_job.live ? "stop simulation" : "start simulation");
    } else {
        section(1, "QUICK DEMONSTRATION");
        if (expanded) {
            line(panel, 2, "Current HTTP state: %s (the page requires Running).", nf_job_status(&http_job));
            section(4, "1. START THE WEB SERVER");
            line(panel, 5, "Press B -> 2 -> Enter; wait for HTTP: Running at the bottom.");
            section(7, "2. OPEN ITS PAGE INSIDE KALI");
            line(panel, 8, "In Firefox: http://%s:%s/", !strcmp(http_fields[0], "0.0.0.0") ? "127.0.0.1" : http_fields[0], http_fields[1]);
            section(10, "3. SCAN THE LOCAL TCP PORTS");
            line(panel, 11, "Press B -> 1 -> Enter. Defaults include localhost port 8080.");
            section(13, "4. READ EXAMPLE PACKET HEADERS");
            line(panel, 14, "Press B -> 3 -> Enter. Read the labeled packet events below.");
            line(panel, 15, "E: edit | P: pause log | W: save | Q: stop tools and quit");
        } else {
            line(panel, 2, "1. B -> 2 -> Enter: start HTTP; wait for HTTP: Running.");
            line(panel, 3, "2. In Kali Firefox: http://%s:%s/", !strcmp(http_fields[0], "0.0.0.0") ? "127.0.0.1" : http_fields[0], http_fields[1]);
            line(panel, 5, "3. B -> 1 -> Enter: scan localhost (includes TCP port 8080).");
            line(panel, 6, "4. B -> 3 -> Enter: read labeled simulated packet headers.");
            line(panel, 8, "E: edit | Ctrl-U: clear field | Tab: next field");
            line(panel, 9, "P: pause log | W: save recent events | Q: stop all and quit");
        }
        line(panel, controls, "B/Esc: main menu | H: return to the previous screen");
    }
    wnoutrefresh(panel);
    draw_activity();
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
        size_t step = (size_t)(getmaxy(activity) - activity_first_row() - 1);
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
        else { editing = true; field = 0; set_notice("%s", field_hints()[field]); }
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
        for (size_t i = 0; i < 3; ++i) {
            bool was_live = jobs[i]->live;
            if (!nf_job_reap(jobs[i])) interrupted = 1;
            if (was_live && !jobs[i]->live && selected_job() == jobs[i] && !editing)
                set_notice("%s: %s. Review the activity below; Enter starts another run.", jobs[i]->name, nf_job_status(jobs[i]));
        }
        int current_rows, current_cols;
        getmaxyx(stdscr, current_rows, current_cols);
        if (current_rows != rows || current_cols != cols || page != layout_page) {
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
