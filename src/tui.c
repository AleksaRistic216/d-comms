#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <dirent.h>
#include <signal.h>

#include "proto.h"
#include "sync.h"

#define MAX_CHATS   64
#define REFRESH_SEC 2

/* ---- terminal state ---- */

static struct termios g_orig_termios;
static char g_basedir[256];

static void disable_raw_mode(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
    printf("\033[?25h");
    fflush(stdout);
}

static void enable_raw_mode(void)
{
    tcgetattr(STDIN_FILENO, &g_orig_termios);
    atexit(disable_raw_mode);

    struct termios raw = g_orig_termios;
    raw.c_lflag &= (tcflag_t)~(ECHO | ICANON);
    raw.c_iflag &= (tcflag_t)~(IXON);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static void get_term_size(int *rows, int *cols)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) {
        *rows = 24;
        *cols = 80;
    } else {
        *rows = ws.ws_row;
        *cols = ws.ws_col;
    }
}

static void clear_screen(void)
{
    printf("\033[2J\033[H");
}

/* ---- resolve binary directory from /proc/self/exe ---- */

static void resolve_basedir(void)
{
    char exe[256];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len == -1) {
        strcpy(g_basedir, ".");
        return;
    }
    exe[len] = '\0';
    char *slash = strrchr(exe, '/');
    if (slash) {
        *slash = '\0';
        strncpy(g_basedir, exe, sizeof(g_basedir) - 1);
        g_basedir[sizeof(g_basedir) - 1] = '\0';
    } else {
        strcpy(g_basedir, ".");
    }
}

/* ---- scan chats/ directory ---- */

static int scan_chats(char names[][64])
{
    int count = 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/chats", g_basedir);

    DIR *d = opendir(path);
    if (!d) return 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < MAX_CHATS) {
        int len = (int)strlen(ent->d_name);
        if (len > 5 && len - 5 < 64 && strcmp(ent->d_name + len - 5, ".chat") == 0) {
            memcpy(names[count], ent->d_name, (size_t)(len - 5));
            names[count][len - 5] = '\0';
            count++;
        }
    }
    closedir(d);
    return count;
}

/* ---- line input in raw mode ---- */

static int read_line_raw(const char *prompt, char *buf, int maxlen)
{
    printf("%s", prompt);
    fflush(stdout);

    int len = 0;
    buf[0] = '\0';

    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);

        /* Block until input */
        if (select(STDIN_FILENO + 1, &fds, NULL, NULL, NULL) <= 0)
            continue;

        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) continue;

        if (c == 27) return -1; /* Escape = cancel */

        if (c == '\n' || c == '\r') {
            buf[len] = '\0';
            printf("\n");
            fflush(stdout);
            return len;
        }

        if ((c == 127 || c == 8) && len > 0) {
            len--;
            buf[len] = '\0';
            printf("\b \b");
            fflush(stdout);
        } else if (c >= 32 && c < 127 && len < maxlen - 1) {
            buf[len++] = c;
            buf[len] = '\0';
            printf("%c", c);
            fflush(stdout);
        }
    }
}

/* ---- drawing helpers ---- */

static void draw_hline(int row, int cols)
{
    printf("\033[%d;1H", row);
    for (int i = 0; i < cols; i++) putchar('-');
}

/* ---- chat view screen ---- */

static void screen_chat_view(const char *name)
{
    proto_chat chat;
    if (proto_load_chat(&chat, name, g_basedir) != 0) return;

    char input[MAX_MSG];
    int input_len = 0;
    input[0] = '\0';

    while (1) {
        sync_with_peers();
        const proto_messages *msgs = proto_list(&chat);

        int rows, cols;
        get_term_size(&rows, &cols);

        /* Hide cursor during render */
        printf("\033[?25l");
        clear_screen();

        /* Header */
        printf("\033[1m %s\033[0m", name);
        const char *ctrl = "[Esc]Back [^R]Refresh";
        int ctrl_len = (int)strlen(ctrl);
        if (cols > ctrl_len + 2)
            printf("\033[1;%dH\033[2m%s\033[0m", cols - ctrl_len, ctrl);

        /* Top separator */
        draw_hline(2, cols);

        /* Messages area: rows 3 to rows-2 */
        int msg_rows = rows - 4;
        if (msg_rows < 1) msg_rows = 1;
        int start = 0;
        if (msgs->count > msg_rows) start = msgs->count - msg_rows;

        for (int i = start; i < msgs->count; i++) {
            int row = 3 + (i - start);
            printf("\033[%d;1H", row);

            if (msgs->sender[i] == 0)
                printf("\033[36m"); /* cyan = initiator */
            else
                printf("\033[33m"); /* yellow = responder */

            printf("  %.*s\033[0m", cols - 3, msgs->texts[i]);
        }

        /* Bottom separator */
        draw_hline(rows - 1, cols);

        /* Input line */
        printf("\033[%d;1H> %.*s", rows, cols - 3, input);

        /* Show cursor at input position */
        printf("\033[?25h");
        fflush(stdout);

        /* Wait for input or timeout */
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        struct timeval tv;
        tv.tv_sec = REFRESH_SEC;
        tv.tv_usec = 0;

        int ret = select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
        if (ret <= 0) continue; /* timeout -> refresh */

        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) continue;

        if (c == 27) { /* Escape */
            /* Check if it's an escape sequence */
            fd_set fds2;
            FD_ZERO(&fds2);
            FD_SET(STDIN_FILENO, &fds2);
            struct timeval tv2;
            tv2.tv_sec = 0;
            tv2.tv_usec = 50000; /* 50ms */
            if (select(STDIN_FILENO + 1, &fds2, NULL, NULL, &tv2) > 0) {
                /* Consume escape sequence */
                char seq[8];
                (void)read(STDIN_FILENO, seq, sizeof(seq));
            } else {
                /* Plain Escape -> back to chat list */
                proto_save_chat(&chat, name, g_basedir);
                break;
            }
        } else if (c == 2) { /* Ctrl-B */
            proto_save_chat(&chat, name, g_basedir);
            break;
        } else if (c == 18) { /* Ctrl-R -> refresh */
            continue;
        } else if (c == '\n' || c == '\r') {
            if (input_len > 0) {
                proto_send(&chat, input);
                input_len = 0;
                input[0] = '\0';
            }
        } else if (c == 127 || c == 8) { /* Backspace */
            if (input_len > 0) {
                input[--input_len] = '\0';
            }
        } else if (c >= 32 && c < 127) { /* Printable */
            if (input_len < MAX_MSG - 1) {
                input[input_len++] = c;
                input[input_len] = '\0';
            }
        }
    }

    proto_chat_cleanup(&chat);
}

/* ---- chat list screen ---- */

static int screen_chat_list(char *out_name)
{
    while (1) {
        char names[MAX_CHATS][64];
        int count = scan_chats(names);

        int rows, cols;
        get_term_size(&rows, &cols);
        (void)rows;

        printf("\033[?25l");
        clear_screen();

        printf("\033[1m d-comms\033[0m\n");
        draw_hline(2, cols);
        printf("\033[3;1H  [N] New chat\n");
        printf("  [J] Join chat\n");
        draw_hline(5, cols);

        for (int i = 0; i < count && i < 9; i++)
            printf("\033[%d;1H  %d. %s", 6 + i, i + 1, names[i]);

        int bottom = 6 + count;
        draw_hline(bottom, cols);
        printf("\033[%d;1H  Select: ", bottom + 1);
        printf("\033[?25h");
        fflush(stdout);

        /* Wait for keypress */
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        if (select(STDIN_FILENO + 1, &fds, NULL, NULL, NULL) <= 0)
            continue;

        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) continue;

        if (c == 'q' || c == 'Q') return -1;

        if (c == 'n' || c == 'N') {
            clear_screen();
            printf("\033[1m New Chat\033[0m\n\n");

            char name[64];
            if (read_line_raw("  Chat name: ", name, (int)sizeof(name)) <= 0)
                continue;

            proto_chat chat;
            char out_key[ID_BYTES * 2 + 1];
            char out_id[ID_BYTES * 2 + 1];
            if (proto_initialize(&chat, out_key, out_id) != 0) {
                printf("\n  \033[31mError: failed to generate keys\033[0m\n");
                printf("  Press any key...");
                fflush(stdout);
                char k;
                (void)read(STDIN_FILENO, &k, 1);
                continue;
            }
            proto_save_chat(&chat, name, g_basedir);

            printf("\n  Share with the other device:\n");
            printf("  \033[1mset %s %s\033[0m\n", out_key, out_id);
            printf("\n  Press Enter to continue...");
            fflush(stdout);

            while (1) {
                char k;
                if (read(STDIN_FILENO, &k, 1) == 1) {
                    if (k == '\n' || k == '\r' || k == 27) break;
                }
            }

            strcpy(out_name, name);
            return 0;
        }

        if (c == 'j' || c == 'J') {
            clear_screen();
            printf("\033[1m Join Chat\033[0m\n\n");

            char name[64], cmd[256];
            if (read_line_raw("  Chat name:    ", name, (int)sizeof(name)) <= 0)
                continue;
            if (read_line_raw("  Set command:  ", cmd, (int)sizeof(cmd)) <= 0)
                continue;

            /* Parse "set <key> <id>" or just "<key> <id>" */
            char key[64], id[64];
            const char *p = cmd;
            if (strncmp(p, "set ", 4) == 0) p += 4;
            while (*p == ' ') p++;
            if (sscanf(p, "%63s %63s", key, id) != 2) {
                printf("\n  Invalid format. Expected: set <key> <id>\n");
                printf("  Press any key...");
                fflush(stdout);
                char k;
                (void)read(STDIN_FILENO, &k, 1);
                continue;
            }

            proto_chat chat;
            proto_join(&chat, key, id);
            proto_save_chat(&chat, name, g_basedir);

            strcpy(out_name, name);
            return 0;
        }

        if (c >= '1' && c <= '9') {
            int idx = c - '1';
            if (idx < count) {
                strcpy(out_name, names[idx]);
                return 0;
            }
        }
    }
}

/* ---- main ---- */

int main(void)
{
    resolve_basedir();

    /* Sync setup (before raw mode so status prints normally) */
    signal(SIGPIPE, SIG_IGN);
    int port = sync_start_server();
    if (port > 0) {
        sync_register(port);
        atexit(sync_unregister);
    }
    int synced = sync_with_peers();
    if (synced > 0)
        printf("Synced %d entries from peers.\n", synced);

    /* TUI */
    setvbuf(stdout, NULL, _IOFBF, 4096);
    enable_raw_mode();

    while (1) {
        char chat_name[64];
        if (screen_chat_list(chat_name) < 0) break;
        screen_chat_view(chat_name);
    }

    clear_screen();
    return 0;
}
