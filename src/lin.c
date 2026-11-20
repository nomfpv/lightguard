/* lightguard for linux: terminal ui with the same layout and wording as the windows window.
   configs in /etc/wireguard (mode 600), tunnels are wg-quick@<name> systemd units. */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include "lgcore.h"

#define CONFDIR "/etc/wireguard"
#define NAME_MAX_LEN 15          /* interface names are limited to 15 chars */
#define MAX_TUN 128

/* accent only for panel top lines, the selected row, the primary key and checked boxes */
#define C_RST "\033[0m"
#define C_ACC "\033[36m"
#define C_SEL "\033[30;46m"
#define C_DIM "\033[2m"
#define C_ERR "\033[31m"
#define C_BOLD "\033[1m"

enum { K_NONE = -1, K_UP = 1000, K_DOWN, K_LEFT, K_RIGHT, K_ESC, K_ENTER, K_BS, K_TAB, K_DEL };

/* ---------- terminal ---------- */
static struct termios g_old;
static int g_raw;
static int g_rows = 24, g_cols = 80;

static void term_restore(void)
{
    if (!g_raw) return;
    fputs("\033[0m\033[?25h\033[?1049l", stdout);
    fflush(stdout);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_old);
    g_raw = 0;
}

static void on_term(int sig)
{
    (void)sig;
    term_restore();
    _exit(1);
}

static void on_winch(int sig) { (void)sig; }

static int term_raw(void)
{
    struct termios t;
    struct sigaction sa;
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) return 0;
    if (tcgetattr(STDIN_FILENO, &g_old) < 0) return 0;
    t = g_old;
    t.c_iflag &= ~(tcflag_t)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    t.c_lflag &= ~(tcflag_t)(ECHO | ICANON | IEXTEN | ISIG);
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &t) < 0) return 0;
    g_raw = 1;
    atexit(term_restore);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = on_winch;      /* no SA_RESTART: poll returns and we redraw */
    sigaction(SIGWINCH, &sa, NULL);
    fputs("\033[?1049h\033[?25l", stdout);
    return 1;
}

static void term_size(void)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 0 && ws.ws_col > 0) {
        g_rows = ws.ws_row;
        g_cols = ws.ws_col;
    }
}

static int read_byte(int timeout_ms)
{
    struct pollfd p;
    unsigned char c;
    p.fd = STDIN_FILENO;
    p.events = POLLIN;
    if (poll(&p, 1, timeout_ms) <= 0) return K_NONE;
    if (read(STDIN_FILENO, &c, 1) != 1) return K_NONE;
    return c;
}

static int get_key(int timeout_ms)
{
    int c = read_byte(timeout_ms);
    if (c == K_NONE) return K_NONE;
    if (c == 27) {
        int d = read_byte(40);
        if (d == K_NONE) return K_ESC;
        if (d == '[' || d == 'O') {
            int e = read_byte(40);
            switch (e) {
            case 'A': return K_UP;
            case 'B': return K_DOWN;
            case 'C': return K_RIGHT;
            case 'D': return K_LEFT;
            case '3': read_byte(40); return K_DEL;
            default:
                while (e >= '0' && e <= '9') e = read_byte(40);   /* swallow other sequences */
                return K_NONE;
            }
        }
        return K_ESC;
    }
    if (c == '\r' || c == '\n') return K_ENTER;
    if (c == 127 || c == 8) return K_BS;
    if (c == '\t') return K_TAB;
    return c;
}

/* ---------- drawing ---------- */
static void at(int r, int c) { printf("\033[%d;%dH", r, c); }

static void rep(const char *s, int n) { while (n-- > 0) fputs(s, stdout); }

/* ascii text clipped to w columns, padded with spaces when pad is set */
static void put_w(const char *s, int w, int pad)
{
    int n = (int)strlen(s);
    if (w <= 0) return;
    if (n > w) n = w;
    fwrite(s, 1, (size_t)n, stdout);
    if (pad) rep(" ", w - n);
}

/* panel: thin border, accent top edge, centered header */
static void box(int r, int c, int h, int w, const char *title)
{
    int i;
    if (h < 2 || w < 4) return;
    at(r, c);
    fputs(C_ACC "\xe2\x94\x8c", stdout);
    rep("\xe2\x94\x80", w - 2);
    fputs("\xe2\x94\x90" C_RST, stdout);
    for (i = 1; i < h - 1; i++) {
        at(r + i, c); fputs("\xe2\x94\x82", stdout);
        at(r + i, c + w - 1); fputs("\xe2\x94\x82", stdout);
    }
    at(r + h - 1, c);
    fputs("\xe2\x94\x94", stdout);
    rep("\xe2\x94\x80", w - 2);
    fputs("\xe2\x94\x98", stdout);
    if (title) {
        int n = (int)strlen(title);
        at(r, c + (w - n - 2) / 2);
        printf(" %s ", title);
    }
}

/* ---------- helpers ---------- */
static int name_ok(const char *n)
{
    return lg_name_ok(n, NAME_MAX_LEN) && !strchr(n, '=') && !strchr(n, '+');   /* not valid in unit names */
}

static void conf_path(const char *name, char *out, size_t cap)
{
    snprintf(out, cap, CONFDIR "/%s.conf", name);
}

static char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *buf;
    long sz;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 || sz > 65536) { fclose(f); return NULL; }
    rewind(f);
    buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { lg_wipe(buf, (size_t)sz); free(buf); fclose(f); return NULL; }
    fclose(f);
    buf[sz] = 0;
    *len = (size_t)sz;
    return buf;
}

static void free_secret(char *p, size_t n)
{
    if (!p) return;
    lg_wipe(p, n);
    free(p);
}

/* write to a 0600 temp file in the same dir, then rename over the target */
static int write_conf(const char *name, const char *data, size_t len)
{
    char path[256], tmp[256];
    int fd;
    size_t off = 0;
    mkdir(CONFDIR, 0700);
    conf_path(name, path, sizeof path);
    snprintf(tmp, sizeof tmp, CONFDIR "/.%s.tmp", name);
    unlink(tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return 0;
    while (off < len) {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; close(fd); unlink(tmp); return 0; }
        off += (size_t)w;
    }
    fchmod(fd, 0600);
    if (fsync(fd) < 0 || close(fd) < 0 || rename(tmp, path) < 0) { unlink(tmp); return 0; }
    return 1;
}

/* the dir may predate us: make it 0700 and every config in it 0600 */
static void tighten_perms(void)
{
    struct stat st;
    DIR *d;
    struct dirent *e;
    if (lstat(CONFDIR, &st) != 0 || !S_ISDIR(st.st_mode)) return;
    chmod(CONFDIR, 0700);
    d = opendir(CONFDIR);
    if (!d) return;
    while ((e = readdir(d)) != NULL) {
        char p[512];
        size_t n = strlen(e->d_name);
        if (n < 6 || strcmp(e->d_name + n - 5, ".conf") != 0) continue;
        snprintf(p, sizeof p, CONFDIR "/%s", e->d_name);
        if (lstat(p, &st) == 0 && S_ISREG(st.st_mode)) chmod(p, 0600);
    }
    closedir(d);
}

static int random32(lg_u8 *o)
{
    int fd = open("/dev/urandom", O_RDONLY);
    size_t got = 0;
    if (fd < 0) return 0;
    while (got < 32) {
        ssize_t r = read(fd, o + got, 32 - got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { close(fd); return 0; }
        got += (size_t)r;
    }
    close(fd);
    return 1;
}

/* run a command, capture stdout+stderr, return exit status (-1 on failure to run) */
static int run(char *const argv[], char *out, size_t cap)
{
    int pfd[2], status;
    pid_t pid;
    size_t n = 0;
    if (out && cap) out[0] = 0;
    if (pipe(pfd) < 0) return -1;
    pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, STDIN_FILENO);
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]);
        close(pfd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pfd[1]);
    for (;;) {
        char tmp[256];
        ssize_t r = read(pfd[0], tmp, sizeof tmp);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        if (out && n + 1 < cap) {
            size_t take = (size_t)r;
            if (take > cap - 1 - n) take = cap - 1 - n;
            memcpy(out + n, tmp, take);
            n += take;
            out[n] = 0;
        }
    }
    close(pfd[0]);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) ;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void trim(char *s)
{
    size_t n = strlen(s), i = 0;
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = 0;
    while (s[i] == ' ' || s[i] == '\t') i++;
    if (i) memmove(s, s + i, n - i + 1);
}

static void unit_of(const char *name, char *out, size_t cap)
{
    snprintf(out, cap, "wg-quick@%s", name);
}

/* ---------- state ---------- */
typedef struct { char name[NAME_MAX_LEN + 1]; int st, boot; } Tun;   /* st: 0 off 1 connecting 2 connected 3 disconnecting 4 failed */
static Tun g_t[MAX_TUN];
static int g_n;
static int g_have_wg;

static int g_selk;                    /* 0 nothing, 1 saved tunnel g_cur, 2 new unsaved tunnel */
static char g_cur[NAME_MAX_LEN + 1];
static lg_conf g_conf;
static int g_dirty, g_touched, g_multi, g_tab, g_show, g_focus, g_item, g_editing = -1;
static int g_armdel, g_armleave, g_armquit, g_copied, g_top;
static char g_msg[256];
static int g_msgk;                    /* 0 dim, 1 text, 2 error */
static char g_pub[45];
static int g_pubok;

/* form fields; checkboxes are items too so the cursor can reach them */
enum { F_NAME, F_ADDR, F_ENDP, F_PEER, F_ALLOWED, F_KEEP, F_BOOT, F_PRIV, F_PSK, NF };
static const char *f_label[NF] = {
    "Name", "Your address", "Friend's server", "Friend's public key", "Networks to reach",
    "Keep connection alive", "Start at boot", "Your private key", "Preshared key"
};
static const char *f_cue[NF] = {
    "home", "10.66.66.2/24", "host:port", "44 characters, ends with =", "192.168.50.0/24, comma-separated",
    NULL, NULL, NULL, "optional"
};
static const char *f_hint[NF] = { NULL, NULL, "optional", NULL, NULL, NULL, NULL, "never share this", "both sides need the same one" };
static const size_t f_max[NF] = { NAME_MAX_LEN, 255, 255, 63, 511, 0, 0, 63, 63 };
static char fv[NF][520];
static int f_keep;
static char ferr[NF][80];

static void msg(int kind, const char *s)
{
    snprintf(g_msg, sizeof g_msg, "%s", s);
    g_msgk = kind;
}

static int cmp_tun(const void *a, const void *b) { return strcmp(((const Tun *)a)->name, ((const Tun *)b)->name); }

static Tun *cur_tun(void)
{
    int i;
    if (g_selk != 1) return NULL;
    for (i = 0; i < g_n; i++) if (strcmp(g_t[i].name, g_cur) == 0) return &g_t[i];
    return NULL;
}

static int sel_index(void)
{
    Tun *t;
    if (g_selk == 2) return g_n;
    t = cur_tun();
    return t ? (int)(t - g_t) : -1;
}

static void wipe_form(void)
{
    lg_wipe(fv, sizeof fv);
    lg_wipe(&g_conf, sizeof g_conf);
    lg_wipe(g_pub, sizeof g_pub);
}

static void load_tunnels(void)
{
    DIR *d;
    struct dirent *e;
    int i;
    g_n = 0;
    d = opendir(CONFDIR);
    if (d) {
        while ((e = readdir(d)) != NULL && g_n < MAX_TUN) {
            size_t n = strlen(e->d_name);
            if (n < 6 || strcmp(e->d_name + n - 5, ".conf") != 0) continue;
            n -= 5;
            if (n > NAME_MAX_LEN) continue;
            memcpy(g_t[g_n].name, e->d_name, n);
            g_t[g_n].name[n] = 0;
            if (!name_ok(g_t[g_n].name)) continue;
            g_t[g_n].st = g_t[g_n].boot = 0;
            g_n++;
        }
        closedir(d);
    }
    qsort(g_t, (size_t)g_n, sizeof g_t[0], cmp_tun);
    for (i = 0; i < g_n; i++) {
        char unit[64], out[64];
        char *a[4];
        unit_of(g_t[i].name, unit, sizeof unit);
        a[0] = "systemctl"; a[1] = "is-active"; a[2] = unit; a[3] = NULL;
        run(a, out, sizeof out);
        trim(out);
        g_t[i].st = strcmp(out, "active") == 0 ? 2 : strcmp(out, "activating") == 0 ? 1 :
                    strcmp(out, "deactivating") == 0 ? 3 : strcmp(out, "failed") == 0 ? 4 : 0;
        a[1] = "is-enabled";
        run(a, out, sizeof out);
        trim(out);
        g_t[i].boot = strcmp(out, "enabled") == 0;
    }
    if (g_selk == 1 && !cur_tun()) {   /* removed behind our back */
        g_selk = 0;
        g_dirty = 0;
        wipe_form();
    }
}

/* returns the systemctl exit code, puts its first output line into the status on failure */
static int systemctl_do(const char *verb, const char *extra, const char *name)
{
    char unit[64], out[256], m[256];
    char *a[6];
    int n = 0, rc;
    unit_of(name, unit, sizeof unit);
    a[n++] = "systemctl";
    a[n++] = (char *)verb;
    if (extra) a[n++] = (char *)extra;
    a[n++] = unit;
    a[n] = NULL;
    rc = run(a, out, sizeof out);
    if (rc != 0) {
        char *nl = strchr(out, '\n');
        if (nl) *nl = 0;
        snprintf(m, sizeof m, "systemctl %s failed: %s", verb, out[0] ? out : "see journalctl");
        msg(2, m);
    }
    return rc;
}

/* ---------- form ---------- */
static void update_pub(void)
{
    lg_u8 k[32], p[32];
    g_pubok = lg_b64dec(fv[F_PRIV], k);
    if (g_pubok) {
        lg_pubkey(p, k);
        lg_b64enc(g_pub, p);
    } else {
        g_pub[0] = 0;
    }
    lg_wipe(k, sizeof k);
}

static int gen_key(int f)
{
    lg_u8 k[32];
    if (!random32(k)) { msg(2, "The random number generator failed."); return 0; }
    if (f == F_PRIV) lg_clamp(k);
    lg_b64enc(fv[f], k);
    lg_wipe(k, sizeof k);
    if (f == F_PRIV) update_pub();
    return 1;
}

static void clear_form(void)
{
    wipe_form();
    memset(ferr, 0, sizeof ferr);
    g_dirty = g_touched = g_multi = g_copied = g_pubok = 0;
    g_armdel = g_armleave = g_armquit = 0;
    g_show = 0;           /* secrets are masked again whenever the form changes hands */
    g_tab = 0;
    g_item = F_NAME;
}

static void load_form(const char *name)
{
    char path[256];
    size_t len = 0;
    char *d;
    clear_form();
    g_selk = 1;
    snprintf(g_cur, sizeof g_cur, "%s", name);
    conf_path(name, path, sizeof path);
    d = read_file(path, &len);
    if (d) {
        lg_conf_parse(&g_conf, d, len);
        free_secret(d, len);
    }
    snprintf(fv[F_NAME], sizeof fv[0], "%s", name);
    snprintf(fv[F_ADDR], sizeof fv[0], "%s", g_conf.address);
    snprintf(fv[F_ENDP], sizeof fv[0], "%s", g_conf.endpoint);
    snprintf(fv[F_PEER], sizeof fv[0], "%s", g_conf.peerpub);
    snprintf(fv[F_ALLOWED], sizeof fv[0], "%s", g_conf.allowed);
    snprintf(fv[F_PRIV], sizeof fv[0], "%s", g_conf.priv);
    snprintf(fv[F_PSK], sizeof fv[0], "%s", g_conf.psk);
    f_keep = g_conf.keepalive[0] && strcmp(g_conf.keepalive, "0") != 0;
    g_multi = g_conf.npeers > 1;
    update_pub();
    g_msg[0] = 0;
    if (!d) msg(2, "Could not read this config file.");
    else if (g_multi) msg(0, "This config has several peers: edit the file by hand. Connect still works.");
}

/* ---------- validation ---------- */
static int ip_list_ok(const char *s)
{
    int digits = 0, sep = 0, slash = 0, pre = 0;
    for (;; s++) {
        char c = *s;
        if (c == ',' || c == 0) {
            if (!digits || !sep || (slash && (pre < 1 || pre > 3))) return 0;
            if (!c) return 1;
            digits = sep = slash = pre = 0;
            continue;
        }
        if (c == ' ') continue;
        if (slash) { if (c < '0' || c > '9') return 0; pre++; continue; }
        if (c == '/') { slash = 1; continue; }
        if (c >= '0' && c <= '9') digits++;
        else if (c == '.' || c == ':') sep = 1;
        else if (!isxdigit((unsigned char)c)) return 0;
    }
}

static int endpoint_ok(const char *s)
{
    const char *c = strrchr(s, ':'), *p;
    int n = 0;
    long port = 0;
    if (strchr(s, ' ') || !c || c == s) return 0;
    for (p = c + 1; *p; p++) {
        if (!isdigit((unsigned char)*p) || ++n > 5) return 0;
        port = port * 10 + (*p - '0');
    }
    return n > 0 && port > 0 && port < 65536;
}

static void key_err(const char *s, char *out, size_t cap)
{
    size_t n = strlen(s);
    if (n != 44) snprintf(out, cap, "has %zu characters, a key has 44", n);
    else snprintf(out, cap, "not a valid key, check for typos");
}

/* complete = also what connecting needs. only = one field or -1. returns the first bad field or -1 */
static int validate(int complete, int only)
{
    lg_u8 k[32];
    char path[256], e[80];
    int bad = -1, f;
#define BAD(F, M) do { if (only < 0 || only == (F)) { snprintf(ferr[F], sizeof ferr[F], "%s", (M)); if (bad < 0) bad = (F); } } while (0)
    for (f = 0; f < NF; f++) if (only < 0 || only == f) ferr[f][0] = 0;
    if (g_multi) return -1;

    if (!name_ok(fv[F_NAME])) BAD(F_NAME, "1-15 letters, digits or _ . -");
    else {
        conf_path(fv[F_NAME], path, sizeof path);
        if ((g_selk == 2 || strcmp(fv[F_NAME], g_cur) != 0) && access(path, F_OK) == 0) BAD(F_NAME, "another tunnel has this name");
    }
    if (!fv[F_ADDR][0]) { if (complete) BAD(F_ADDR, "needed to connect, e.g. 10.66.66.2/24"); }
    else if (!ip_list_ok(fv[F_ADDR])) BAD(F_ADDR, "use an address like 10.66.66.2/24");
    if (fv[F_ENDP][0] && !endpoint_ok(fv[F_ENDP])) BAD(F_ENDP, "use host:port, e.g. vpn.example.org:51820");
    if (!fv[F_PEER][0]) { if (complete) BAD(F_PEER, "needed, ask your friend for it"); }
    else if (!lg_b64dec(fv[F_PEER], k)) { key_err(fv[F_PEER], e, sizeof e); BAD(F_PEER, e); }
    else if (strcmp(fv[F_PEER], g_pub) == 0) BAD(F_PEER, "this is your own key, paste your friend's");
    if (!fv[F_ALLOWED][0]) { if (complete) BAD(F_ALLOWED, "needed to connect, e.g. 192.168.50.0/24"); }
    else if (!ip_list_ok(fv[F_ALLOWED])) BAD(F_ALLOWED, "use networks like 192.168.50.0/24");
    if (!lg_b64dec(fv[F_PRIV], k)) BAD(F_PRIV, "not a valid key, press g for a new one");
    if (fv[F_PSK][0] && !lg_b64dec(fv[F_PSK], k)) { key_err(fv[F_PSK], e, sizeof e); BAD(F_PSK, e); }
#undef BAD
    lg_wipe(k, sizeof k);
    return bad;
}

static void show_bad(int f, int complete)
{
    g_tab = f >= F_PRIV;
    g_item = f;
    g_focus = 1;
    msg(2, complete ? "Fill in the marked fields to connect." : "Not saved: check the marked field.");
}

static int name_locked(void)
{
    Tun *t = cur_tun();
    return t && (t->st != 0 || t->boot);
}

static int form_save(int complete)
{
    static char out[8192];
    char old[256];
    int bad, len;
    Tun *t;
    if (g_multi) return 1;   /* read only, nothing to write */
    bad = validate(complete, -1);
    if (bad >= 0) { show_bad(bad, complete); return 0; }
    snprintf(g_conf.priv, sizeof g_conf.priv, "%s", fv[F_PRIV]);
    snprintf(g_conf.address, sizeof g_conf.address, "%s", fv[F_ADDR]);
    snprintf(g_conf.endpoint, sizeof g_conf.endpoint, "%s", fv[F_ENDP]);
    snprintf(g_conf.peerpub, sizeof g_conf.peerpub, "%s", fv[F_PEER]);
    snprintf(g_conf.allowed, sizeof g_conf.allowed, "%s", fv[F_ALLOWED]);
    snprintf(g_conf.psk, sizeof g_conf.psk, "%s", fv[F_PSK]);
    if (f_keep) { if (!g_conf.keepalive[0] || strcmp(g_conf.keepalive, "0") == 0) snprintf(g_conf.keepalive, sizeof g_conf.keepalive, "25"); }
    else g_conf.keepalive[0] = 0;
    len = lg_conf_format(&g_conf, out, sizeof out);
    if (len < 0) { snprintf(ferr[F_ADDR], sizeof ferr[F_ADDR], "too long for a config file"); show_bad(F_ADDR, 0); return 0; }
    if (!write_conf(fv[F_NAME], out, (size_t)len)) {
        char m[160];
        lg_wipe(out, sizeof out);
        snprintf(m, sizeof m, "Could not write the config file: %s", strerror(errno));
        msg(2, m);
        return 0;
    }
    lg_wipe(out, sizeof out);
    if (g_selk == 1 && strcmp(fv[F_NAME], g_cur) != 0) {
        conf_path(g_cur, old, sizeof old);
        unlink(old);
    }
    g_selk = 1;
    snprintf(g_cur, sizeof g_cur, "%s", fv[F_NAME]);
    g_dirty = 0;
    g_armleave = g_armquit = 0;
    load_tunnels();
    t = cur_tun();
    msg(0, t && t->st == 2 ? "Saved. Disconnect and connect again to use the changes." : "Saved.");
    return 1;
}

/* may the right side switch to something else? saves valid changes on the way */
static int leave_current(void)
{
    if (g_selk == 0) return 1;
    if (g_selk == 2 && !g_touched) { g_selk = 0; return 1; }   /* untouched new tunnel: just drop it */
    if (!g_dirty) return 1;
    if (g_armleave) { if (g_selk == 2) g_selk = 0; g_dirty = 0; return 1; }
    if (form_save(0)) return 1;
    g_armleave = 1;
    msg(2, "Not saved: fix the marked field, or press again to throw the changes away.");
    return 0;
}

static void select_row(int i)
{
    char name[NAME_MAX_LEN + 1];
    if (i == sel_index() || i < 0 || i >= g_n) return;
    snprintf(name, sizeof name, "%s", g_t[i].name);
    if (!leave_current()) return;
    load_tunnels();
    load_form(name);
}

/* ---------- actions ---------- */
static void do_new(void)
{
    char path[256];
    int i;
    if (g_selk == 2) { g_focus = 1; g_tab = 0; g_item = F_NAME; return; }
    if (!leave_current()) return;
    load_tunnels();
    clear_form();
    g_selk = 2;
    g_cur[0] = 0;
    for (i = 1; i < 1000; i++) {
        snprintf(fv[F_NAME], sizeof fv[0], "tunnel%d", i);
        conf_path(fv[F_NAME], path, sizeof path);
        if (access(path, F_OK) != 0) break;
    }
    f_keep = 1;
    gen_key(F_PRIV);   /* the keypair is made right away */
    g_dirty = 1;
    g_focus = 1;
    msg(0, "New tunnel. Send your key to your friend, fill in their details, then Save.");
}

static int ready_for_service(void)
{
    int bad;
    if (g_dirty || g_selk == 2) return form_save(1);
    bad = validate(1, -1);
    if (bad >= 0) { show_bad(bad, 1); return 0; }
    return 1;
}

static void draw(void);

static void do_connect(void)
{
    Tun *t;
    char name[NAME_MAX_LEN + 1];
    if (!g_selk) return;
    if (!g_have_wg) { msg(2, "Install wireguard-tools first."); return; }
    t = cur_tun();
    if (t && (t->st == 1 || t->st == 2)) {
        snprintf(name, sizeof name, "%s", t->name);
        msg(0, "Disconnecting...");
        draw();
        if (systemctl_do("stop", NULL, name) == 0) g_msg[0] = 0;
        load_tunnels();
        return;
    }
    if (!ready_for_service()) return;
    t = cur_tun();
    if (!t) return;
    snprintf(name, sizeof name, "%s", t->name);
    msg(0, "Connecting...");
    draw();
    if (systemctl_do("start", NULL, name) == 0) g_msg[0] = 0;
    load_tunnels();
}

/* start at boot only enables or disables the unit; it does not connect now */
static void do_boot(void)
{
    Tun *t;
    char name[NAME_MAX_LEN + 1];
    int want;
    if (!g_selk) return;
    if (!g_have_wg) { msg(2, "Install wireguard-tools first."); return; }
    if (!ready_for_service()) return;
    t = cur_tun();
    if (!t) return;
    want = !t->boot;
    snprintf(name, sizeof name, "%s", t->name);
    if (systemctl_do(want ? "enable" : "disable", NULL, name) == 0)
        msg(0, want ? "Starts at boot from the next boot." : "Does not start at boot any more.");
    load_tunnels();
}

static void do_delete(void)
{
    char path[256], name[NAME_MAX_LEN + 1];
    if (!g_selk) return;
    if (!g_armdel) {
        g_armdel = 1;
        msg(0, g_selk == 2 ? "Press d again to throw this new tunnel away." : "Press d again to delete this tunnel for good.");
        return;
    }
    g_armdel = 0;
    if (g_selk == 2) {
        clear_form();
        g_selk = 0;
        msg(0, "New tunnel thrown away.");
        return;
    }
    snprintf(name, sizeof name, "%s", g_cur);
    if (cur_tun() && (cur_tun()->st || cur_tun()->boot)) systemctl_do("disable", "--now", name);
    conf_path(name, path, sizeof path);
    if (unlink(path) < 0) {
        char m[160];
        snprintf(m, sizeof m, "Could not delete the config file: %s", strerror(errno));
        msg(2, m);
        return;
    }
    clear_form();
    g_selk = 0;
    load_tunnels();
    if (g_n > 0) load_form(g_t[0].name);
    msg(0, "Tunnel deleted.");
}

/* single line prompt on the bottom row */
static void prompt(const char *label, char *buf, size_t cap)
{
    size_t n = 0;
    buf[0] = 0;
    fputs("\033[?25h", stdout);
    for (;;) {
        int k;
        term_size();
        at(g_rows, 1);
        printf("\033[K%s%s", label, buf);
        fflush(stdout);
        k = get_key(-1);
        if (k == K_ENTER) break;
        if (k == K_ESC) { buf[0] = 0; break; }
        if (k == K_BS && n) buf[--n] = 0;
        else if (k >= 32 && k < 127 && n + 1 < cap) { buf[n++] = (char)k; buf[n] = 0; }
    }
    fputs("\033[?25l", stdout);
}

/* copies a .conf into /etc/wireguard. the source file is only read, never changed or removed */
static void do_import(void)
{
    char path[512], name[NAME_MAX_LEN + 1], try_[NAME_MAX_LEN + 8], dst[256], m[200];
    const char *base;
    size_t n, i, len = 0;
    int k;
    char *d;
    static lg_conf c;

    prompt(" path of the .conf to import (esc cancels): ", path, sizeof path);
    if (!path[0]) return;
    base = strrchr(path, '/');
    base = base ? base + 1 : path;
    n = strlen(base);
    if (n < 6 || strcmp(base + n - 5, ".conf") != 0) { msg(2, "Only .conf files can be imported."); return; }
    n -= 5;
    if (n > NAME_MAX_LEN - 3) n = NAME_MAX_LEN - 3;   /* room for -2 .. -99 */
    for (i = 0; i < n; i++) {
        char ch = base[i];
        name[i] = (isalnum((unsigned char)ch) || ch == '_' || ch == '.' || ch == '-') ? ch : '-';
    }
    name[n] = 0;
    d = read_file(path, &len);
    if (!d) { snprintf(m, sizeof m, "Could not read that file: %s", strerror(errno)); msg(2, m); return; }
    lg_conf_parse(&c, d, len);
    k = c.priv[0] != 0;
    lg_wipe(&c, sizeof c);
    if (!k) { free_secret(d, len); msg(2, "That file is not a WireGuard config (it has no PrivateKey)."); return; }
    snprintf(try_, sizeof try_, "%s", name);
    for (k = 2; k < 100; k++) {
        conf_path(try_, dst, sizeof dst);
        if (access(dst, F_OK) != 0) break;
        snprintf(try_, sizeof try_, "%s-%d", name, k);
    }
    if (!write_conf(try_, d, len)) {
        free_secret(d, len);
        snprintf(m, sizeof m, "Could not write the config file: %s", strerror(errno));
        msg(2, m);
        return;
    }
    free_secret(d, len);
    load_tunnels();
    if (!leave_current()) {
        snprintf(m, sizeof m, "Imported %s. Your open changes are not saved yet: fix the marked field.", try_);
        msg(2, m);
        return;
    }
    load_tunnels();
    load_form(try_);
    if (strcmp(try_, name) != 0) snprintf(m, sizeof m, "Imported as %s (the name was taken). The original file was not changed.", try_);
    else snprintf(m, sizeof m, "Imported %s. The original file was not changed.", try_);
    msg(0, m);
}

/* osc 52: the public key only; the private key never goes to the clipboard */
static void copy_pub(void)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n, i;
    if (!g_pubok) return;
    n = strlen(g_pub);
    fputs("\033]52;c;", stdout);
    for (i = 0; i < n; i += 3) {
        unsigned v = (unsigned)(unsigned char)g_pub[i] << 16;
        if (i + 1 < n) v |= (unsigned)(unsigned char)g_pub[i + 1] << 8;
        if (i + 2 < n) v |= (unsigned char)g_pub[i + 2];
        fputc(T[(v >> 18) & 63], stdout);
        fputc(T[(v >> 12) & 63], stdout);
        fputc(i + 1 < n ? T[(v >> 6) & 63] : '=', stdout);
        fputc(i + 2 < n ? T[v & 63] : '=', stdout);
    }
    fputc('\007', stdout);
    fflush(stdout);
    g_copied = 1;
    g_touched = 1;
}

/* inline edit of one text field on the form */
static void edit_field(int f)
{
    char backup[520];
    int k;
    if (g_multi) { msg(0, "This config has several peers: edit the file by hand."); return; }
    if (f == F_NAME && name_locked()) { msg(0, "Disconnect and turn off Start at boot to rename."); return; }
    memcpy(backup, fv[f], sizeof backup);
    g_editing = f;
    for (;;) {
        size_t n = strlen(fv[f]);
        draw();
        k = get_key(-1);
        if (k == K_ENTER) break;
        if (k == K_ESC) { memcpy(fv[f], backup, sizeof backup); break; }
        if (k == K_BS && n) fv[f][n - 1] = 0;
        else if (k >= 32 && k < 127 && n < f_max[f]) { fv[f][n] = (char)k; fv[f][n + 1] = 0; }
    }
    g_editing = -1;
    trim(fv[f]);
    if (strcmp(backup, fv[f]) != 0) {
        g_dirty = g_touched = 1;
        g_armleave = g_armquit = 0;
        g_msg[0] = 0;
        if (f == F_PRIV) update_pub();
        if (fv[f][0]) validate(0, f); else ferr[f][0] = 0;
    }
    lg_wipe(backup, sizeof backup);
}

/* ---------- drawing ---------- */
static const char *state_text(int st)
{
    return st == 2 ? "connected" : st == 1 ? "connecting" : st == 3 ? "disconnecting" : st == 4 ? "failed" : "";
}

static void dot(int st, int sel)
{
    if (sel) fputs(st == 2 ? "\xe2\x97\x8f" : "\xe2\x97\x8b", stdout);              /* on the accent row: filled / hollow */
    else if (st == 2) fputs(C_ACC "\xe2\x97\x8f" C_RST, stdout);                     /* accent = connected */
    else if (st == 1 || st == 3) fputs(C_ACC "\xe2\x97\x8b" C_RST, stdout);
    else fputs(C_DIM "\xe2\x97\x8f" C_RST, stdout);                                  /* grey = off */
}

static void draw_list(int r0, int c0, int h, int w)
{
    int n = g_n + (g_selk == 2), sel = sel_index(), rows = h, i;
    if (n == 0) {
        at(r0 + h / 2 - 1, c0 + 1);
        fputs(C_DIM, stdout);
        put_w("No tunnels yet.", w - 2, 0);
        at(r0 + h / 2, c0 + 1);
        put_w("Press i to import a .conf", w - 2, 0);
        at(r0 + h / 2 + 1, c0 + 1);
        put_w("or n for New.", w - 2, 0);
        fputs(C_RST, stdout);
        return;
    }
    if (sel >= 0) {
        if (sel < g_top) g_top = sel;
        if (sel >= g_top + rows) g_top = sel - rows + 1;
    }
    if (g_top > n - rows) g_top = n - rows;
    if (g_top < 0) g_top = 0;
    for (i = g_top; i < n && i < g_top + rows; i++) {
        const char *name = i < g_n ? g_t[i].name : (fv[F_NAME][0] ? fv[F_NAME] : "new tunnel");
        const char *st = i < g_n ? state_text(g_t[i].st) : "not saved";
        int s = i < g_n ? g_t[i].st : 0, issel = i == sel, nw;
        at(r0 + i - g_top, c0);
        if (issel) fputs(g_focus == 0 ? C_SEL : C_SEL C_BOLD, stdout);
        fputs(" ", stdout);
        dot(s, issel);
        if (issel) fputs(C_SEL, stdout);
        fputs(" ", stdout);
        nw = w - 3 - (int)strlen(st) - 1;
        put_w(name, nw, 1);
        if (!issel) fputs(C_DIM, stdout);
        put_w(st, (int)strlen(st), 0);
        fputs(" " C_RST, stdout);
    }
}

/* label line (label left, error or hint right) and the value line below it */
static void draw_field(int f, int r, int c, int w)
{
    int cur = g_focus == 1 && g_item == f, vw = w - 2, n;
    const char *right = ferr[f][0] ? ferr[f] : f_hint[f];
    at(r, c);
    fputs(C_DIM, stdout);
    put_w(f_label[f], w, 0);
    fputs(C_RST, stdout);
    if (right) {
        n = (int)strlen(right);
        if (n < w - (int)strlen(f_label[f]) - 2) {
            at(r, c + w - n);
            fputs(ferr[f][0] ? C_ERR : C_DIM, stdout);
            fputs(right, stdout);
            fputs(C_RST, stdout);
        }
    }
    at(r + 1, c);
    fputs(cur ? (ferr[f][0] ? C_ERR "> " C_RST : C_BOLD "> " C_RST) : (ferr[f][0] ? C_ERR "! " C_RST : "  "), stdout);
    if ((f == F_PRIV || f == F_PSK) && !g_show && fv[f][0]) {
        n = (int)strlen(fv[f]);
        rep("*", n < vw ? n : vw);
    } else if (fv[f][0] || g_editing == f) {
        n = (int)strlen(fv[f]);
        put_w(n > vw - 1 && g_editing == f ? fv[f] + n - (vw - 1) : fv[f], vw - 1, 0);   /* show the end while typing */
    } else if (f_cue[f]) {
        fputs(C_DIM, stdout);
        put_w(f_cue[f], vw, 0);
        fputs(C_RST, stdout);
    }
    if (g_editing == f) fputs(C_ACC "_" C_RST, stdout);
}

static void draw_check(int f, int on, int r, int c, int w)
{
    int cur = g_focus == 1 && g_item == f;
    at(r, c);
    fputs(cur ? C_BOLD "> " C_RST : "  ", stdout);
    fputs(on ? C_ACC "[x]" C_RST " " : "[ ] ", stdout);
    put_w(f_label[f], w - 6, 0);
}

static void draw_status(int r, int c, int w)
{
    Tun *t = cur_tun();
    int st = t ? t->st : 0;
    at(r, c);
    if (g_msg[0]) {
        fputs(g_msgk == 2 ? C_ERR : g_msgk == 1 ? "" : C_DIM, stdout);
        put_w(g_msg, w, 0);
    } else if (g_selk == 2) {
        fputs(C_DIM, stdout);
        put_w("Not saved yet.", w, 0);
    } else if (!g_have_wg) {
        fputs(C_DIM, stdout);
        put_w("Connecting needs wireguard-tools.", w, 0);
    } else {
        dot(st, 0);
        fputs(" ", stdout);
        if (!st) fputs(C_DIM, stdout);
        put_w(st == 2 ? "Connected." : st == 1 ? "Connecting..." : st == 3 ? "Disconnecting..." : st == 4 ? "Failed, see journalctl." :
              (t && t->boot) ? "Not connected. Starts at boot." : "Not connected.", w - 2, 0);
    }
    fputs(C_RST, stdout);
}

static void draw(void)
{
    int top = 2, bottom, lw, rx, rw, kh = 4, sh, cx, cw, r, f, avail, compact;
    Tun *t;
    term_size();
    fputs("\033[H\033[2J", stdout);
    at(1, (g_cols - 10) / 2 + 1);
    fputs(C_BOLD "light" C_ACC "guard" C_RST, stdout);
    if (!g_have_wg) {
        at(2, 2);
        fputs(C_ERR, stdout);
        put_w("WireGuard is not installed. You can set up tunnels now; connecting needs wireguard-tools.", g_cols - 2, 0);
        fputs(C_RST, stdout);
        top = 3;
    }
    bottom = g_rows - 1;   /* last row: key hints */
    lw = g_cols * 30 / 100;
    if (lw < 22) lw = 22;
    if (lw > 32) lw = 32;

    /* tunnels */
    box(top, 1, bottom - top + 1, lw, "Tunnels");
    draw_list(top + 1, 2, bottom - top - 3, lw - 2);
    at(bottom - 1, 3);
    put_w("[i] Import .conf  [n] New", lw - 4, 0);

    /* your key */
    rx = lw + 2;
    rw = g_cols - rx + 1;
    box(bottom - kh + 1, rx, kh, rw, "Your key");
    cx = rx + 2;
    cw = rw - 4;
    if (!g_selk) {
        at(bottom - kh + 2, cx);
        fputs(C_DIM, stdout);
        put_w("Your public key shows here.", cw, 0);
        fputs(C_RST, stdout);
    } else {
        at(bottom - kh + 2, cx);
        put_w(g_pubok ? g_pub : "", cw - 10, 1);
        fputs(g_pubok ? " [y] Copy" : "", stdout);
        at(bottom - kh + 3, cx);
        fputs(g_copied ? "" : C_DIM, stdout);
        put_w(!g_pubok ? "No valid private key: make one under Advanced." :
              g_copied ? "Copied. Send this to your friend." : "Send this to your friend.", cw, 0);
        fputs(C_RST, stdout);
    }

    /* setup, with the tabs in its top edge */
    sh = bottom - kh - top + 1;
    box(top, rx, sh, rw, g_selk ? NULL : "Setup");
    if (g_selk) {
        at(top, rx + 2);
        fputs(g_tab == 0 ? C_BOLD " Setup " C_RST : C_DIM " Setup " C_RST, stdout);
        fputs(g_tab == 1 ? C_BOLD " Advanced " C_RST : C_DIM " Advanced " C_RST, stdout);
        fputs(C_DIM "(a)" C_RST, stdout);
    }
    avail = sh - 2;
    r = top + 1;
    if (!g_selk) {
        at(top + sh / 2 - 1, cx);
        fputs(C_DIM, stdout);
        put_w(g_n ? "Pick a tunnel on the left, or press New." : "Press New to make your first tunnel.", cw, 0);
        fputs(C_RST, stdout);
        if (g_msg[0]) { at(top + sh / 2 + 1, cx); fputs(g_msgk == 2 ? C_ERR : C_DIM, stdout); put_w(g_msg, cw, 0); fputs(C_RST, stdout); }
    } else if (g_tab == 0) {
        t = cur_tun();
        compact = avail < 15;
        for (f = F_NAME; f <= F_ALLOWED; f++, r += 2) draw_field(f, r, cx, cw);
        if (compact) {
            draw_check(F_KEEP, f_keep, r, cx, cw / 2);
            draw_check(F_BOOT, t && t->boot, r, cx + cw / 2, cw - cw / 2);
            r++;
        } else {
            draw_check(F_KEEP, f_keep, r++, cx, cw);
            draw_check(F_BOOT, t && t->boot, r++, cx, cw);
        }
        if (avail > 15) r++;
        at(r, cx);
        fputs(g_dirty && !g_multi ? "[s] Save" : C_DIM "[s] Save" C_RST, stdout);
        fputs("   ", stdout);
        if (!g_have_wg) fputs(C_DIM "[c] Connect" C_RST, stdout);
        else if (t && (t->st == 1 || t->st == 2)) fputs("[c] Disconnect", stdout);
        else fputs(C_SEL " [c] Connect " C_RST, stdout);   /* the primary action */
        draw_status(r + 1, cx, cw);
    } else {
        char info[300];
        draw_field(F_PRIV, r, cx, cw);
        at(r + 2, cx + 2);
        fputs(g_show ? "[v] Hide" : "[v] Show", stdout);
        fputs("  [g] New key", stdout);
        draw_field(F_PSK, r + 3, cx, cw);
        at(r + 5, cx + 2);
        fputs("[p] Generate", stdout);
        at(r + 7, cx);
        fputs(C_DIM, stdout);
        if (g_selk == 2) snprintf(info, sizeof info, "Not saved yet.");
        else snprintf(info, sizeof info, "Saved as " CONFDIR "/%s.conf", g_cur);
        put_w(info, cw, 0);
        at(r + 8, cx);
        put_w("Other settings in the file, like DNS or MTU, are kept as they are.", cw, 0);
        fputs(C_RST, stdout);
        at(r + 10, cx);
        if (g_armdel) fputs(C_ERR, stdout);
        fputs(g_armdel ? "[d] Press again to delete" : g_selk == 2 ? "[d] Discard new tunnel" : "[d] Delete tunnel", stdout);
        fputs(C_RST, stdout);
        draw_status(r + 12 < top + sh - 1 ? r + 12 : top + sh - 2, cx, cw);
    }

    /* key hints */
    at(g_rows, 1);
    fputs(C_DIM, stdout);
    if (g_editing >= 0) put_w(" type, enter accepts, esc undoes", g_cols - 1, 0);
    else if (g_focus == 0) put_w(" up/down pick  enter connect  n new  i import  d delete  tab setup  q quit", g_cols - 1, 0);
    else put_w(" up/down move  enter edit  space toggle  s save  c connect  a advanced  y copy key  esc tunnels  q quit",
               g_cols - 1, 0);
    fputs(C_RST, stdout);
    fflush(stdout);
}

/* ---------- main loop ---------- */
static int have_wg_quick(void)
{
    static const char *p[] = { "/usr/bin/wg-quick", "/usr/sbin/wg-quick", "/bin/wg-quick", "/usr/local/bin/wg-quick" };
    size_t i;
    for (i = 0; i < sizeof p / sizeof p[0]; i++) if (access(p[i], X_OK) == 0) return 1;
    return 0;
}

static void st_out(const char *s) { fputs(s, stdout); }

static int try_quit(void)
{
    if (g_selk == 2 && !g_touched) return 1;
    if (g_dirty && !g_armquit && !form_save(0)) {
        g_armquit = 1;
        msg(2, "Not saved: fix the marked field, or press q again to throw the changes away.");
        return 0;
    }
    return 1;
}

static void form_key(int k)
{
    int first = g_tab == 0 ? F_NAME : F_PRIV, last = g_tab == 0 ? F_BOOT : F_PSK;
    if (g_item < first || g_item > last) g_item = first;
    if (k == K_UP || k == 'k') g_item = g_item > first ? g_item - 1 : last;
    else if (k == K_DOWN || k == 'j') g_item = g_item < last ? g_item + 1 : first;
    else if (k == K_ESC) g_focus = 0;
    else if (k == K_ENTER || k == ' ') {
        if (g_item == F_KEEP) { if (!g_multi) { f_keep = !f_keep; g_dirty = g_touched = 1; } }
        else if (g_item == F_BOOT) do_boot();
        else if (k == K_ENTER) edit_field(g_item);
    }
}

int main(int argc, char **argv)
{
    int quit = 0;
    struct rlimit nocore = { 0, 0 };
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0) {
        int f = lg_selftest(st_out);
        puts(f ? "selftest FAILED" : "selftest passed");
        return f ? 1 : 0;
    }
    if (argc > 1) { fputs("usage: lightguard [--selftest]\n", stderr); return 2; }
    if (geteuid() != 0) {
        fputs("lightguard needs root, because the configs in " CONFDIR " are readable by root only.\n"
              "run it with sudo.\n", stderr);
        return 1;
    }
    /* no core dumps that could carry keys */
    setrlimit(RLIMIT_CORE, &nocore);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (!term_raw()) { fputs("lightguard needs an interactive terminal\n", stderr); return 1; }
    umask(077);
    tighten_perms();
    g_have_wg = have_wg_quick();
    load_tunnels();
    if (g_n > 0) load_form(g_t[0].name);

    while (!quit) {
        int k, i;
        draw();
        k = get_key(2000);
        if (k == K_NONE) { load_tunnels(); continue; }
        if (k != 'd') g_armdel = 0;
        if (k != 'q' && k != K_ESC) g_armquit = 0;
        if (k != K_UP && k != K_DOWN && k != 'k' && k != 'j' && k != 'q') g_msg[0] = 0;
        if (k == K_TAB) { if (g_selk) g_focus = !g_focus; continue; }
        if (k == 'q' || (k == K_ESC && g_focus == 0)) { if (try_quit()) quit = 1; continue; }
        if (k == 'n') { do_new(); continue; }
        if (k == 'i') { do_import(); continue; }
        if (!g_selk) {
            if (g_n > 0 && (k == K_UP || k == K_DOWN || k == 'j' || k == 'k')) select_row(0);
            continue;
        }
        switch (k) {
        case 's': if (!g_dirty && g_selk == 1) msg(0, "Nothing changed."); else form_save(0); continue;
        case 'c': do_connect(); continue;
        case 'y': copy_pub(); continue;
        case 'd': do_delete(); continue;
        case 'a': g_tab = !g_tab; g_focus = 1; g_item = g_tab ? F_PRIV : F_NAME; continue;
        case 'v': if (g_tab == 1) g_show = !g_show; continue;
        case 'g': if (g_tab == 1 && !g_multi && gen_key(F_PRIV)) { g_dirty = g_touched = 1; msg(0, "New key made. Send the new public key to your friend, then Save."); } continue;
        case 'p': if (g_tab == 1 && !g_multi && gen_key(F_PSK)) { g_dirty = g_touched = 1; msg(0, "Preshared key made. Your friend needs the same one: press v to read it."); } continue;
        }
        if (g_focus == 1) { form_key(k); continue; }
        i = g_selk == 2 ? g_n : sel_index();
        if (k == K_UP || k == 'k') select_row(i - 1);
        else if (k == K_DOWN || k == 'j') select_row(i + 1);
        else if (k == K_ENTER) do_connect();
        else if (k == K_RIGHT) g_focus = 1;
    }
    wipe_form();
    term_restore();
    return 0;
}
