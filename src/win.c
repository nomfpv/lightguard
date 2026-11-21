/* lightguard for windows: the window (ui only). logic lives in wincore.c, config text and keys in lgcore.c.
   everything is owner drawn; the window only paints in response to input or a state change. */
#include "wincore.h"
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <dwmapi.h>
#include "lgcore.h"

#ifndef WM_COPYGLOBALDATA
#define WM_COPYGLOBALDATA 0x0049
#endif
#define DWMA_DARK 20
#define DWMA_CORNER 33
#define DWMA_BORDER 34

#define APPNAME L"lightguard"
#define MAX_TUN 256

/* layout in pixels at 100%, on the grid of the 13 px font; scaled by whole multiples only */
#define TITLE_H 24
#define PAD 6
#define HDR 20
#define IP 8
#define LBL 16
#define FH 20
#define PITCH 38
#define ROW_H 20
#define BTN_H 20
#define CONN_H 26
#define BANNER_H 32
#define KEY_H 70
#define SETUP_H 300

#define XL(l) ((int)(short)LOWORD(l))
#define YL(l) ((int)(short)HIWORD(l))

/* ---------- state ---------- */
static HINSTANCE g_inst;
static HWND g_main, g_list;
static UINT g_dpi = 96;
static int g_dark;
static HFONT f_ui, f_title, f_mono;
static int g_lh, g_lhm;

typedef struct {
    COLORREF win, panel, field, border, text, dim, accent, danger, onacc, hover;
    COLORREF btop, bbot, htop, hbot, dtop, dbot, bline, hline;
    COLORREF ptop, pbot, phtop, phbot, pdtop, pdbot, pline;
} Pal;
static Pal C;
static HBRUSH br_field, br_panel;

/* whole-number scale so the pixel font and the 1 px lines stay crisp: 100% -> 1, 150% and 200% -> 2, ... */
static int scale(void) { int k = ((int)g_dpi + 48) / 96; return k < 1 ? 1 : k; }
static int S(int v) { return v * scale(); }

/* fields */
enum { F_NAME, F_ADDR, F_ENDP, F_PEER, F_ALLOWED, F_PRIV, F_PSK, F_DNS, F_PUB, NF };
typedef struct { const wchar_t *label, *cue, *hint; int tab, max, mono; } FieldDef;
static const FieldDef FD[NF] = {
    { L"Name", L"home", NULL, 0, NAME_MAX_LEN, 0 },
    { L"Your address", L"10.66.66.2/24", NULL, 0, 255, 0 },
    { L"Friend's server", L"host:port", L"optional", 0, 255, 0 },
    { L"Friend's public key", L"44 characters, ends with =", NULL, 0, 63, 1 },
    { L"Networks to reach", L"192.168.50.0/24, comma-separated", NULL, 0, 511, 0 },
    { L"Your private key", NULL, L"never share this", 1, 63, 1 },
    { L"Preshared key", L"optional", L"both sides need the same one", 1, 63, 1 },
    { L"DNS servers", L"empty = keep the normal DNS", L"optional", 1, 255, 0 },
    { NULL, NULL, NULL, 2, 63, 1 },
};
static HWND fe[NF];
static RECT fr[NF], flr[NF];
static wchar_t ferr[NF][96];

/* buttons, all owner drawn */
enum { BK_NORMAL, BK_PRIMARY, BK_DANGER, BK_CHECK, BK_TITLE, BK_CLOSE };
enum { B_IMPORT, B_NEW, B_KEEP, B_BOOT, B_SAVE, B_CONN, B_SHOW, B_NEWKEY, B_GENPSK, B_DELETE, B_COPY, B_INSTALL, B_MIN, B_CLOSE, NB };
typedef struct { int kind, hover, checked; } Btn;
static const struct { const wchar_t *text; int kind; } BD[NB] = {
    { L"Import .conf", BK_NORMAL }, { L"New", BK_NORMAL },
    { L"Keep connection alive", BK_CHECK }, { L"Start with Windows", BK_CHECK },
    { L"Save", BK_NORMAL }, { L"Connect", BK_PRIMARY },
    { L"Show", BK_NORMAL }, { L"New key", BK_NORMAL }, { L"Generate", BK_NORMAL },
    { L"Delete tunnel", BK_DANGER }, { L"Copy", BK_NORMAL },
    { L"Install WireGuard", BK_NORMAL }, { L"", BK_TITLE }, { L"", BK_CLOSE },
};
static HWND bh[NB];
static Btn bi[NB];
enum { ID_LIST = 99, ID_BTN = 100, ID_EDIT = 200 };

/* tunnels on disk + their service state */
typedef struct { wchar_t name[NAME_MAX_LEN + 1]; int st, installed, boot; } Tun;   /* st: 0 off 1 connecting 2 connected 3 disconnecting */
static Tun g_t[MAX_TUN], g_nt[MAX_TUN];
static int g_n;

/* what the right side shows: 0 nothing, 1 saved tunnel g_cur, 2 a new unsaved tunnel */
static int g_selk;
static wchar_t g_cur[NAME_MAX_LEN + 1];
static lg_conf g_conf;
static int g_dirty, g_touched, g_multi, g_loading, g_tab, g_showkey, g_pubok, g_copied;
static int g_armdel, g_armleave, g_armclose, g_busy, g_hovtab = -1, g_tracking;
static wchar_t g_msg[200];
static int g_msgk;   /* 0 dim, 1 text, 2 danger */
static DWORD g_fast_since;

/* layout */
static RECT r_title, r_banner, r_left, r_listbox, r_setup, r_tab[2], r_key, r_status, r_advinfo, r_keyhint;
static int g_banner;

/* ---------- small drawing helpers ---------- */
static COLORREF mix(COLORREF a, COLORREF b, int t)   /* t/255 of b */
{
    int r = GetRValue(a) + (GetRValue(b) - GetRValue(a)) * t / 255;
    int g = GetGValue(a) + (GetGValue(b) - GetGValue(a)) * t / 255;
    int bl = GetBValue(a) + (GetBValue(b) - GetBValue(a)) * t / 255;
    return RGB(r, g, bl);
}

static void fillr(HDC dc, const RECT *r, COLORREF c)
{
    SetDCBrushColor(dc, c);
    FillRect(dc, r, (HBRUSH)GetStockObject(DC_BRUSH));
}

static void fill4(HDC dc, int l, int t, int r, int b, COLORREF c)
{
    RECT x;
    SetRect(&x, l, t, r, b);
    fillr(dc, &x, c);
}

static void frame(HDC dc, const RECT *r, COLORREF c)
{
    fill4(dc, r->left, r->top, r->right, r->top + 1, c);
    fill4(dc, r->left, r->bottom - 1, r->right, r->bottom, c);
    fill4(dc, r->left, r->top, r->left + 1, r->bottom, c);
    fill4(dc, r->right - 1, r->top, r->right, r->bottom, c);
}

static void vgrad(HDC dc, const RECT *r, COLORREF a, COLORREF b)
{
    int h = r->bottom - r->top, y;
    for (y = 0; y < h; y++)
        fill4(dc, r->left, r->top + y, r->right, r->top + y + 1, mix(a, b, h > 1 ? y * 255 / (h - 1) : 0));
}

static void txt(HDC dc, const wchar_t *s, const RECT *r, COLORREF c, HFONT f, UINT fl)
{
    RECT x = *r;
    SelectObject(dc, f);
    SetTextColor(dc, c);
    SetBkMode(dc, TRANSPARENT);
    DrawTextW(dc, s, -1, &x, fl | DT_NOPREFIX);
}

/* anti-aliased dot or ring; centre and radius in 1/8 px, 4x4 samples per pixel */
static void dot(HDC dc, int cx, int cy, int r, int ring, COLORREF col, COLORREF bg)
{
    int x, y, i, j, n;
    long rr = (long)r * r, ri = (long)(r - ring) * (r - ring);
    for (y = (cy - r) / 8 - 1; y <= (cy + r) / 8 + 1; y++)
        for (x = (cx - r) / 8 - 1; x <= (cx + r) / 8 + 1; x++) {
            n = 0;
            for (i = 0; i < 4; i++)
                for (j = 0; j < 4; j++) {
                    long sx = x * 8 + j * 2 + 1 - cx, sy = y * 8 + i * 2 + 1 - cy, d = sx * sx + sy * sy;
                    if (d <= rr && (!ring || d >= ri)) n++;
                }
            if (n) SetPixelV(dc, x, y, mix(bg, col, n * 255 / 16));
        }
}

static void inval(void) { if (g_main) InvalidateRect(g_main, NULL, FALSE); }

/* ---------- theme and fonts ---------- */
static int sys_dark(void)
{
    DWORD v = 1, sz = sizeof v;
    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                     L"AppsUseLightTheme", RRF_RT_REG_DWORD, NULL, &v, &sz) != ERROR_SUCCESS) return 0;
    return v == 0;
}

static void make_colors(void)
{
    COLORREF w = RGB(255, 255, 255), k = RGB(0, 0, 0);
    g_dark = sys_dark();
    if (g_dark) {
        C.win = RGB(0x16, 0x18, 0x1c); C.panel = RGB(0x1e, 0x21, 0x26); C.field = RGB(0x14, 0x16, 0x1a);
        C.border = RGB(0x2f, 0x34, 0x3c); C.text = RGB(0xe8, 0xea, 0xed); C.dim = RGB(0x9a, 0xa1, 0xab);
        C.accent = RGB(0x4f, 0xb8, 0xa5); C.danger = RGB(0xe0, 0x67, 0x5f); C.onacc = C.win;
        C.btop = RGB(0x2b, 0x2f, 0x36); C.bbot = RGB(0x24, 0x28, 0x2e);
        C.htop = RGB(0x34, 0x39, 0x41); C.hbot = RGB(0x2c, 0x30, 0x37);
        C.dtop = RGB(0x1b, 0x1e, 0x22); C.dbot = RGB(0x21, 0x24, 0x29);
        C.bline = RGB(0x3a, 0x40, 0x49); C.hline = RGB(0x50, 0x57, 0x62);
        C.ptop = mix(C.accent, w, 20); C.pbot = C.accent;
        C.phtop = mix(C.accent, w, 45); C.phbot = mix(C.accent, w, 20);
        C.pdtop = mix(C.accent, k, 40); C.pdbot = mix(C.accent, k, 20);
        C.pline = mix(C.accent, k, 70);
        C.hover = mix(C.field, C.text, 16);
    } else {
        C.win = RGB(0xe7, 0xe9, 0xec); C.panel = RGB(0xf6, 0xf7, 0xf8); C.field = RGB(0xff, 0xff, 0xff);
        C.border = RGB(0xc3, 0xc8, 0xd0); C.text = RGB(0x1c, 0x20, 0x26); C.dim = RGB(0x5c, 0x65, 0x70);
        C.accent = RGB(0x1f, 0x7a, 0x6b); C.danger = RGB(0xb4, 0x36, 0x2f); C.onacc = w;
        C.btop = w; C.bbot = RGB(0xec, 0xee, 0xf1);
        C.htop = w; C.hbot = RGB(0xf5, 0xf6, 0xf8);
        C.dtop = RGB(0xe0, 0xe3, 0xe7); C.dbot = RGB(0xe9, 0xeb, 0xee);
        C.bline = RGB(0xb4, 0xba, 0xc3); C.hline = RGB(0x8c, 0x94, 0xa0);
        C.ptop = C.accent; C.pbot = mix(C.accent, k, 25);
        C.phtop = mix(C.accent, w, 10); C.phbot = C.accent;
        C.pdtop = mix(C.accent, k, 45); C.pdbot = mix(C.accent, k, 25);
        C.pline = mix(C.accent, k, 60);
        C.hover = mix(C.field, C.text, 12);
    }
    if (br_field) DeleteObject(br_field);
    if (br_panel) DeleteObject(br_panel);
    br_field = CreateSolidBrush(C.field);
    br_panel = CreateSolidBrush(C.panel);
}

static void apply_dwm(HWND w)
{
    BOOL d = g_dark;
    DWORD corner = 1;                 /* square corners */
    COLORREF none = 0xFFFFFFFE;       /* we draw the border ourselves */
    DwmSetWindowAttribute(w, DWMA_DARK, &d, sizeof d);
    DwmSetWindowAttribute(w, DWMA_CORNER, &corner, sizeof corner);
    DwmSetWindowAttribute(w, DWMA_BORDER, &none, sizeof none);
}

/* ProggyClean is embedded as RCDATA 1 and added for this process only; nothing is installed */
static int g_proggy;
static void load_font(void)
{
    HRSRC r = FindResourceW(NULL, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(10) /* RT_RCDATA */);
    HGLOBAL g = r ? LoadResource(NULL, r) : NULL;
    void *p = g ? LockResource(g) : NULL;
    DWORD n = 0;
    if (p && AddFontMemResourceEx(p, SizeofResource(NULL, r), NULL, &n) && n) g_proggy = 1;
}

static HFONT mkfont_face(const wchar_t *face, int h, int weight, DWORD quality)
{
    LOGFONTW lf;
    HFONT f;
    HDC dc;
    wchar_t got[LF_FACESIZE];
    memset(&lf, 0, sizeof lf);
    lf.lfHeight = h;   /* > 0: cell height, < 0: em height */
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfOutPrecision = OUT_TT_ONLY_PRECIS;
    lf.lfQuality = (BYTE)quality;
    lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
    lstrcpyW(lf.lfFaceName, face);
    f = CreateFontIndirectW(&lf);
    if (!f) return NULL;
    dc = GetDC(NULL);   /* make sure the face really exists and was not substituted */
    SelectObject(dc, f);
    got[0] = 0;
    GetTextFaceW(dc, LF_FACESIZE, got);
    SelectObject(dc, GetStockObject(SYSTEM_FONT));
    ReleaseDC(NULL, dc);
    if (lstrcmpiW(got, face) != 0) { DeleteObject(f); return NULL; }
    return f;
}

/* the 13 px pixel font (measured against the design reference: same widths to the pixel),
   or Consolas, then Tahoma when it cannot be loaded */
static HFONT mkfont(int weight)
{
    HFONT f = NULL;
    if (g_proggy) f = mkfont_face(L"ProggyCleanTT", 13 * scale(), weight, NONANTIALIASED_QUALITY);   /* 13 px cell, 7 px per char */
    if (!f) f = mkfont_face(L"Consolas", -MulDiv(12, (int)g_dpi, 96), weight, CLEARTYPE_QUALITY);
    if (!f) f = mkfont_face(L"Tahoma", -MulDiv(11, (int)g_dpi, 96), weight, CLEARTYPE_QUALITY);
    if (!f) f = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    return f;
}

static int font_h(HFONT f)
{
    HDC dc = GetDC(NULL);
    TEXTMETRICW tm;
    HGDIOBJ o = SelectObject(dc, f);
    GetTextMetricsW(dc, &tm);
    SelectObject(dc, o);
    ReleaseDC(NULL, dc);
    return tm.tmHeight;
}

static void make_fonts(void)
{
    int i;
    if (f_ui) DeleteObject(f_ui);       /* deleting a stock object is a harmless no-op */
    if (f_title) DeleteObject(f_title);
    f_ui = mkfont(FW_NORMAL);
    f_title = mkfont(FW_BOLD);
    f_mono = f_ui;                      /* one monospaced font for everything */
    g_lh = font_h(f_ui);
    g_lhm = font_h(f_mono);
    for (i = 0; i < NF; i++) if (fe[i]) SendMessageW(fe[i], WM_SETFONT, (WPARAM)(FD[i].mono ? f_mono : f_ui), FALSE);
}

/* ---------- text helpers ---------- */
static void gettext_u(HWND h, char *o, int cap)
{
    wchar_t w[600];
    int n, s = 0;
    GetWindowTextW(h, w, 600);
    w2u(w, o, cap);
    SecureZeroMemory(w, sizeof w);
    n = lstrlenA(o);
    while (n > 0 && (o[n - 1] == ' ' || o[n - 1] == '\t')) o[--n] = 0;
    while (o[s] == ' ' || o[s] == '\t') s++;
    if (s) { memcpy(o, o + s, (size_t)(n - s + 1)); SecureZeroMemory(o + n - s + 1, (size_t)s); }
}

static void settext_u(HWND h, const char *u)
{
    wchar_t w[600];
    u2w(u, w, 600);
    SetWindowTextW(h, w);
    SecureZeroMemory(w, sizeof w);
}

static void set_text(HWND h, const wchar_t *s)
{
    wchar_t cur[64];
    GetWindowTextW(h, cur, 64);
    if (lstrcmpW(cur, s) != 0) SetWindowTextW(h, s);
}

static void set_msg(int kind, const wchar_t *s)
{
    lstrcpynW(g_msg, s, 200);
    g_msgk = kind;
    inval();
}

/* ---------- clipboard (public key only) ---------- */
static void copy_text(HWND w, const wchar_t *t)
{
    SIZE_T n = ((SIZE_T)lstrlenW(t) + 1) * sizeof(wchar_t);
    HGLOBAL g = GlobalAlloc(GMEM_MOVEABLE, n);
    void *p;
    if (!g) return;
    p = GlobalLock(g);
    if (!p) { GlobalFree(g); return; }
    memcpy(p, t, n);
    GlobalUnlock(g);
    if (OpenClipboard(w)) {
        EmptyClipboard();
        if (!SetClipboardData(CF_UNICODETEXT, g)) GlobalFree(g);
        CloseClipboard();
    } else {
        GlobalFree(g);
    }
}

/* ---------- tunnels ---------- */
static Tun *cur_tun(void)
{
    int i;
    if (g_selk != 1) return NULL;
    for (i = 0; i < g_n; i++) if (lstrcmpiW(g_t[i].name, g_cur) == 0) return &g_t[i];
    return NULL;
}

static int sel_index(void)
{
    Tun *t;
    if (g_selk == 2) return g_n;
    t = cur_tun();
    return t ? (int)(t - g_t) : -1;
}

static int list_count(void) { return g_n + (g_selk == 2); }

static void update_controls(void);
static void show_controls(void);
static void list_show(int i);

/* rescans the folder and the services; repaints only when something changed */
static int rescan(void)
{
    WIN32_FIND_DATAW fd;
    wchar_t pat[MAX_PATH];
    HANDLE h;
    SC_HANDLE scm;
    int i, n = 0, changed, pending = 0;
    char u[160];

    wsprintfW(pat, L"%s\\*.conf", g_dir);
    h = FindFirstFileW(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            int l = lstrlenW(fd.cFileName) - 5;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (l < 1 || l > NAME_MAX_LEN || n >= MAX_TUN) continue;
            memset(&g_nt[n], 0, sizeof g_nt[n]);
            memcpy(g_nt[n].name, fd.cFileName, (size_t)l * sizeof(wchar_t));
            g_nt[n].name[l] = 0;
            w2u(g_nt[n].name, u, sizeof u);
            if (!lg_name_ok(u, NAME_MAX_LEN)) continue;
            n++;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    for (i = 1; i < n; i++) {   /* sort by name, few entries: insertion sort */
        int j = i;
        Tun tmp = g_nt[i];
        while (j > 0 && lstrcmpiW(g_nt[j - 1].name, tmp.name) > 0) { g_nt[j] = g_nt[j - 1]; j--; }
        g_nt[j] = tmp;
    }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    for (i = 0; i < n; i++) {
        SvcInfo si;
        if (scm) svc_info(scm, g_nt[i].name, &si); else memset(&si, 0, sizeof si);
        g_nt[i].installed = si.installed;
        g_nt[i].boot = si.autostart;
        g_nt[i].st = !si.installed ? 0 : si.state == SERVICE_RUNNING ? 2 : si.state == SERVICE_START_PENDING ? 1 :
                     si.state == SERVICE_STOP_PENDING ? 3 : 0;
        if (g_nt[i].st == 1 || g_nt[i].st == 3) pending = 1;
    }
    if (scm) CloseServiceHandle(scm);

    changed = n != g_n;
    for (i = 0; !changed && i < n; i++)
        if (lstrcmpW(g_nt[i].name, g_t[i].name) || g_nt[i].st != g_t[i].st ||
            g_nt[i].installed != g_t[i].installed || g_nt[i].boot != g_t[i].boot) changed = 1;
    if (changed) {
        memcpy(g_t, g_nt, (size_t)n * sizeof g_t[0]);
        g_n = n;
        if (g_selk == 1 && !cur_tun()) {   /* removed behind our back */
            g_selk = 0;
            g_dirty = 0;
            show_controls();
        }
        if (g_list) InvalidateRect(g_list, NULL, FALSE);
        update_controls();
        inval();
    }
    return pending;
}

/* ---------- form ---------- */
static void update_pub(void)
{
    char priv[80], b[45];
    lg_u8 k[32], p[32];
    gettext_u(fe[F_PRIV], priv, sizeof priv);
    g_pubok = lg_b64dec(priv, k);
    if (g_pubok) {
        lg_pubkey(p, k);
        lg_b64enc(b, p);
        settext_u(fe[F_PUB], b);
    } else {
        SetWindowTextW(fe[F_PUB], L"");
    }
    SecureZeroMemory(k, sizeof k);
    SecureZeroMemory(priv, sizeof priv);
    inval();
}

static void set_showkey(int on)
{
    WPARAM ch = on ? 0 : 0x25CF;
    g_showkey = on;
    SendMessageW(fe[F_PRIV], EM_SETPASSWORDCHAR, ch, 0);
    SendMessageW(fe[F_PSK], EM_SETPASSWORDCHAR, ch, 0);
    InvalidateRect(fe[F_PRIV], NULL, TRUE);
    InvalidateRect(fe[F_PSK], NULL, TRUE);
    SetWindowTextW(bh[B_SHOW], on ? L"Hide" : L"Show");
}

static void clear_form(void)
{
    int f;
    g_loading = 1;
    for (f = 0; f < NF; f++) { SetWindowTextW(fe[f], L""); ferr[f][0] = 0; }
    g_loading = 0;
    SecureZeroMemory(&g_conf, sizeof g_conf);
    g_dirty = g_touched = g_multi = g_copied = g_pubok = 0;
    g_armdel = g_armleave = g_armclose = 0;
    set_showkey(0);   /* secrets are masked again whenever the form changes hands */
}

static void fill_edits(void)
{
    g_loading = 1;
    settext_u(fe[F_ADDR], g_conf.address);
    settext_u(fe[F_ENDP], g_conf.endpoint);
    settext_u(fe[F_PEER], g_conf.peerpub);
    settext_u(fe[F_ALLOWED], g_conf.allowed);
    settext_u(fe[F_PRIV], g_conf.priv);
    settext_u(fe[F_PSK], g_conf.psk);
    settext_u(fe[F_DNS], g_conf.dns);
    bi[B_KEEP].checked = g_conf.keepalive[0] && lstrcmpA(g_conf.keepalive, "0") != 0;
    g_loading = 0;
    update_pub();
}

static void load_tunnel(const wchar_t *name)
{
    wchar_t path[MAX_PATH];
    DWORD len = 0;
    char *d;
    clear_form();
    g_selk = 1;
    g_tab = 0;
    lstrcpynW(g_cur, name, NAME_MAX_LEN + 1);
    conf_path(name, path);
    d = read_file(path, &len);
    if (d) {
        lg_conf_parse(&g_conf, d, len);
        SecureZeroMemory(d, len);
        HeapFree(GetProcessHeap(), 0, d);
    }
    g_loading = 1;
    SetWindowTextW(fe[F_NAME], name);
    g_loading = 0;
    fill_edits();
    g_multi = g_conf.npeers > 1;
    g_msg[0] = 0;
    if (!d) set_msg(2, L"Could not read this config file.");
    else if (g_multi) set_msg(0, L"This config has several peers: edit the file by hand. Connect still works.");
    show_controls();
    update_controls();
    list_show(sel_index());
    if (g_list) InvalidateRect(g_list, NULL, FALSE);
    inval();
}

static int gen_key(int f)
{
    lg_u8 k[32];
    char b[45];
    if (!random32(k)) { set_msg(2, L"The random number generator failed."); return 0; }
    if (f == F_PRIV) lg_clamp(k);
    lg_b64enc(b, k);
    settext_u(fe[f], b);
    SecureZeroMemory(k, sizeof k);
    SecureZeroMemory(b, sizeof b);
    return 1;
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
        else if (!((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
    }
}

static int endpoint_ok(const char *s)
{
    const char *c = NULL, *p;
    int n = 0;
    long port = 0;
    for (p = s; *p; p++) {
        if (*p == ':') c = p;
        if (*p == ' ') return 0;
    }
    if (!c || c == s) return 0;
    for (p = c + 1; *p; p++) {
        if (*p < '0' || *p > '9' || ++n > 5) return 0;
        port = port * 10 + (*p - '0');
    }
    return n > 0 && port > 0 && port < 65536;
}

static void key_err(const char *s, wchar_t *out)
{
    int n = lstrlenA(s);
    if (n != 44) wsprintfW(out, L"has %d characters, a key has 44", n);
    else lstrcpyW(out, L"not a valid key, check for typos");
}

/* checks the form; complete = also everything needed to connect. only = one field or -1.
   returns the first bad field or -1 */
static int validate(int complete, int only)
{
    char s[600], pub[45];
    wchar_t wn[40], path[MAX_PATH], e[96];
    lg_u8 k[32];
    int bad = -1, f;

#define BAD(F, M) do { if (only < 0 || only == (F)) { lstrcpynW(ferr[F], (M), 96); if (bad < 0) bad = (F); } } while (0)
    for (f = 0; f < NF; f++) if (only < 0 || only == f) ferr[f][0] = 0;
    if (g_multi) return -1;

    gettext_u(fe[F_NAME], s, sizeof s);
    if (!lg_name_ok(s, NAME_MAX_LEN)) BAD(F_NAME, L"1-32 letters, digits or _ = + . -");
    else {
        u2w(s, wn, 40);
        conf_path(wn, path);
        if ((g_selk == 2 || lstrcmpiW(wn, g_cur) != 0) && file_exists(path)) BAD(F_NAME, L"another tunnel has this name");
    }

    gettext_u(fe[F_ADDR], s, sizeof s);
    if (!s[0]) { if (complete) BAD(F_ADDR, L"needed to connect, e.g. 10.66.66.2/24"); }
    else if (!ip_list_ok(s)) BAD(F_ADDR, L"use an address like 10.66.66.2/24");

    gettext_u(fe[F_ENDP], s, sizeof s);
    if (s[0] && !endpoint_ok(s)) BAD(F_ENDP, L"use host:port, e.g. vpn.example.org:51820");

    gettext_u(fe[F_PUB], pub, sizeof pub);
    gettext_u(fe[F_PEER], s, sizeof s);
    if (!s[0]) { if (complete) BAD(F_PEER, L"needed, ask your friend for it"); }
    else if (!lg_b64dec(s, k)) { key_err(s, e); BAD(F_PEER, e); }
    else if (lstrcmpA(s, pub) == 0) BAD(F_PEER, L"this is your own key, paste your friend's");

    gettext_u(fe[F_ALLOWED], s, sizeof s);
    if (!s[0]) { if (complete) BAD(F_ALLOWED, L"needed to connect, e.g. 192.168.50.0/24"); }
    else if (!ip_list_ok(s)) BAD(F_ALLOWED, L"use networks like 192.168.50.0/24");

    gettext_u(fe[F_PRIV], s, sizeof s);
    if (!lg_b64dec(s, k)) BAD(F_PRIV, L"not a valid key, press New key");

    gettext_u(fe[F_PSK], s, sizeof s);
    if (s[0] && !lg_b64dec(s, k)) { key_err(s, e); BAD(F_PSK, e); }

    gettext_u(fe[F_DNS], s, sizeof s);
    if (s[0] && !ip_list_ok(s)) BAD(F_DNS, L"use addresses like 1.1.1.1, comma-separated");
#undef BAD
    SecureZeroMemory(s, sizeof s);
    SecureZeroMemory(k, sizeof k);
    return bad;
}

static void set_tab(int t)
{
    g_tab = t;
    g_armdel = 0;
    show_controls();
    update_controls();
    inval();
}

static void show_bad(int f, int complete)
{
    if (FD[f].tab < 2 && FD[f].tab != g_tab) set_tab(FD[f].tab);
    SetFocus(fe[f]);
    set_msg(2, complete ? L"Fill in the marked fields to connect." : L"Not saved: check the marked field.");
}

/* writes the form to <name>.conf. complete = also require what connecting needs */
static int form_save(int complete)
{
    static char out[8192];
    char nm[64];
    wchar_t wname[40], path[MAX_PATH], old[MAX_PATH];
    int n, bad, renamed;
    Tun *t;

    if (g_multi) return 1;   /* read only, nothing to write */
    bad = validate(complete, -1);
    if (bad >= 0) { show_bad(bad, complete); inval(); return 0; }

    gettext_u(fe[F_NAME], nm, sizeof nm);
    gettext_u(fe[F_ADDR], g_conf.address, sizeof g_conf.address);
    gettext_u(fe[F_ENDP], g_conf.endpoint, sizeof g_conf.endpoint);
    gettext_u(fe[F_PEER], g_conf.peerpub, sizeof g_conf.peerpub);
    gettext_u(fe[F_ALLOWED], g_conf.allowed, sizeof g_conf.allowed);
    gettext_u(fe[F_PRIV], g_conf.priv, sizeof g_conf.priv);
    gettext_u(fe[F_PSK], g_conf.psk, sizeof g_conf.psk);
    gettext_u(fe[F_DNS], g_conf.dns, sizeof g_conf.dns);
    if (bi[B_KEEP].checked) {
        if (!g_conf.keepalive[0] || lstrcmpA(g_conf.keepalive, "0") == 0) lstrcpyA(g_conf.keepalive, "25");
    } else {
        g_conf.keepalive[0] = 0;
    }

    u2w(nm, wname, 40);
    conf_path(wname, path);
    renamed = g_selk == 1 && lstrcmpW(wname, g_cur) != 0;
    n = lg_conf_format(&g_conf, out, sizeof out);
    if (n < 0) {
        lstrcpyW(ferr[F_ADDR], L"too long for a config file");
        show_bad(F_ADDR, 0);
        return 0;
    }
    if (!write_file(path, out, (DWORD)n)) {
        SecureZeroMemory(out, sizeof out);
        set_msg(2, L"Could not write the config file.");
        return 0;
    }
    SecureZeroMemory(out, sizeof out);
    if (renamed) {
        conf_path(g_cur, old);
        if (lstrcmpiW(wname, g_cur) != 0) DeleteFileW(old);
        else MoveFileW(old, path);   /* only the case changed */
    }
    g_selk = 1;
    lstrcpyW(g_cur, wname);
    g_dirty = 0;
    g_armleave = g_armclose = 0;
    rescan();
    t = cur_tun();
    set_msg(0, t && t->st ? L"Saved. Disconnect and connect again to use the changes." : L"Saved.");
    update_controls();
    list_show(sel_index());
    InvalidateRect(g_list, NULL, FALSE);
    return 1;
}

/* may the right side switch to something else? saves valid changes on the way */
static int leave_current(void)
{
    if (g_selk == 0) return 1;
    if (g_selk == 2 && !g_touched) { g_selk = 0; return 1; }   /* untouched new tunnel: just drop it */
    if (!g_dirty) return 1;
    if (g_armleave) { g_selk = g_selk == 2 ? 0 : g_selk; g_dirty = 0; return 1; }
    if (form_save(0)) return 1;
    g_armleave = 1;
    set_msg(2, L"Not saved: fix the marked field, or click again to throw the changes away.");
    return 0;
}

static void select_none(void)
{
    clear_form();
    g_selk = 0;
    g_cur[0] = 0;
    show_controls();
    update_controls();
    InvalidateRect(g_list, NULL, FALSE);
    inval();
}

static void select_row(int i)
{
    wchar_t name[NAME_MAX_LEN + 1];
    if (i == sel_index() || i < 0 || i >= g_n) return;
    lstrcpyW(name, g_t[i].name);
    if (!leave_current()) { InvalidateRect(g_list, NULL, FALSE); return; }
    rescan();
    load_tunnel(name);
}

/* ---------- actions ---------- */
static HWND g_busyfocus;
static void busy(int on)
{
    g_busy = on;
    if (on) g_busyfocus = GetFocus();
    EnableWindow(g_main, !on);
    SetCursor(LoadCursorW(NULL, on ? IDC_WAIT : IDC_ARROW));
    if (on) { inval(); UpdateWindow(g_main); }
    else if (g_busyfocus && IsWindowVisible(g_busyfocus)) SetFocus(g_busyfocus);
}

static void go_fast(void)
{
    g_fast_since = GetTickCount();
    SetTimer(g_main, 2, 500, NULL);
}

static void wg_error(int rc, wchar_t *out)
{
    if (rc == -1) lstrcpyW(out, L"Could not run wireguard.exe.");
    else wsprintfW(out, L"wireguard.exe failed (exit code %d). Check the fields and try again.", rc);
}

static void do_new(void)
{
    wchar_t nm[40], path[MAX_PATH];
    int i;
    if (g_selk == 2) { SetFocus(fe[F_NAME]); return; }
    if (!leave_current()) return;
    rescan();
    clear_form();
    g_selk = 2;
    g_cur[0] = 0;
    for (i = 1; i < 1000; i++) {
        wsprintfW(nm, L"tunnel%d", i);
        conf_path(nm, path);
        if (!file_exists(path)) break;
    }
    g_loading = 1;
    SetWindowTextW(fe[F_NAME], nm);
    bi[B_KEEP].checked = 1;
    gen_key(F_PRIV);   /* the keypair is made right away */
    g_loading = 0;
    update_pub();
    g_dirty = 1;
    g_tab = 0;
    set_msg(0, L"New tunnel. Send your key to your friend, fill in their details, then Save.");
    show_controls();
    update_controls();
    list_show(g_n);
    InvalidateRect(g_list, NULL, FALSE);
    SetFocus(fe[F_NAME]);
    SendMessageW(fe[F_NAME], EM_SETSEL, 0, -1);
}

static void do_save(void)
{
    if (!g_selk || g_multi) return;
    if (!g_dirty && g_selk == 1) { set_msg(0, L"Nothing changed."); return; }
    form_save(0);
}

/* the tunnel must be saved and complete before the service may use it */
static int ready_for_service(void)
{
    int bad;
    if (g_dirty || g_selk == 2) return form_save(1);
    bad = validate(1, -1);
    if (bad >= 0) { show_bad(bad, 1); return 0; }
    return 1;
}

static void do_connect(void)
{
    Tun *t;
    wchar_t name[NAME_MAX_LEN + 1], path[MAX_PATH], e[128];
    int rc;
    if (!g_selk) return;
    if (!g_wgok) { set_msg(2, L"Install WireGuard first (button at the top)."); return; }
    t = cur_tun();
    if (t && (t->st == 1 || t->st == 2)) {
        lstrcpyW(name, t->name);
        busy(1);
        set_msg(0, L"Disconnecting...");
        e[0] = 0;
        if (t->boot) {   /* keep the service so it still starts with windows */
            if (!svc_op(name, SVC_STOP)) wsprintfW(e, L"Windows could not stop the tunnel (error %lu).", GetLastError());
        } else if ((rc = wg_cmd(L"uninstalltunnelservice", name)) != 0) {
            wg_error(rc, e);
        }
        busy(0);
        set_msg(e[0] ? 2 : 0, e);
        rescan();
        go_fast();
        return;
    }
    if (!ready_for_service()) return;
    t = cur_tun();
    if (!t) return;
    lstrcpyW(name, t->name);
    busy(1);
    set_msg(0, L"Connecting...");
    e[0] = 0;
    if (t->installed) {
        if (!svc_op(name, SVC_START) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
            wsprintfW(e, L"Windows could not start the tunnel (error %lu).", GetLastError());
    } else {
        conf_path(name, path);
        rc = wg_cmd(L"installtunnelservice", path);
        if (rc == 0) svc_op(name, SVC_MANUAL);   /* connect now, but not at boot */
        else wg_error(rc, e);
    }
    busy(0);
    set_msg(e[0] ? 2 : 0, e);
    rescan();
    go_fast();
}

static void wait_settled(const wchar_t *name)
{
    DWORD t0 = GetTickCount();
    SvcInfo si;
    for (;;) {
        svc_info_one(name, &si);
        if (!si.installed || (si.state != SERVICE_START_PENDING && si.state != SERVICE_STOP_PENDING)) return;
        if (GetTickCount() - t0 > 10000) return;
        MsgWaitForMultipleObjects(0, NULL, FALSE, 100, QS_ALLINPUT);
        core_pump();
    }
}

static void do_boot(void)
{
    Tun *t;
    wchar_t name[NAME_MAX_LEN + 1], path[MAX_PATH], e[128];
    int want = !bi[B_BOOT].checked, rc;
    if (!g_selk) return;
    if (!g_wgok) { set_msg(2, L"Install WireGuard first (button at the top)."); return; }
    if (!ready_for_service()) return;
    t = cur_tun();
    if (!t) return;
    lstrcpyW(name, t->name);
    busy(1);
    e[0] = 0;
    if (t->installed) {
        if (want) { if (!svc_op(name, SVC_AUTO)) wsprintfW(e, L"Windows refused the change (error %lu).", GetLastError()); }
        else if (t->st == 0) { if ((rc = wg_cmd(L"uninstalltunnelservice", name)) != 0) wg_error(rc, e); }   /* nothing left to keep */
        else if (!svc_op(name, SVC_MANUAL)) wsprintfW(e, L"Windows refused the change (error %lu).", GetLastError());
    } else if (want) {
        /* installing the service also starts it; we only want it at boot, so stop it again */
        conf_path(name, path);
        rc = wg_cmd(L"installtunnelservice", path);
        if (rc == 0) {
            svc_op(name, SVC_AUTO);
            wait_settled(name);
            svc_op(name, SVC_STOP);
        } else {
            wg_error(rc, e);
        }
    }
    busy(0);
    if (e[0]) set_msg(2, e);
    else set_msg(0, want ? L"Starts with Windows from the next boot." : L"Does not start with Windows any more.");
    rescan();
    update_controls();
    go_fast();
}

static void do_delete(void)
{
    Tun *t;
    wchar_t name[NAME_MAX_LEN + 1], path[MAX_PATH], e[128];
    int rc;
    if (!g_selk) return;
    if (!g_armdel) {
        g_armdel = 1;
        update_controls();
        set_msg(0, g_selk == 2 ? L"Click again to throw this new tunnel away." : L"Click again to delete this tunnel for good.");
        return;
    }
    g_armdel = 0;
    if (g_selk == 2) {
        select_none();
        set_msg(0, L"New tunnel thrown away.");
        return;
    }
    t = cur_tun();
    lstrcpyW(name, g_cur);
    e[0] = 0;
    busy(1);
    if (t && t->installed) {
        if (!g_wgok) lstrcpyW(e, L"Install WireGuard to remove this tunnel's service first.");
        else if ((rc = wg_cmd(L"uninstalltunnelservice", name)) != 0) wg_error(rc, e);
    }
    if (!e[0]) {
        conf_path(name, path);
        if (!DeleteFileW(path)) wsprintfW(e, L"Could not delete the config file (error %lu).", GetLastError());
    }
    busy(0);
    if (e[0]) { set_msg(2, e); update_controls(); return; }
    select_none();
    rescan();
    if (g_n > 0) load_tunnel(g_t[0].name);
    set_msg(0, L"Tunnel deleted.");
}

/* copies a .conf into our folder. the source file is only read, never changed or removed */
static int import_file(const wchar_t *src, wchar_t *got)
{
    wchar_t name[NAME_MAX_LEN + 1], try_[NAME_MAX_LEN + 8], dst[MAX_PATH];
    const wchar_t *base = src, *p;
    int n, i, k;
    DWORD len = 0;
    char *data;
    static lg_conf c;

    for (p = src; *p; p++) if (*p == L'\\' || *p == L'/') base = p + 1;
    n = lstrlenW(base);
    if (n < 6 || lstrcmpiW(base + n - 5, L".conf") != 0) { set_msg(2, L"Only .conf files can be imported."); return 0; }
    n -= 5;
    if (n > NAME_MAX_LEN - 4) n = NAME_MAX_LEN - 4;   /* room for -2 .. -99 */
    for (i = 0; i < n; i++) {
        wchar_t ch = base[i];
        name[i] = ((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') || (ch >= L'0' && ch <= L'9') ||
                   ch == L'_' || ch == L'=' || ch == L'+' || ch == L'.' || ch == L'-') ? ch : L'-';
    }
    name[n] = 0;

    data = read_file(src, &len);
    if (!data) { set_msg(2, L"Could not read that file."); return 0; }
    lg_conf_parse(&c, data, len);
    k = c.priv[0] != 0;
    SecureZeroMemory(&c, sizeof c);
    if (!k) {
        SecureZeroMemory(data, len);
        HeapFree(GetProcessHeap(), 0, data);
        set_msg(2, L"That file is not a WireGuard config (it has no PrivateKey).");
        return 0;
    }
    lstrcpyW(try_, name);
    for (k = 2; k < 100; k++) {
        conf_path(try_, dst);
        if (!file_exists(dst)) break;
        wsprintfW(try_, L"%s-%d", name, k);
    }
    i = write_file(dst, data, len);
    SecureZeroMemory(data, len);
    HeapFree(GetProcessHeap(), 0, data);
    if (!i) { set_msg(2, L"Could not write the config file."); return 0; }
    lstrcpyW(got, try_);
    return lstrcmpW(try_, name) == 0 ? 1 : 2;
}

static void after_import(const wchar_t *name, int how)
{
    wchar_t m[160];
    rescan();
    if (!leave_current()) {
        wsprintfW(m, L"Imported %s. Your open changes are not saved yet: fix the marked field.", name);
        set_msg(2, m);
        return;
    }
    rescan();
    load_tunnel(name);
    if (how == 2) wsprintfW(m, L"Imported as %s (the name was taken). The original file was not changed.", name);
    else wsprintfW(m, L"Imported %s. The original file was not changed.", name);
    set_msg(0, m);
}

static void do_import(void)
{
    OPENFILENAMEW o;
    wchar_t f[MAX_PATH] = L"", got[NAME_MAX_LEN + 8];
    int how;
    memset(&o, 0, sizeof o);
    o.lStructSize = sizeof o;
    o.hwndOwner = g_main;
    o.lpstrFilter = L"WireGuard config (*.conf)\0*.conf\0\0";
    o.lpstrFile = f;
    o.nMaxFile = MAX_PATH;
    o.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR | OFN_DONTADDTORECENT;
    if (GetOpenFileNameW(&o) && (how = import_file(f, got)) != 0) after_import(got, how);
}

static void do_copy(void)
{
    wchar_t t[64];
    GetWindowTextW(fe[F_PUB], t, 64);   /* the public key; the private key never reaches the clipboard */
    if (!t[0]) return;
    copy_text(g_main, t);
    g_copied = 1;
    g_touched = 1;
    inval();
}

static void do_install_wg(void)
{
    static wchar_t cmd[] = L"cmd.exe /c winget install -e --id WireGuard.WireGuard --accept-package-agreements --accept-source-agreements & pause";
    busy(1);
    run_wait(cmd, 0);
    busy(0);
    core_find_wg();
    if (g_wgok) set_msg(0, L"WireGuard is installed. You can connect now.");
    SendMessageW(g_main, WM_SIZE, 0, 0);
    rescan();
    update_controls();
}

static void try_close(void)
{
    if (g_selk == 2 && !g_touched) { DestroyWindow(g_main); return; }
    if (g_dirty && !g_armclose && !form_save(0)) {
        g_armclose = 1;
        set_msg(2, L"Not saved: fix the marked field, or close again to throw the changes away.");
        return;
    }
    DestroyWindow(g_main);
}

/* ---------- controls state ---------- */
static void show_controls(void)
{
    int f, i, has = g_selk != 0;
    HWND foc = GetFocus();
    for (f = 0; f < NF; f++) {
        int vis = has && (FD[f].tab == 2 || FD[f].tab == g_tab);
        ShowWindow(fe[f], vis ? SW_SHOWNA : SW_HIDE);
    }
    for (i = B_KEEP; i <= B_CONN; i++) ShowWindow(bh[i], has && g_tab == 0 ? SW_SHOWNA : SW_HIDE);
    for (i = B_SHOW; i <= B_DELETE; i++) ShowWindow(bh[i], has && g_tab == 1 ? SW_SHOWNA : SW_HIDE);
    ShowWindow(bh[B_COPY], has ? SW_SHOWNA : SW_HIDE);
    if (foc && foc != g_main && !IsWindowVisible(foc)) SetFocus(g_list);
}

static void enable(int b, int on)
{
    if (!IsWindowEnabled(bh[b]) != !on) EnableWindow(bh[b], on);
}

static void set_check(int b, int on)
{
    if (bi[b].checked != on) { bi[b].checked = on; InvalidateRect(bh[b], NULL, FALSE); }
}

static void update_controls(void)
{
    Tun *t = cur_tun();
    int on = t && (t->st == 1 || t->st == 2), ro, f, kind;
    if (!bh[0]) return;
    set_text(bh[B_CONN], on ? L"Disconnect" : L"Connect");
    kind = on ? BK_NORMAL : BK_PRIMARY;
    if (bi[B_CONN].kind != kind) { bi[B_CONN].kind = kind; InvalidateRect(bh[B_CONN], NULL, FALSE); }
    enable(B_CONN, g_wgok && g_selk);
    set_check(B_BOOT, t && t->boot);
    enable(B_BOOT, g_wgok && g_selk);
    enable(B_KEEP, g_selk && !g_multi);
    enable(B_SAVE, g_dirty && !g_multi);
    enable(B_NEWKEY, !g_multi);
    enable(B_GENPSK, !g_multi);
    enable(B_COPY, g_pubok);
    set_text(bh[B_DELETE], g_armdel ? (g_selk == 2 ? L"Click again to discard" : L"Click again to delete")
                                    : (g_selk == 2 ? L"Discard new tunnel" : L"Delete tunnel"));
    set_check(B_DELETE, g_armdel);
    for (f = 0; f < F_PUB; f++) {
        ro = g_multi || (f == F_NAME && t && t->installed);
        if ((((DWORD)GetWindowLongW(fe[f], GWL_STYLE) & ES_READONLY) != 0) != (ro != 0))
            SendMessageW(fe[f], EM_SETREADONLY, (WPARAM)ro, 0);
    }
}

/* ---------- owner drawn buttons ---------- */
static void draw_btn(const DRAWITEMSTRUCT *d)
{
    Btn *b = (Btn *)GetWindowLongPtrW(d->hwndItem, GWLP_USERDATA);
    RECT r = d->rcItem, t;
    wchar_t s[64];
    int w = r.right - r.left, h = r.bottom - r.top;
    int dn = (d->itemState & ODS_SELECTED) != 0, dis = (d->itemState & ODS_DISABLED) != 0;
    int foc = (d->itemState & ODS_FOCUS) && !(d->itemState & ODS_NOFOCUSRECT);
    int hot = b->hover && !dis;
    HDC dc = CreateCompatibleDC(d->hDC);
    HBITMAP bm = CreateCompatibleBitmap(d->hDC, w, h);
    HGDIOBJ ob = SelectObject(dc, bm);
    COLORREF fg = C.text;

    GetWindowTextW(d->hwndItem, s, 64);
    SetRect(&r, 0, 0, w, h);
    fillr(dc, &r, C.panel);

    if (b->kind == BK_CHECK) {
        int bs = S(12), y0 = (h - bs) / 2;
        RECT box;
        SetRect(&box, 0, y0, bs, y0 + bs);
        if (b->checked && !dis) {
            HPEN pen = CreatePen(PS_SOLID, S(2) > 1 ? S(2) : 2, C.onacc);
            HGDIOBJ op;
            POINT pt[3];
            fillr(dc, &box, hot ? mix(C.accent, C.text, 30) : C.accent);
            frame(dc, &box, C.pline);
            pt[0].x = S(3); pt[0].y = y0 + S(6);
            pt[1].x = S(5); pt[1].y = y0 + S(8);
            pt[2].x = S(9); pt[2].y = y0 + S(3);
            op = SelectObject(dc, pen);
            Polyline(dc, pt, 3);
            SelectObject(dc, op);
            DeleteObject(pen);
        } else {
            fillr(dc, &box, dis ? C.panel : C.field);
            frame(dc, &box, dis ? C.border : hot ? C.hline : C.bline);
            if (b->checked) fill4(dc, S(4), y0 + S(4), bs - S(4), y0 + bs - S(4), C.dim);
        }
        SetRect(&t, bs + S(6), 0, w, h);
        txt(dc, s, &t, dis ? C.dim : C.text, f_ui, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        if (foc) {
            DrawTextW(dc, s, -1, &t, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
            t.top = (h - (t.bottom - t.top)) / 2 - 1;
            t.bottom = t.top + g_lh + 2;
            t.left -= 2; t.right += 2;
            frame(dc, &t, C.dim);
        }
    } else if (b->kind == BK_TITLE || b->kind == BK_CLOSE) {
        int cx = w / 2, cy = h / 2, g = S(4);
        HPEN pen;
        HGDIOBJ op;
        COLORREF bg = C.panel;
        if (hot) bg = b->kind == BK_CLOSE ? C.danger : mix(C.panel, C.text, 28);
        if (hot && dn) bg = mix(bg, RGB(0, 0, 0), 40);
        fillr(dc, &r, bg);
        fg = hot ? (b->kind == BK_CLOSE ? RGB(255, 255, 255) : C.text) : C.dim;
        pen = CreatePen(PS_SOLID, S(1), fg);
        op = SelectObject(dc, pen);
        if (b->kind == BK_CLOSE) {
            MoveToEx(dc, cx - g, cy - g, NULL); LineTo(dc, cx + g + 1, cy + g + 1);
            MoveToEx(dc, cx + g, cy - g, NULL); LineTo(dc, cx - g - 1, cy + g + 1);
        } else {
            MoveToEx(dc, cx - g, cy, NULL); LineTo(dc, cx + g + 1, cy);
        }
        SelectObject(dc, op);
        DeleteObject(pen);
    } else {
        RECT in = r;
        InflateRect(&in, -1, -1);
        if (dis) {
            fillr(dc, &r, mix(C.panel, C.field, 128));
            frame(dc, &r, C.border);
            fg = C.dim;
        } else if (b->kind == BK_PRIMARY) {
            vgrad(dc, &in, dn ? C.pdtop : hot ? C.phtop : C.ptop, dn ? C.pdbot : hot ? C.phbot : C.pbot);
            frame(dc, &r, C.pline);
            fg = C.onacc;
        } else if (b->kind == BK_DANGER && b->checked) {   /* armed delete */
            fillr(dc, &r, dn ? mix(C.danger, RGB(0, 0, 0), 40) : C.danger);
            fg = C.onacc;
        } else {
            vgrad(dc, &in, dn ? C.dtop : hot ? C.htop : C.btop, dn ? C.dbot : hot ? C.hbot : C.bbot);
            frame(dc, &r, hot ? C.hline : C.bline);
        }
        t = r;
        if (dn) OffsetRect(&t, 0, 1);
        txt(dc, s, &t, fg, f_ui, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        if (foc) {
            InflateRect(&in, -S(2), -S(2));
            frame(dc, &in, b->kind == BK_PRIMARY ? C.onacc : C.dim);
        }
    }
    BitBlt(d->hDC, d->rcItem.left, d->rcItem.top, w, h, dc, 0, 0, SRCCOPY);
    SelectObject(dc, ob);
    DeleteObject(bm);
    DeleteDC(dc);
}

static LRESULT CALLBACK btn_sub(HWND h, UINT m, WPARAM wp, LPARAM lp, UINT_PTR id, DWORD_PTR ref)
{
    Btn *b = (Btn *)ref;
    (void)id;
    switch (m) {
    case WM_MOUSEMOVE:
        if (!b->hover) {
            TRACKMOUSEEVENT t;
            t.cbSize = sizeof t;
            t.dwFlags = TME_LEAVE;
            t.hwndTrack = h;
            t.dwHoverTime = 0;
            TrackMouseEvent(&t);
            b->hover = 1;
            InvalidateRect(h, NULL, FALSE);
        }
        break;
    case WM_MOUSELEAVE:
        b->hover = 0;
        InvalidateRect(h, NULL, FALSE);
        break;
    case WM_LBUTTONDBLCLK:   /* a fast second click is just another click */
        return DefSubclassProc(h, WM_LBUTTONDOWN, wp, lp);
    case WM_ERASEBKGND:
        return 1;
    }
    return DefSubclassProc(h, m, wp, lp);
}

/* edits: placeholder text, and the private key can never be copied out */
static LRESULT CALLBACK edit_sub(HWND h, UINT m, WPARAM wp, LPARAM lp, UINT_PTR id, DWORD_PTR ref)
{
    if ((int)id == F_PRIV && (m == WM_COPY || m == WM_CUT)) return 0;
    if ((int)id == F_PRIV && m == WM_CONTEXTMENU) return 0;
    if (m == WM_PAINT && ref && GetWindowTextLengthW(h) == 0) {
        LRESULT r = DefSubclassProc(h, m, wp, lp);
        HDC dc = GetDC(h);
        RECT rc;
        SendMessageW(h, EM_GETRECT, 0, (LPARAM)&rc);
        HideCaret(h);
        txt(dc, (const wchar_t *)ref, &rc, C.dim, (HFONT)SendMessageW(h, WM_GETFONT, 0, 0), DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
        ShowCaret(h);
        ReleaseDC(h, dc);
        return r;
    }
    return DefSubclassProc(h, m, wp, lp);
}

/* ---------- tunnel list ---------- */
static int g_top, g_hov = -1, g_wheel, g_lhov;

static int list_rows(void)
{
    RECT r;
    GetClientRect(g_list, &r);
    return r.bottom / S(ROW_H);
}

static void clamp_top(void)
{
    int max = list_count() - list_rows();
    if (max < 0) max = 0;
    if (g_top > max) g_top = max;
    if (g_top < 0) g_top = 0;
}

static void list_show(int i)
{
    int rows;
    if (!g_list || i < 0) return;
    rows = list_rows();
    if (rows < 1) rows = 1;
    if (i < g_top) g_top = i;
    else if (i >= g_top + rows) g_top = i - rows + 1;
    clamp_top();
    InvalidateRect(g_list, NULL, FALSE);
}

static void list_paint(HWND w)
{
    PAINTSTRUCT ps;
    HDC wdc = BeginPaint(w, &ps), dc;
    RECT rc, row, t;
    HBITMAP bm;
    HGDIOBJ ob;
    int n = list_count(), sel = sel_index(), rh = S(ROW_H), i, y;

    GetClientRect(w, &rc);
    dc = CreateCompatibleDC(wdc);
    bm = CreateCompatibleBitmap(wdc, rc.right, rc.bottom);
    ob = SelectObject(dc, bm);
    fillr(dc, &rc, C.field);

    if (!n) {
        int th;
        t = rc;
        InflateRect(&t, -S(14), 0);
        SelectObject(dc, f_ui);
        DrawTextW(dc, L"No tunnels yet.\nDrop a .conf here or press New.", -1, &t, DT_CALCRECT | DT_CENTER | DT_WORDBREAK | DT_NOPREFIX);
        th = t.bottom - t.top;
        t.left = rc.left + S(14);
        t.right = rc.right - S(14);
        t.top = (rc.bottom - th) / 2 - S(10);
        t.bottom = t.top + th;
        txt(dc, L"No tunnels yet.\nDrop a .conf here or press New.", &t, C.dim, f_ui, DT_CENTER | DT_WORDBREAK);
    }
    for (i = g_top; i < n; i++) {
        const wchar_t *name, *state = L"";
        wchar_t dn[NAME_MAX_LEN + 1];
        int st = 0, issel = i == sel;
        COLORREF bg, fg, sub, dc_;
        y = (i - g_top) * rh;
        if (y >= rc.bottom) break;
        if (i < g_n) {
            name = g_t[i].name;
            st = g_t[i].st;
            state = st == 2 ? L"connected" : st == 1 ? L"connecting" : st == 3 ? L"disconnecting" : L"";
        } else {
            GetWindowTextW(fe[F_NAME], dn, NAME_MAX_LEN + 1);
            name = dn[0] ? dn : L"new tunnel";
            state = L"not saved";
        }
        bg = issel ? C.accent : i == g_hov ? C.hover : C.field;
        fg = issel ? C.onacc : C.text;
        sub = issel ? C.onacc : C.dim;
        SetRect(&row, 0, y, rc.right, y + rh - 1);
        fillr(dc, &row, bg);
        fill4(dc, 0, y + rh - 1, rc.right, y + rh, C.border);
        /* status dot: accent = connected, grey = off */
        if (issel) dc_ = st ? C.onacc : mix(C.accent, C.onacc, 110);
        else dc_ = st ? C.accent : mix(C.field, C.dim, 170);
        dot(dc, (S(7) + S(3)) * 8, (y * 2 + rh - 1) * 4, S(3) * 8, (st == 1 || st == 3) ? S(2) * 8 : 0, dc_, bg);
        SetRect(&t, S(18), y, rc.right - S(8), y + rh - 1);
        if (state[0]) {
            RECT m = t;
            int sw;
            SelectObject(dc, f_ui);
            DrawTextW(dc, state, -1, &m, DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX);
            sw = m.right - m.left;
            txt(dc, state, &t, sub, f_ui, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
            t.right -= sw + S(8);
        }
        txt(dc, name, &t, fg, f_ui, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }
    if (n * rh > rc.bottom && n > 0) {
        int rows = rc.bottom / rh, th = rc.bottom * rows / n, ty;
        if (th < S(16)) th = S(16);
        ty = n > rows ? g_top * (rc.bottom - th) / (n - rows) : 0;
        fill4(dc, rc.right - S(3), ty, rc.right - 1, ty + th, C.dim);
    }
    if (GetFocus() == w && n) {
        RECT f = rc;
        frame(dc, &f, C.dim);
    }
    BitBlt(wdc, 0, 0, rc.right, rc.bottom, dc, 0, 0, SRCCOPY);
    SelectObject(dc, ob);
    DeleteObject(bm);
    DeleteDC(dc);
    EndPaint(w, &ps);
}

static LRESULT CALLBACK list_proc(HWND w, UINT m, WPARAM wp, LPARAM lp)
{
    int i;
    switch (m) {
    case WM_PAINT: list_paint(w); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_SIZE: clamp_top(); InvalidateRect(w, NULL, FALSE); return 0;
    case WM_SETFOCUS: case WM_KILLFOCUS: InvalidateRect(w, NULL, FALSE); return 0;
    case WM_GETDLGCODE: return DLGC_WANTARROWS;
    case WM_LBUTTONDOWN:
        SetFocus(w);
        i = g_top + YL(lp) / S(ROW_H);
        if (i < g_n) select_row(i);
        return 0;
    case WM_MOUSEMOVE:
        if (!g_lhov) {
            TRACKMOUSEEVENT t;
            t.cbSize = sizeof t;
            t.dwFlags = TME_LEAVE;
            t.hwndTrack = w;
            t.dwHoverTime = 0;
            TrackMouseEvent(&t);
            g_lhov = 1;
        }
        i = g_top + YL(lp) / S(ROW_H);
        if (i >= list_count()) i = -1;
        if (i != g_hov) { g_hov = i; InvalidateRect(w, NULL, FALSE); }
        return 0;
    case WM_MOUSELEAVE:
        g_lhov = 0;
        if (g_hov != -1) { g_hov = -1; InvalidateRect(w, NULL, FALSE); }
        return 0;
    case WM_MOUSEWHEEL:
        g_wheel += GET_WHEEL_DELTA_WPARAM(wp);
        while (g_wheel >= WHEEL_DELTA) { g_top--; g_wheel -= WHEEL_DELTA; }
        while (g_wheel <= -WHEEL_DELTA) { g_top++; g_wheel += WHEEL_DELTA; }
        clamp_top();
        InvalidateRect(w, NULL, FALSE);
        return 0;
    case WM_KEYDOWN:
        i = sel_index();
        if (g_selk == 2) i = g_n;
        if (wp == VK_UP) select_row(i < 0 ? 0 : i - 1);
        else if (wp == VK_DOWN) select_row(i < 0 ? 0 : i + 1);
        else if (wp == VK_HOME) select_row(0);
        else if (wp == VK_END) select_row(g_n - 1);
        return 0;
    }
    return DefWindowProcW(w, m, wp, lp);
}

/* ---------- layout ---------- */
static void place(HWND h, int x, int y, int w, int hh)
{
    SetWindowPos(h, NULL, x, y, w, hh, SWP_NOZORDER | SWP_NOACTIVATE);
}

/* label line + field frame; nb buttons of width bw each to the right of the field */
static void place_field(int f, int x, int y, int w, int b1, int b2, int bw)
{
    int ft = FD[f].label ? y + S(LBL) : y, fw = w, eh = FD[f].mono ? g_lhm : g_lh;
    SetRect(&flr[f], x, y, x + w, y + S(LBL));
    if (b2 >= 0) { fw -= bw + S(4); place(bh[b2], x + fw + S(4), ft, bw, S(FH)); }
    if (b1 >= 0) { fw -= bw + S(4); place(bh[b1], x + fw + S(4), ft, bw, S(FH)); }
    SetRect(&fr[f], x, ft, x + fw, ft + S(FH));
    place(fe[f], x + S(5), ft + (S(FH) - eh) / 2, fw - S(10), eh);
}

static void layout(void)
{
    RECT rc;
    int W, H, x0, x1, y, y1, lw, bw, rx, cx, cw, fy, cy, by, mid, f;
    GetClientRect(g_main, &rc);
    W = rc.right;
    H = rc.bottom;
    SetRect(&r_title, 1, 1, W - 1, S(TITLE_H));
    place(bh[B_CLOSE], W - 1 - S(30), 1, S(30), S(TITLE_H) - 2);
    place(bh[B_MIN], W - 1 - S(60), 1, S(30), S(TITLE_H) - 2);

    x0 = 1 + S(PAD);
    x1 = W - 1 - S(PAD);
    y = S(TITLE_H) + S(PAD);
    y1 = H - 1 - S(PAD);
    g_banner = !g_wgok;
    if (g_banner) {
        SetRect(&r_banner, x0, y, x1, y + S(BANNER_H));
        place(bh[B_INSTALL], x1 - S(IP) - S(130), y + S(2) + (S(BANNER_H) - S(2) - S(BTN_H)) / 2, S(130), S(BTN_H));
        y += S(BANNER_H) + S(PAD);
    }
    ShowWindow(bh[B_INSTALL], g_banner ? SW_SHOWNA : SW_HIDE);

    lw = W * 30 / 100;
    if (lw < S(190)) lw = S(190);
    if (lw > S(260)) lw = S(260);
    SetRect(&r_left, x0, y, x0 + lw, y1);
    SetRect(&r_listbox, r_left.left + S(IP), r_left.top + S(HDR) + S(4), r_left.right - S(IP),
            r_left.bottom - S(IP) - S(BTN_H) - S(6));
    place(g_list, r_listbox.left + 1, r_listbox.top + 1, r_listbox.right - r_listbox.left - 2, r_listbox.bottom - r_listbox.top - 2);
    bw = (lw - 2 * S(IP) - S(4)) / 2;
    place(bh[B_IMPORT], r_left.left + S(IP), r_left.bottom - S(IP) - S(BTN_H), bw, S(BTN_H));
    place(bh[B_NEW], r_left.right - S(IP) - bw, r_left.bottom - S(IP) - S(BTN_H), bw, S(BTN_H));

    rx = r_left.right + S(PAD);
    SetRect(&r_key, rx, y1 - S(KEY_H), x1, y1);
    SetRect(&r_setup, rx, y, x1, r_key.top - S(PAD));
    mid = (r_setup.left + r_setup.right) / 2;
    SetRect(&r_tab[0], r_setup.left + 1, r_setup.top + 1, mid, r_setup.top + S(HDR));
    SetRect(&r_tab[1], mid + 1, r_setup.top + 1, r_setup.right - 1, r_setup.top + S(HDR));

    /* setup tab: one field per row */
    cx = r_setup.left + S(IP);
    cw = r_setup.right - r_setup.left - 2 * S(IP);
    fy = r_setup.top + S(HDR) + S(8);
    for (f = F_NAME; f <= F_ALLOWED; f++) place_field(f, cx, fy + (f - F_NAME) * S(PITCH), cw, -1, -1, 0);
    cy = fy + 5 * S(PITCH) + S(2);
    place(bh[B_KEEP], cx, cy, cw / 2 - S(4), S(16));
    place(bh[B_BOOT], cx + cw / 2, cy, cw - cw / 2, S(16));
    by = cy + S(16) + S(10);
    place(bh[B_SAVE], cx, by, S(80), S(CONN_H));
    place(bh[B_CONN], cx + S(86), by, cw - S(86), S(CONN_H));
    SetRect(&r_status, cx, by + S(CONN_H) + S(4), cx + cw, by + S(CONN_H) + S(4) + S(16));

    /* advanced tab */
    place_field(F_PRIV, cx, fy, cw, B_SHOW, B_NEWKEY, S(64));
    place_field(F_PSK, cx, fy + S(PITCH), cw, B_GENPSK, -1, S(64));
    place_field(F_DNS, cx, fy + 2 * S(PITCH), cw, -1, -1, 0);
    SetRect(&r_advinfo, cx, fy + 3 * S(PITCH) + S(2), cx + cw, fy + 3 * S(PITCH) + S(2) + S(3 * 14));
    place(bh[B_DELETE], cx, r_advinfo.bottom + S(8), S(150), S(BTN_H));

    /* key panel */
    cx = r_key.left + S(IP);
    cw = r_key.right - r_key.left - 2 * S(IP);
    place_field(F_PUB, cx, r_key.top + S(HDR) + S(6), cw, B_COPY, -1, S(64));
    SetRect(&r_keyhint, cx, fr[F_PUB].bottom + S(3), cx + cw, fr[F_PUB].bottom + S(3) + S(16));
    inval();
}
/* ---------- painting ---------- */
static void panel_box(HDC dc, const RECT *r, const wchar_t *title, COLORREF line)
{
    RECT h;
    fillr(dc, r, C.panel);
    frame(dc, r, C.border);
    fill4(dc, r->left + 1, r->top + 1, r->right - 1, r->top + 1 + S(2), line);
    if (title) {
        SetRect(&h, r->left, r->top + S(2), r->right, r->top + S(HDR));
        txt(dc, title, &h, C.text, f_ui, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
}

static void status_line(HDC dc)
{
    Tun *t = cur_tun();
    const wchar_t *s;
    COLORREF c = C.text;
    RECT r = r_status;
    int st = t ? t->st : 0, cy = (r.top + r.bottom) / 2;
    if (g_msg[0]) {
        s = g_msg;
        c = g_msgk == 2 ? C.danger : g_msgk == 1 ? C.text : C.dim;
    } else if (g_selk == 2) {
        s = L"Not saved yet.";
        c = C.dim;
    } else if (!g_wgok) {
        s = L"Connecting needs WireGuard (see the bar at the top).";
        c = C.dim;
    } else {
        s = st == 2 ? L"Connected." : st == 1 ? L"Connecting..." : st == 3 ? L"Disconnecting..." :
            (t && t->boot) ? L"Not connected. Starts with Windows." : L"Not connected.";
        c = st ? C.text : C.dim;
        dot(dc, (r.left + S(3)) * 8, cy * 8, S(3) * 8, (st == 1 || st == 3) ? S(2) * 8 : 0,
            st ? C.accent : mix(C.panel, C.dim, 170), C.panel);
        r.left += S(12);
    }
    txt(dc, s, &r, c, f_ui, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

static void paint_main(HDC dc, const RECT *rc)
{
    RECT t;
    int f, has = g_selk != 0, i;
    SIZE a, b;
    HWND foc = GetFocus();

    fillr(dc, rc, C.win);
    /* title bar */
    fillr(dc, &r_title, C.panel);
    fill4(dc, 1, S(TITLE_H) - 1, rc->right - 1, S(TITLE_H), C.border);
    SelectObject(dc, f_title);
    GetTextExtentPoint32W(dc, L"light", 5, &a);
    GetTextExtentPoint32W(dc, L"guard", 5, &b);
    i = (rc->right - a.cx - b.cx) / 2;
    SetRect(&t, i, 1, i + a.cx + S(2), S(TITLE_H) - 1);
    txt(dc, L"light", &t, C.text, f_title, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SetRect(&t, i + a.cx, 1, i + a.cx + b.cx + S(2), S(TITLE_H) - 1);
    txt(dc, L"guard", &t, C.accent, f_title, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    frame(dc, rc, C.border);

    if (g_banner) {
        panel_box(dc, &r_banner, NULL, C.danger);
        SetRect(&t, r_banner.left + S(IP), r_banner.top + S(2), r_banner.right - S(IP) - S(140), r_banner.bottom);
        txt(dc, L"WireGuard is not installed. You can set up tunnels now; connecting needs it.", &t, C.text, f_ui,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }

    panel_box(dc, &r_left, L"Tunnels", C.accent);
    frame(dc, &r_listbox, C.border);

    /* setup panel: tabs as its header */
    fillr(dc, &r_setup, C.panel);
    frame(dc, &r_setup, C.border);
    if (!has) {
        panel_box(dc, &r_setup, L"Setup", C.accent);
        SetRect(&t, r_setup.left + S(IP), r_setup.top + S(HDR), r_setup.right - S(IP), (r_setup.top + r_setup.bottom) / 2);
        txt(dc, g_n ? L"Pick a tunnel on the left, or press New." : L"Press New to make your first tunnel.", &t, C.dim, f_ui,
            DT_CENTER | DT_BOTTOM | DT_SINGLELINE);
        if (g_msg[0]) {
            SetRect(&t, r_setup.left + S(IP), (r_setup.top + r_setup.bottom) / 2 + S(8), r_setup.right - S(IP), r_setup.bottom - S(IP));
            txt(dc, g_msg, &t, g_msgk == 2 ? C.danger : C.dim, f_ui, DT_CENTER | DT_TOP | DT_WORDBREAK);
        }
    } else {
        static const wchar_t *tabs[2] = { L"Setup", L"Advanced" };
        for (i = 0; i < 2; i++) {
            if (i == g_tab) {
                fill4(dc, r_tab[i].left, r_tab[i].top, r_tab[i].right, r_tab[i].top + S(2), C.accent);
                txt(dc, tabs[i], &r_tab[i], C.text, f_ui, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            } else {
                fillr(dc, &r_tab[i], g_hovtab == i ? mix(C.win, C.panel, 128) : C.win);
                fill4(dc, r_tab[i].left, r_tab[i].bottom - 1, r_tab[i].right, r_tab[i].bottom, C.border);
                txt(dc, tabs[i], &r_tab[i], g_hovtab == i ? C.text : C.dim, f_ui, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            }
        }
        fill4(dc, r_tab[0].right, r_tab[0].top, r_tab[0].right + 1, r_tab[0].bottom, C.border);

        if (g_tab == 0) {
            status_line(dc);
        } else {
            wchar_t info[MAX_PATH + 80];
            if (g_selk == 2) lstrcpyW(info, L"Not saved yet.");
            else wsprintfW(info, L"Saved as %s\\%s.conf", g_dir, g_cur);
            lstrcatW(info, L"\nOther settings in the file, like MTU, are kept as they are.");
            txt(dc, info, &r_advinfo, C.dim, f_ui, DT_LEFT | DT_TOP | DT_WORDBREAK | DT_PATH_ELLIPSIS);
            if (g_msg[0]) {
                RECT m;
                GetWindowRect(bh[B_DELETE], &m);
                MapWindowPoints(NULL, g_main, (POINT *)&m, 2);
                SetRect(&t, r_advinfo.left, m.bottom + S(8), r_advinfo.right, m.bottom + S(26));
                txt(dc, g_msg, &t, g_msgk == 2 ? C.danger : C.dim, f_ui, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
            }
        }
    }

    /* key panel */
    panel_box(dc, &r_key, L"Your key", C.accent);
    if (!has) {
        SetRect(&t, r_key.left, r_key.top + S(HDR), r_key.right, r_key.bottom);
        txt(dc, L"Your public key shows here.", &t, C.dim, f_ui, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    } else {
        const wchar_t *hint = g_copied ? L"Copied. Send this to your friend." : L"Send this to your friend.";
        if (!g_pubok) hint = L"No valid private key: make one under Advanced.";
        txt(dc, hint, &r_keyhint, g_copied ? C.text : (g_pubok ? C.dim : C.danger), f_ui, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }

    /* labels and field frames */
    for (f = 0; f < NF && has; f++) {
        COLORREF bc;
        if (FD[f].tab != 2 && FD[f].tab != g_tab) continue;
        if (FD[f].label) {
            txt(dc, FD[f].label, &flr[f], C.dim, f_ui, DT_LEFT | DT_TOP | DT_SINGLELINE);
            if (ferr[f][0]) txt(dc, ferr[f], &flr[f], C.danger, f_ui, DT_RIGHT | DT_TOP | DT_SINGLELINE);
            else if (FD[f].hint) txt(dc, FD[f].hint, &flr[f], C.dim, f_ui, DT_RIGHT | DT_TOP | DT_SINGLELINE);
        }
        bc = ferr[f][0] ? C.danger : foc == fe[f] ? C.dim : C.border;
        fillr(dc, &fr[f], C.field);
        frame(dc, &fr[f], bc);
    }
}

/* ---------- main window ---------- */
static HWND mkbtn(int i, HWND parent)
{
    HWND h = CreateWindowExW(0, L"BUTTON", BD[i].text, WS_CHILD | BS_OWNERDRAW |
                             (BD[i].kind == BK_TITLE || BD[i].kind == BK_CLOSE ? 0 : WS_TABSTOP) |
                             (i == B_MIN || i == B_CLOSE || i == B_IMPORT || i == B_NEW ? WS_VISIBLE : 0),
                             0, 0, 10, 10, parent, (HMENU)(INT_PTR)(ID_BTN + i), g_inst, NULL);
    bi[i].kind = BD[i].kind;
    SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)&bi[i]);
    SetWindowSubclass(h, btn_sub, (UINT_PTR)i, (DWORD_PTR)&bi[i]);
    SendMessageW(h, WM_SETFONT, (WPARAM)f_ui, FALSE);
    bh[i] = h;
    return h;
}

static void mkedit(int f, HWND parent)
{
    DWORD st = WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL;
    if (f == F_PUB) st |= ES_READONLY;
    if (f == F_PRIV || f == F_PSK) st |= ES_PASSWORD;
    fe[f] = CreateWindowExW(0, L"EDIT", L"", st, 0, 0, 10, 10, parent, (HMENU)(INT_PTR)(ID_EDIT + f), g_inst, NULL);
    SendMessageW(fe[f], EM_LIMITTEXT, (WPARAM)FD[f].max, 0);
    SendMessageW(fe[f], WM_SETFONT, (WPARAM)(FD[f].mono ? f_mono : f_ui), FALSE);
    SendMessageW(fe[f], EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, 0);
    if (f == F_PRIV || f == F_PSK) SendMessageW(fe[f], EM_SETPASSWORDCHAR, 0x25CF, 0);
    SetWindowSubclass(fe[f], edit_sub, (UINT_PTR)f, (DWORD_PTR)FD[f].cue);
}

static void create_children(HWND w)
{
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = list_proc;
    wc.hInstance = g_inst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.lpszClassName = L"lightguard_list";
    RegisterClassExW(&wc);

    /* creation order is the tab order */
    g_list = CreateWindowExW(0, L"lightguard_list", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, w,
                             (HMENU)(INT_PTR)ID_LIST, g_inst, NULL);
    mkbtn(B_IMPORT, w);
    mkbtn(B_NEW, w);
    mkedit(F_NAME, w);
    mkedit(F_ADDR, w);
    mkedit(F_ENDP, w);
    mkedit(F_PEER, w);
    mkedit(F_ALLOWED, w);
    mkbtn(B_KEEP, w);
    mkbtn(B_BOOT, w);
    mkbtn(B_SAVE, w);
    mkbtn(B_CONN, w);
    mkedit(F_PRIV, w);
    mkbtn(B_SHOW, w);
    mkbtn(B_NEWKEY, w);
    mkedit(F_PSK, w);
    mkbtn(B_GENPSK, w);
    mkedit(F_DNS, w);
    mkbtn(B_DELETE, w);
    mkedit(F_PUB, w);
    mkbtn(B_COPY, w);
    mkbtn(B_INSTALL, w);
    mkbtn(B_MIN, w);
    mkbtn(B_CLOSE, w);
}

static void on_edit(int f, int code)
{
    if (code == EN_CHANGE) {
        if (GetWindowTextLengthW(fe[f]) == 0) InvalidateRect(fe[f], NULL, TRUE);   /* placeholder */
        if (g_loading || f == F_PUB) return;
        if (ferr[f][0]) ferr[f][0] = 0;
        g_dirty = 1;
        g_touched = 1;
        g_armleave = g_armclose = 0;
        g_msg[0] = 0;   /* "Saved." or an old error no longer applies */
        if (f == F_PRIV) update_pub();
        if (f == F_NAME && g_selk == 2) InvalidateRect(g_list, NULL, FALSE);
        update_controls();
        inval();
    } else if (code == EN_SETFOCUS) {
        inval();
    } else if (code == EN_KILLFOCUS) {
        if (!g_loading && g_selk && f != F_PUB && GetWindowTextLengthW(fe[f]) > 0) validate(0, f);
        inval();
    }
}

static void on_button(int b)
{
    if (g_busy) return;
    if (b != B_DELETE && g_armdel) { g_armdel = 0; update_controls(); }
    if (b != B_CLOSE) g_armclose = 0;
    if (b != B_COPY && b != B_MIN && b != B_CLOSE && b != B_DELETE) g_msg[0] = 0;
    switch (b) {
    case B_IMPORT: do_import(); break;
    case B_NEW: do_new(); break;
    case B_KEEP:
        bi[B_KEEP].checked = !bi[B_KEEP].checked;
        InvalidateRect(bh[B_KEEP], NULL, FALSE);
        g_dirty = g_touched = 1;
        update_controls();
        break;
    case B_BOOT: do_boot(); break;
    case B_SAVE: do_save(); break;
    case B_CONN: do_connect(); break;
    case B_SHOW: set_showkey(!g_showkey); break;
    case B_NEWKEY:
        if (gen_key(F_PRIV)) set_msg(0, L"New key made. Send the new public key to your friend, then Save.");
        break;
    case B_GENPSK:
        if (gen_key(F_PSK)) set_msg(0, L"Preshared key made. Your friend needs the same one: press Show to read it.");
        break;
    case B_DELETE: do_delete(); break;
    case B_COPY: do_copy(); break;
    case B_INSTALL: do_install_wg(); break;
    case B_MIN: ShowWindow(g_main, SW_MINIMIZE); break;
    case B_CLOSE: try_close(); break;
    }
    inval();
}

static LRESULT CALLBACK main_proc(HWND w, UINT m, WPARAM wp, LPARAM lp)
{
    switch (m) {
    case WM_CREATE:
        g_main = w;
        g_dpi = GetDpiForWindow(w);
        make_fonts();
        create_children(w);
        apply_dwm(w);
        DragAcceptFiles(w, TRUE);
        ChangeWindowMessageFilterEx(w, WM_DROPFILES, MSGFLT_ALLOW, NULL);
        ChangeWindowMessageFilterEx(w, WM_COPYDATA, MSGFLT_ALLOW, NULL);
        ChangeWindowMessageFilterEx(w, WM_COPYGLOBALDATA, MSGFLT_ALLOW, NULL);
        rescan();
        layout();
        if (g_n > 0) load_tunnel(g_t[0].name);
        else { show_controls(); update_controls(); }
        SetTimer(w, 1, 2000, NULL);
        return 0;
    case WM_NCCALCSIZE:
        if (wp) {
            if (IsZoomed(w)) {   /* a maximised window hangs over the screen edge by its frame */
                NCCALCSIZE_PARAMS *p = (NCCALCSIZE_PARAMS *)lp;
                int fx = GetSystemMetricsForDpi(SM_CXFRAME, g_dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, g_dpi);
                int fy = GetSystemMetricsForDpi(SM_CYFRAME, g_dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, g_dpi);
                p->rgrc[0].left += fx; p->rgrc[0].right -= fx;
                p->rgrc[0].top += fy; p->rgrc[0].bottom -= fy;
            }
            return 0;
        }
        break;
    case WM_NCACTIVATE:
        return DefWindowProcW(w, m, wp, -1);   /* no default frame painting */
    case WM_NCHITTEST: {
        POINT p;
        RECT rc;
        int e = S(6);
        p.x = XL(lp);
        p.y = YL(lp);
        ScreenToClient(w, &p);
        GetClientRect(w, &rc);
        if (!IsZoomed(w)) {
            int l = p.x < e, r = p.x >= rc.right - e, t = p.y < e, b = p.y >= rc.bottom - e;
            if (t && l) return HTTOPLEFT;
            if (t && r) return HTTOPRIGHT;
            if (b && l) return HTBOTTOMLEFT;
            if (b && r) return HTBOTTOMRIGHT;
            if (l) return HTLEFT;
            if (r) return HTRIGHT;
            if (t) return HTTOP;
            if (b) return HTBOTTOM;
        }
        if (p.y < S(TITLE_H)) return HTCAPTION;
        return HTCLIENT;
    }
    case WM_SIZE:
        if (g_list) layout();
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mi = (MINMAXINFO *)lp;
        mi->ptMinTrackSize.x = S(640);
        mi->ptMinTrackSize.y = S(TITLE_H + 2 * PAD + SETUP_H + PAD + KEY_H + 2) + (g_wgok ? 0 : S(BANNER_H + PAD));
        return 0;
    }
    case WM_DPICHANGED: {
        RECT *r = (RECT *)lp;
        int i;
        g_dpi = HIWORD(wp);
        make_fonts();
        for (i = 0; i < NB; i++) SendMessageW(bh[i], WM_SETFONT, (WPARAM)f_ui, FALSE);
        SetWindowPos(w, NULL, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        layout();
        return 0;
    }
    case WM_SETTINGCHANGE:
        if (lp && lstrcmpW((const wchar_t *)lp, L"ImmersiveColorSet") == 0) {
            make_colors();
            apply_dwm(w);
            RedrawWindow(w, NULL, NULL, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
        }
        return 0;
    case WM_TIMER:
        if (g_busy || IsIconic(w)) return 0;
        if (!rescan() && wp == 2 && GetTickCount() - g_fast_since > 3000) KillTimer(w, 2);
        return 0;
    case WM_ACTIVATE:
        if (LOWORD(wp) != WA_INACTIVE && g_list && !g_busy) rescan();
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(w, &ps), md;
        RECT rc;
        HBITMAP bm;
        HGDIOBJ ob;
        GetClientRect(w, &rc);
        md = CreateCompatibleDC(dc);
        bm = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        ob = SelectObject(md, bm);
        paint_main(md, &rc);
        BitBlt(dc, 0, 0, rc.right, rc.bottom, md, 0, 0, SRCCOPY);
        SelectObject(md, ob);
        DeleteObject(bm);
        DeleteDC(md);
        EndPaint(w, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_LBUTTONDOWN: {
        POINT p;
        int i;
        p.x = XL(lp);
        p.y = YL(lp);
        for (i = 0; i < 2 && g_selk; i++)
            if (PtInRect(&r_tab[i], p) && i != g_tab) set_tab(i);
        return 0;
    }
    case WM_MOUSEMOVE: {
        POINT p;
        int i, h = -1;
        p.x = XL(lp);
        p.y = YL(lp);
        for (i = 0; i < 2 && g_selk; i++) if (PtInRect(&r_tab[i], p) && i != g_tab) h = i;
        if (!g_tracking) {
            TRACKMOUSEEVENT t;
            t.cbSize = sizeof t;
            t.dwFlags = TME_LEAVE;
            t.hwndTrack = w;
            t.dwHoverTime = 0;
            TrackMouseEvent(&t);
            g_tracking = 1;
        }
        if (h != g_hovtab) { g_hovtab = h; InvalidateRect(w, &r_setup, FALSE); }
        return 0;
    }
    case WM_MOUSELEAVE:
        g_tracking = 0;
        if (g_hovtab != -1) { g_hovtab = -1; InvalidateRect(w, &r_setup, FALSE); }
        return 0;
    case WM_DRAWITEM:
        draw_btn((const DRAWITEMSTRUCT *)lp);
        return TRUE;
    case WM_CTLCOLOREDIT: case WM_CTLCOLORSTATIC:
        SetTextColor((HDC)wp, C.text);
        SetBkColor((HDC)wp, C.field);
        return (LRESULT)br_field;
    case WM_CTLCOLORBTN:
        return (LRESULT)br_panel;
    case WM_COMMAND: {
        int id = LOWORD(wp), code = HIWORD(wp);
        if (id >= ID_EDIT && id < ID_EDIT + NF) { on_edit(id - ID_EDIT, code); return 0; }
        if (id == IDOK) {   /* enter: press the focused button, otherwise save */
            HWND f = GetFocus();
            int i;
            for (i = 0; i < NB; i++) if (f == bh[i]) { on_button(i); return 0; }
            if (!g_busy) do_save();
            return 0;
        }
        if (id >= ID_BTN && id < ID_BTN + NB && code == BN_CLICKED) on_button(id - ID_BTN);
        return 0;
    }
    case WM_DROPFILES: {
        HDROP d = (HDROP)wp;
        UINT i, n = DragQueryFileW(d, 0xFFFFFFFF, NULL, 0);
        wchar_t got[NAME_MAX_LEN + 8];
        int how = 0, h;
        got[0] = 0;
        for (i = 0; i < n && !g_busy; i++) {
            wchar_t f[MAX_PATH];
            if (DragQueryFileW(d, i, f, MAX_PATH) && (h = import_file(f, got)) != 0) how = h;
        }
        DragFinish(d);
        if (how) after_import(got, how);
        SetForegroundWindow(w);
        return 0;
    }
    case WM_CLOSE:
        if (!g_busy) try_close();
        return 0;
    case WM_DESTROY:
        KillTimer(w, 1);
        KillTimer(w, 2);
        SecureZeroMemory(&g_conf, sizeof g_conf);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(w, m, wp, lp);
}

/* ---------- selftest output ---------- */
static HANDLE g_out;
static void out_line(const char *s)
{
    DWORD n;
    WriteFile(g_out, s, (DWORD)lstrlenA(s), &n, NULL);
}

static int selftest(void)
{
    int fails;
    g_out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!g_out || g_out == INVALID_HANDLE_VALUE) {
        if (AttachConsole(ATTACH_PARENT_PROCESS))
            g_out = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    }
    if (!g_out || g_out == INVALID_HANDLE_VALUE) return 1;
    fails = lg_selftest(out_line);
    out_line(fails ? "selftest FAILED\n" : "selftest passed\n");
    return fails ? 1 : 0;
}

/* ---------- entry ---------- */
static LONG WINAPI on_crash(EXCEPTION_POINTERS *e)
{
    (void)e;
    SecureZeroMemory(&g_conf, sizeof g_conf);
    TerminateProcess(GetCurrentProcess(), 3);
    return EXCEPTION_EXECUTE_HANDLER;
}

static int run(void)
{
    INITCOMMONCONTROLSEX ic;
    WNDCLASSEXW wc;
    MSG mm;
    int argc = 0, cw, ch;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    RECT wa;
    HWND w;

    if (argv && argc > 1 && lstrcmpiW(argv[1], L"--selftest") == 0) return selftest();

    /* no crash dumps or error reports that could carry keys: a crash just ends the process */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    SetUnhandledExceptionFilter(on_crash);

    ic.dwSize = sizeof ic;
    ic.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&ic);

    g_inst = GetModuleHandleW(NULL);
    g_dpi = GetDpiForSystem();
    make_colors();
    load_font();

    if (!core_init_dir()) {
        MessageBoxW(NULL, L"Could not create the config folder in ProgramData. Run as administrator.", APPNAME, MB_ICONERROR | MB_OK);
        return 1;
    }
    core_find_wg();

    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc;
    wc.lpfnWndProc = main_proc;
    wc.hInstance = g_inst;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.lpszClassName = L"lightguard_main";
    wc.hIcon = LoadIconW(NULL, IDI_SHIELD);
    RegisterClassExW(&wc);

    cw = S(740);
    ch = S(TITLE_H + 2 * PAD + SETUP_H + PAD + KEY_H + 2) + (g_wgok ? 0 : S(BANNER_H + PAD));
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    w = CreateWindowExW(0, L"lightguard_main", APPNAME, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                        wa.left + (wa.right - wa.left - cw) / 2, wa.top + (wa.bottom - wa.top - ch) / 2, cw, ch,
                        NULL, NULL, g_inst, NULL);
    if (!w) return 1;
    SetWindowPos(w, NULL, 0, 0, 0, 0, SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER);
    ShowWindow(w, SW_SHOW);

    while (GetMessageW(&mm, NULL, 0, 0) > 0) {
        if (mm.message == WM_KEYDOWN && (GetKeyState(VK_CONTROL) & 0x8000)) {
            if (mm.wParam == 'S') { if (!g_busy) do_save(); continue; }
            if (mm.wParam == VK_TAB && g_selk) { set_tab(!g_tab); continue; }
        }
        if (!IsDialogMessageW(g_main, &mm)) {
            TranslateMessage(&mm);
            DispatchMessageW(&mm);
        }
    }
    return 0;
}

void start(void)
{
    ExitProcess((UINT)run());
}
