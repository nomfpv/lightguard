/* windows logic without any ui. no crt. */
#include "wincore.h"
#include <sddl.h>
#include <bcrypt.h>
#include <intrin.h>

/* no crt: the compiler may emit these */
#pragma function(memset)
#pragma function(memcpy)
void *memset(void *d, int c, size_t n) { __stosb((unsigned char *)d, (unsigned char)c, n); return d; }
void *memcpy(void *d, const void *s, size_t n) { __movsb((unsigned char *)d, (const unsigned char *)s, n); return d; }

wchar_t g_dir[MAX_PATH];
wchar_t g_wg[MAX_PATH];
int g_wgok;

void w2u(const wchar_t *w, char *o, int cap)
{
    if (!WideCharToMultiByte(CP_UTF8, 0, w, -1, o, cap, NULL, NULL)) o[0] = 0;
}

void u2w(const char *u, wchar_t *o, int cap)
{
    if (!MultiByteToWideChar(CP_UTF8, 0, u, -1, o, cap)) o[0] = 0;
}

void conf_path(const wchar_t *name, wchar_t *out) { wsprintfW(out, L"%s\\%s.conf", g_dir, name); }
int file_exists(const wchar_t *p) { return GetFileAttributesW(p) != INVALID_FILE_ATTRIBUTES; }

char *read_file(const wchar_t *path, DWORD *len)
{
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD sz, got = 0;
    char *buf;
    if (f == INVALID_HANDLE_VALUE) return NULL;
    sz = GetFileSize(f, NULL);
    if (sz == INVALID_FILE_SIZE || sz > 65536) { CloseHandle(f); return NULL; }
    buf = (char *)HeapAlloc(GetProcessHeap(), 0, sz + 1);
    if (!buf) { CloseHandle(f); return NULL; }
    if (!ReadFile(f, buf, sz, &got, NULL) || got != sz) { HeapFree(GetProcessHeap(), 0, buf); CloseHandle(f); return NULL; }
    buf[sz] = 0;
    CloseHandle(f);
    *len = sz;
    return buf;
}

/* only ever called with paths inside g_dir; no temp files anywhere else */
int write_file(const wchar_t *path, const char *data, DWORD len)
{
    static const wchar_t sddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD put = 0;
    HANDLE f;
    int ok;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) return 0;
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    f = CreateFileW(path, GENERIC_WRITE | WRITE_DAC, 0, &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE)   /* CREATE_ALWAYS keeps the dacl of an existing file: set it again */
        SetFileSecurityW(path, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    if (f == INVALID_HANDLE_VALUE) return 0;
    ok = WriteFile(f, data, len, &put, NULL) && put == len;
    if (!FlushFileBuffers(f)) ok = 0;
    CloseHandle(f);
    return ok;
}

int random32(unsigned char *o)
{
    return BCryptGenRandom(NULL, o, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

/* SYSTEM + Administrators only, not inherited from ProgramData */
static int protect(const wchar_t *path, int dir)
{
    static const wchar_t sddl_dir[] = L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";
    static const wchar_t sddl_file[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    PSECURITY_DESCRIPTOR sd = NULL;
    int ok;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(dir ? sddl_dir : sddl_file, SDDL_REVISION_1, &sd, NULL)) return 0;
    ok = SetFileSecurityW(path, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd) != 0;
    LocalFree(sd);
    return ok;
}

int core_init_dir(void)
{
    static const wchar_t sddl[] = L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    WIN32_FIND_DATAW fd;
    wchar_t base[MAX_PATH], p[MAX_PATH];
    HANDLE h;
    int ok;

    if (!GetEnvironmentVariableW(L"ProgramData", base, MAX_PATH)) lstrcpyW(base, L"C:\\ProgramData");
    wsprintfW(g_dir, L"%s\\lightguard", base);

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, NULL)) return 0;
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    ok = CreateDirectoryW(g_dir, &sa) || GetLastError() == ERROR_ALREADY_EXISTS;
    LocalFree(sd);
    if (!ok) return 0;
    protect(g_dir, 1);   /* also tighten a directory that already existed */

    /* and every config already in it: a protected dir dacl does not reach existing files */
    wsprintfW(p, L"%s\\*.conf", g_dir);
    h = FindFirstFileW(p, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (lstrlenW(g_dir) + lstrlenW(fd.cFileName) + 2 > MAX_PATH) continue;
            wsprintfW(p, L"%s\\%s", g_dir, fd.cFileName);
            protect(p, 0);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return 1;
}

void core_find_wg(void)
{
    wchar_t pf[MAX_PATH];
    if (!GetEnvironmentVariableW(L"ProgramW6432", pf, MAX_PATH) &&
        !GetEnvironmentVariableW(L"ProgramFiles", pf, MAX_PATH))
        lstrcpyW(pf, L"C:\\Program Files");
    wsprintfW(g_wg, L"%s\\WireGuard\\wireguard.exe", pf);
    g_wgok = file_exists(g_wg);
}

/* ---------- services ---------- */
void svc_info(SC_HANDLE scm, const wchar_t *name, SvcInfo *si)
{
    static union { QUERY_SERVICE_CONFIGW c; BYTE b[2048]; } qb;
    wchar_t sn[96];
    SC_HANDLE s;
    SERVICE_STATUS st;
    DWORD need;
    memset(si, 0, sizeof *si);
    wsprintfW(sn, L"WireGuardTunnel$%s", name);
    s = OpenServiceW(scm, sn, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!s) return;
    si->installed = 1;
    if (QueryServiceStatus(s, &st)) si->state = st.dwCurrentState;
    if (QueryServiceConfigW(s, &qb.c, sizeof qb, &need)) si->autostart = qb.c.dwStartType == SERVICE_AUTO_START;
    CloseServiceHandle(s);
}

void svc_info_one(const wchar_t *name, SvcInfo *si)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    memset(si, 0, sizeof *si);
    if (!scm) return;
    svc_info(scm, name, si);
    CloseServiceHandle(scm);
}

int svc_op(const wchar_t *name, int op)
{
    wchar_t sn[96];
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT), s;
    SERVICE_STATUS st;
    int ok = 0;
    if (!scm) return 0;
    wsprintfW(sn, L"WireGuardTunnel$%s", name);
    s = OpenServiceW(scm, sn, SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG);
    if (s) {
        if (op == SVC_START) ok = StartServiceW(s, 0, NULL);
        else if (op == SVC_STOP) ok = ControlService(s, SERVICE_CONTROL_STOP, &st);
        else ok = ChangeServiceConfigW(s, SERVICE_NO_CHANGE, op == SVC_AUTO ? SERVICE_AUTO_START : SERVICE_DEMAND_START,
                                       SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
    return ok;
}

/* ---------- processes ---------- */
void core_pump(void)
{
    MSG m;
    while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

int run_wait(wchar_t *cmd, int hidden)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD code = (DWORD)-1;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, hidden ? CREATE_NO_WINDOW : 0, NULL, NULL, &si, &pi))
        return -1;
    CloseHandle(pi.hThread);
    while (MsgWaitForMultipleObjects(1, &pi.hProcess, FALSE, INFINITE, QS_ALLINPUT) == WAIT_OBJECT_0 + 1)
        core_pump();
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    return (int)code;
}

int wg_cmd(const wchar_t *verb, const wchar_t *arg)
{
    wchar_t cmd[2 * MAX_PATH + 64];
    if (!g_wgok) return -2;
    wsprintfW(cmd, L"\"%s\" /%s \"%s\"", g_wg, verb, arg);
    return run_wait(cmd, 1);
}
