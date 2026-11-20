/* windows logic without any ui: paths, files, keygen rng, tunnel services, wireguard.exe */
#ifndef WINCORE_H
#define WINCORE_H

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>

#define NAME_MAX_LEN 32

void *memset(void *d, int c, size_t n);
void *memcpy(void *d, const void *s, size_t n);

extern wchar_t g_dir[MAX_PATH];   /* %ProgramData%\lightguard */
extern wchar_t g_wg[MAX_PATH];    /* wireguard.exe */
extern int g_wgok;                /* wireguard.exe present */

void w2u(const wchar_t *w, char *o, int cap);
void u2w(const char *u, wchar_t *o, int cap);

/* config folder (created with SYSTEM + Administrators only ACL) and files */
int  core_init_dir(void);
void core_find_wg(void);
void conf_path(const wchar_t *name, wchar_t *out);
int  file_exists(const wchar_t *p);
char *read_file(const wchar_t *path, DWORD *len);   /* HeapFree(GetProcessHeap(),0,p) when done */
int  write_file(const wchar_t *path, const char *data, DWORD len);
int  random32(unsigned char *o);

/* services: WireGuardTunnel$<name> */
typedef struct { int installed; DWORD state; int autostart; } SvcInfo;
void svc_info(SC_HANDLE scm, const wchar_t *name, SvcInfo *si);
void svc_info_one(const wchar_t *name, SvcInfo *si);
enum { SVC_START, SVC_STOP, SVC_AUTO, SVC_MANUAL };
int  svc_op(const wchar_t *name, int op);

/* runs a command and waits; keeps the calling thread's messages flowing. -1 = could not start */
void core_pump(void);
int  run_wait(wchar_t *cmd, int hidden);

/* wireguard.exe /installtunnelservice <conf> or /uninstalltunnelservice <name>; returns exit code, -2 if missing */
int  wg_cmd(const wchar_t *verb, const wchar_t *arg);

#endif
