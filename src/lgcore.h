/* lightguard core: x25519, base64, wg conf parse/format, selftest.
   no libc needed, shared by the windows and linux front ends. */
#ifndef LGCORE_H
#define LGCORE_H

#include <stddef.h>

typedef unsigned char lg_u8;

/* curve25519 (rfc 7748) */
void lg_x25519(lg_u8 out[32], const lg_u8 k[32], const lg_u8 u[32]);
void lg_clamp(lg_u8 k[32]);
void lg_pubkey(lg_u8 pub[32], const lg_u8 priv[32]);

/* zero memory that held secrets; never optimised away */
void lg_wipe(void *p, size_t n);

/* base64 of a 32 byte key: 44 chars + nul */
void lg_b64enc(char out[45], const lg_u8 in[32]);
int  lg_b64dec(const char *s, lg_u8 out[32]);   /* 1 = ok */

/* tunnel names: [A-Za-z0-9_=+.-], 1..maxlen chars */
int lg_name_ok(const char *name, size_t maxlen);

/* single-peer wireguard config, utf-8 text */
typedef struct {
    char priv[64];
    char address[256];
    char peerpub[64];
    char psk[64];
    char endpoint[256];
    char allowed[512];
    char keepalive[16];
    char extra_if[1024];     /* unknown [Interface] lines, kept verbatim */
    char extra_peer[1024];   /* unknown [Peer] lines, kept verbatim */
    int  npeers;
} lg_conf;

void lg_conf_parse(lg_conf *c, const char *text, size_t len);
/* returns length written (nul terminated) or -1 if it does not fit / has bad chars */
int  lg_conf_format(const lg_conf *c, char *out, size_t cap);

/* runs rfc 7748 vectors, prints one line per check, returns number of failures */
int lg_selftest(void (*out)(const char *line));

#endif
