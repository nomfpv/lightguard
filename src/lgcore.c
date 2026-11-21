/* x25519 after tweetnacl (public domain), plus small helpers. no libc. */
#include "lgcore.h"

typedef long long i64;
typedef i64 gf[16];

static const gf C121665 = { 0xDB41, 1 };

static void car(gf o)
{
    int i;
    i64 c;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536;
    }
}

static void sel(gf p, gf q, int b)
{
    i64 t, c = ~((i64)b - 1);
    int i;
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack(lg_u8 *o, const gf n)
{
    int i, j, b;
    gf m, t;
    for (i = 0; i < 16; i++) t[i] = n[i];
    car(t); car(t); car(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) {
        o[2 * i] = (lg_u8)(t[i] & 0xff);
        o[2 * i + 1] = (lg_u8)(t[i] >> 8);
    }
}

static void unpack(gf o, const lg_u8 *n)
{
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void Z(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void M(gf o, const gf a, const gf b)
{
    i64 t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car(o);
    car(o);
}

static void S(gf o, const gf a) { M(o, a, a); }

static void inv(gf o, const gf i)
{
    gf c;
    int a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
    lg_wipe(c, sizeof c);
}

void lg_x25519(lg_u8 out[32], const lg_u8 k[32], const lg_u8 u[32])
{
    lg_u8 z[32];
    i64 x[80], r;
    int i;
    gf a, b, c, d, e, f;

    for (i = 0; i < 31; i++) z[i] = k[i];
    z[31] = (lg_u8)((k[31] & 127) | 64);
    z[0] &= 248;
    unpack(x, u);
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel(a, b, (int)r);
        sel(c, d, (int)r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, C121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel(a, b, (int)r);
        sel(c, d, (int)r);
    }
    for (i = 0; i < 16; i++) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    inv(x + 32, x + 32);
    M(x + 16, x + 16, x + 32);
    pack(out, x + 16);
    /* scalar and ladder state are secret */
    lg_wipe(z, sizeof z);
    lg_wipe(x, sizeof x);
    lg_wipe(a, sizeof a); lg_wipe(b, sizeof b); lg_wipe(c, sizeof c);
    lg_wipe(d, sizeof d); lg_wipe(e, sizeof e); lg_wipe(f, sizeof f);
    r = 0;
    (void)r;
}

/* a store through a volatile pointer cannot be dropped as a dead store */
void lg_wipe(void *p, size_t n)
{
    volatile lg_u8 *v = (volatile lg_u8 *)p;
    while (n--) *v++ = 0;
}

void lg_clamp(lg_u8 k[32])
{
    k[0] &= 248;
    k[31] = (lg_u8)((k[31] & 127) | 64);
}

void lg_pubkey(lg_u8 pub[32], const lg_u8 priv[32])
{
    lg_u8 base[32];
    int i;
    for (i = 0; i < 32; i++) base[i] = 0;
    base[0] = 9;
    lg_x25519(pub, priv, base);
}

/* ---- base64 ---- */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void lg_b64enc(char out[45], const lg_u8 in[32])
{
    int i, o = 0;
    for (i = 0; i + 3 <= 32; i += 3) {
        out[o++] = B64[in[i] >> 2];
        out[o++] = B64[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[o++] = B64[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
        out[o++] = B64[in[i + 2] & 63];
    }
    out[o++] = B64[in[30] >> 2];
    out[o++] = B64[((in[30] & 3) << 4) | (in[31] >> 4)];
    out[o++] = B64[(in[31] & 15) << 2];
    out[o++] = '=';
    out[o] = 0;
}

static int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int lg_b64dec(const char *s, lg_u8 out[32])
{
    /* 44 chars = 10 full groups (30 bytes) + "xxx=" (2 bytes) */
    int i, g, v[4], o = 0;
    for (i = 0; i < 44; i++) if (!s[i]) return 0;
    if (s[44] || s[43] != '=') return 0;
    for (g = 0; g < 11; g++) {
        int n = (g == 10) ? 3 : 4;
        v[3] = 0;
        for (i = 0; i < n; i++) {
            v[i] = b64val(s[g * 4 + i]);
            if (v[i] < 0) return 0;
        }
        out[o++] = (lg_u8)((v[0] << 2) | (v[1] >> 4));
        out[o++] = (lg_u8)(((v[1] & 15) << 4) | (v[2] >> 2));
        if (g == 10) {
            if (v[2] & 3) return 0;
        } else {
            out[o++] = (lg_u8)(((v[2] & 3) << 6) | v[3]);
        }
    }
    return o == 32;
}

/* ---- small string helpers ---- */

static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

static int ieqn(const char *a, size_t n, const char *lit)
{
    size_t i;
    if (slen(lit) != n) return 0;
    for (i = 0; i < n; i++) if (lower(a[i]) != lower(lit[i])) return 0;
    return 1;
}

static int is_ws(char c) { return c == ' ' || c == '\t' || c == '\r'; }

static void put(char *dst, size_t cap, const char *s, size_t n)
{
    size_t i;
    if (n >= cap) n = cap - 1;
    for (i = 0; i < n; i++) dst[i] = s[i];
    dst[n] = 0;
}

/* append sep + s (n bytes) to dst when there is room */
static void add(char *dst, size_t cap, const char *sep, const char *s, size_t n)
{
    size_t l = slen(dst), sl = slen(sep), i;
    if (l + sl + n + 1 > cap) return;
    for (i = 0; i < sl; i++) dst[l++] = sep[i];
    for (i = 0; i < n; i++) dst[l++] = s[i];
    dst[l] = 0;
}

int lg_name_ok(const char *name, size_t maxlen)
{
    size_t i, n = slen(name);
    if (n == 0 || n > maxlen) return 0;
    for (i = 0; i < n; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '=' || c == '+' || c == '.' || c == '-')) return 0;
    }
    return 1;
}

/* ---- conf ---- */

static void setf(char *dst, size_t cap, int join, const char *s, size_t n)
{
    if (join && dst[0]) add(dst, cap, ", ", s, n);
    else put(dst, cap, s, n);
}

void lg_conf_parse(lg_conf *c, const char *t, size_t n)
{
    size_t i = 0, p = sizeof(*c);
    int sect = 0;
    char *z = (char *)c;
    while (p--) z[p] = 0;

    if (n >= 3 && (lg_u8)t[0] == 0xEF && (lg_u8)t[1] == 0xBB && (lg_u8)t[2] == 0xBF) i = 3;

    while (i < n) {
        size_t s = i, e, eq;
        while (i < n && t[i] != '\n') i++;
        e = i;
        if (i < n) i++;
        while (s < e && is_ws(t[s])) s++;
        while (e > s && is_ws(t[e - 1])) e--;
        if (s == e || t[s] == '#' || t[s] == ';') continue;

        if (t[s] == '[') {
            if (ieqn(t + s, e - s, "[Interface]")) sect = 1;
            else if (ieqn(t + s, e - s, "[Peer]")) { sect = 2; c->npeers++; }
            else sect = 0;
            continue;
        }
        if (sect == 0 || (sect == 2 && c->npeers > 1)) continue;

        for (eq = s; eq < e && t[eq] != '='; eq++) ;
        if (eq < e) {
            size_t ke = eq, vs = eq + 1;
            const char *k = t + s, *v;
            size_t kl, vl;
            while (ke > s && is_ws(t[ke - 1])) ke--;
            while (vs < e && is_ws(t[vs])) vs++;
            kl = ke - s; v = t + vs; vl = e - vs;
            if (sect == 1) {
                if (ieqn(k, kl, "PrivateKey")) { setf(c->priv, sizeof c->priv, 0, v, vl); continue; }
                if (ieqn(k, kl, "Address")) { setf(c->address, sizeof c->address, 1, v, vl); continue; }
                if (ieqn(k, kl, "DNS")) { setf(c->dns, sizeof c->dns, 1, v, vl); continue; }
            } else {
                if (ieqn(k, kl, "PublicKey")) { setf(c->peerpub, sizeof c->peerpub, 0, v, vl); continue; }
                if (ieqn(k, kl, "PresharedKey")) { setf(c->psk, sizeof c->psk, 0, v, vl); continue; }
                if (ieqn(k, kl, "Endpoint")) { setf(c->endpoint, sizeof c->endpoint, 0, v, vl); continue; }
                if (ieqn(k, kl, "PersistentKeepalive")) { setf(c->keepalive, sizeof c->keepalive, 0, v, vl); continue; }
                if (ieqn(k, kl, "AllowedIPs")) { setf(c->allowed, sizeof c->allowed, 1, v, vl); continue; }
            }
        }
        /* unknown line: keep verbatim */
        if (sect == 1) {
            add(c->extra_if, sizeof c->extra_if, "", t + s, e - s);
            add(c->extra_if, sizeof c->extra_if, "", "\n", 1);
        } else {
            add(c->extra_peer, sizeof c->extra_peer, "", t + s, e - s);
            add(c->extra_peer, sizeof c->extra_peer, "", "\n", 1);
        }
    }
}

typedef struct { char *p; size_t cap, n; int bad; } W;

static void wput(W *w, const char *s)
{
    while (*s) {
        if (w->n + 1 >= w->cap) { w->bad = 1; return; }
        w->p[w->n++] = *s++;
    }
}

static void wkv(W *w, const char *k, const char *v)
{
    if (!*v) return;
    wput(w, k); wput(w, " = "); wput(w, v); wput(w, "\n");
}

static int clean(const char *s)
{
    for (; *s; s++) if (*s == '\n' || *s == '\r') return 0;
    return 1;
}

int lg_conf_format(const lg_conf *c, char *out, size_t cap)
{
    W w;
    if (!cap) return -1;
    if (!clean(c->priv) || !clean(c->address) || !clean(c->dns) || !clean(c->peerpub) || !clean(c->psk) ||
        !clean(c->endpoint) || !clean(c->allowed) || !clean(c->keepalive)) return -1;
    w.p = out; w.cap = cap; w.n = 0; w.bad = 0;
    wput(&w, "[Interface]\n");
    wkv(&w, "PrivateKey", c->priv);
    wkv(&w, "Address", c->address);
    wkv(&w, "DNS", c->dns);
    wput(&w, c->extra_if);
    wput(&w, "\n[Peer]\n");
    wkv(&w, "PublicKey", c->peerpub);
    wkv(&w, "PresharedKey", c->psk);
    wkv(&w, "Endpoint", c->endpoint);
    wkv(&w, "AllowedIPs", c->allowed);
    wkv(&w, "PersistentKeepalive", c->keepalive);
    wput(&w, c->extra_peer);
    if (w.bad) return -1;
    out[w.n] = 0;
    return (int)w.n;
}

/* ---- selftest ---- */

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

static void unhex(lg_u8 o[32], const char *h)
{
    int i;
    for (i = 0; i < 32; i++) o[i] = (lg_u8)((hexv(h[2 * i]) << 4) | hexv(h[2 * i + 1]));
}

static int same(const lg_u8 *a, const lg_u8 *b)
{
    int i, d = 0;
    for (i = 0; i < 32; i++) d |= a[i] ^ b[i];
    return d == 0;
}

static int check(void (*out)(const char *), const char *name, int ok)
{
    out(ok ? "ok    " : "FAIL  ");
    out(name);
    out("\n");
    return ok ? 0 : 1;
}

int lg_selftest(void (*out)(const char *line))
{
    lg_u8 k[32], u[32], want[32], got[32], tmp[32], pa[32], pb[32], sa[32], sb[32];
    char b64[45];
    int fails = 0, i, j;
    static const char sample[] =
        "[Interface]\nPrivateKey = AAAA\nAddress = 10.66.66.2/24\nDNS = 1.1.1.1\n\n"
        "[Peer]\nPublicKey = BBBB\nEndpoint = h:1\nAllowedIPs = 10.66.66.0/24\nAllowedIPs = 192.168.50.0/24\n";
    static lg_conf c;
    char buf[1024];

    unhex(k, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    unhex(u, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    unhex(want, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    lg_x25519(got, k, u);
    fails += check(out, "rfc7748 5.2 vector 1", same(got, want));

    unhex(k, "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    unhex(u, "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    unhex(want, "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    lg_x25519(got, k, u);
    fails += check(out, "rfc7748 5.2 vector 2", same(got, want));

    for (i = 0; i < 32; i++) k[i] = u[i] = 0;
    k[0] = u[0] = 9;
    for (i = 1; i <= 1000; i++) {
        lg_x25519(got, k, u);
        for (j = 0; j < 32; j++) { u[j] = k[j]; k[j] = got[j]; }
        if (i == 1) {
            unhex(want, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
            fails += check(out, "rfc7748 5.2 iterated x1", same(k, want));
        }
    }
    unhex(want, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
    fails += check(out, "rfc7748 5.2 iterated x1000", same(k, want));

    unhex(sa, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    unhex(sb, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    unhex(want, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    lg_pubkey(pa, sa);
    fails += check(out, "rfc7748 6.1 alice public", same(pa, want));
    unhex(want, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    lg_pubkey(pb, sb);
    fails += check(out, "rfc7748 6.1 bob public", same(pb, want));
    unhex(want, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    lg_x25519(got, sa, pb);
    lg_x25519(tmp, sb, pa);
    fails += check(out, "rfc7748 6.1 shared secret", same(got, want) && same(tmp, want));

    lg_b64enc(b64, pa);
    fails += check(out, "base64 roundtrip", lg_b64dec(b64, got) && same(got, pa));
    fails += check(out, "base64 rejects junk", !lg_b64dec("not a key", got));

    lg_conf_parse(&c, sample, sizeof sample - 1);
    fails += check(out, "conf parse", c.npeers == 1 && slen(c.allowed) == 30 && slen(c.dns) == 7 && !c.extra_if[0]);
    fails += check(out, "conf format", lg_conf_format(&c, buf, sizeof buf) > 0);
    return fails;
}
