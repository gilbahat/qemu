/*
 * Emulated AMD SEV-SNP attestation-flow test.
 *
 * Nothing here checks that a report is trustworthy -- it cannot be, there is no
 * key, and the emulation refuses to pretend otherwise. What is checkable is
 * the flow, and on SNP it is a demanding one: SNP_GUEST_REQUEST carries
 * its payload sealed with AES-256-GCM under a VMPCK from the secrets page, with
 * the message header from offset 0x30 as additional authenticated data and the
 * sequence number as the nonce.  A guest that gets any of that wrong sees a
 * failed authentication and no report, which is what hardware would do.
 *
 * So this test carries its own AES-256-GCM.  That is the point: it proves the
 * emulator interoperates with an independent implementation of the same
 * construction, rather than with itself.
 *
 * It also asserts what must *not* work: the report signature is the fixed
 * not-real marker, a tampered tag is refused, the wrong VMPCK is refused, and
 * the extended request -- which would imply a certificate chain -- is refused.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <minilib.h>

#define MSR_AMD64_SEV_ES_GHCB   0xc0010130
#define GHCB_MSR_REG_GPA_REQ    0x012
#define GHCB_MSR_REG_GPA_RESP   0x013

#define SVM_EXIT_GUEST_REQUEST      0x80000011
#define SVM_EXIT_EXT_GUEST_REQUEST  0x80000012

#define GHCB_OFF_SW_EXITCODE    0x390
#define GHCB_OFF_SW_EXITINFO1   0x398
#define GHCB_OFF_SW_EXITINFO2   0x3a0
#define GHCB_OFF_VALID_BITMAP   0x3f0
#define GHCB_BIT(off)           ((off) / 8)

#define MSG_HDR_LEN             96
#define MSG_AAD_OFF             0x30
#define MSG_AAD_LEN             (MSG_HDR_LEN - MSG_AAD_OFF)
#define AEAD_AES_256_GCM        1
#define MSG_HDR_VERSION         1
#define MSG_REPORT_REQ          5
#define MSG_REPORT_RSP          6

#define VMPCK_LEN               32
#define REPORTDATA_LEN          64
#define MEASUREMENT_LEN         48
#define REPORT_LEN              1184

/* ATTESTATION_REPORT offsets. */
#define R_OFF_VERSION           0
#define R_OFF_REPORTDATA        0x50
#define R_OFF_MEASUREMENT       0x90
#define R_OFF_SIGNATURE         0x2a0

#define FAKE_SIG "QEMU-TCG-EMULATED-SEV-SNP-NOT-REAL!!"

static int failures;

static void check(int ok, const char *what)
{
    if (!ok) {
        failures++;
        ml_printf("FAIL: %s\n", what);
    }
}

static void wrmsr(unsigned int idx, unsigned long val)
{
    __asm__ __volatile__("wrmsr"
                         : : "c"(idx), "a"((unsigned int)val),
                             "d"((unsigned int)(val >> 32)));
}

static unsigned long rdmsr(unsigned int idx)
{
    unsigned int lo, hi;

    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(idx));
    return ((unsigned long)hi << 32) | lo;
}

static void vmgexit(void)
{
    __asm__ __volatile__(".byte 0xf3,0x0f,0x01,0xd9" : : : "memory");
}

static void *mem_set(void *d, int c, unsigned long n)
{
    unsigned char *p = d;
    unsigned long i;

    for (i = 0; i < n; i++) {
        p[i] = (unsigned char)c;
    }
    return d;
}

static void mem_cpy(void *d, const void *s, unsigned long n)
{
    unsigned char *p = d;
    const unsigned char *q = s;
    unsigned long i;

    for (i = 0; i < n; i++) {
        p[i] = q[i];
    }
}

static int mem_eq(const void *a, const void *b, unsigned long n)
{
    const unsigned char *p = a, *q = b;
    unsigned long i;

    for (i = 0; i < n; i++) {
        if (p[i] != q[i]) {
            return 0;
        }
    }
    return 1;
}

static int is_zero(const void *a, unsigned long n)
{
    const unsigned char *p = a;
    unsigned long i;

    for (i = 0; i < n; i++) {
        if (p[i]) {
            return 0;
        }
    }
    return 1;
}

/* --- AES-256, enough of it to drive GCM ---------------------------------- */

static const unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static unsigned char xtime(unsigned char a)
{
    return (unsigned char)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
}

static unsigned char rkey[15 * 16];

static void aes256_expand(const unsigned char *key)
{
    int i;
    unsigned char t[4];
    unsigned char rcon = 1;

    mem_cpy(rkey, key, 32);
    for (i = 8; i < 60; i++) {
        mem_cpy(t, rkey + (i - 1) * 4, 4);
        if (i % 8 == 0) {
            unsigned char tmp = t[0];

            t[0] = (unsigned char)(sbox[t[1]] ^ rcon);
            t[1] = sbox[t[2]];
            t[2] = sbox[t[3]];
            t[3] = sbox[tmp];
            rcon = xtime(rcon);
        } else if (i % 8 == 4) {
            t[0] = sbox[t[0]];
            t[1] = sbox[t[1]];
            t[2] = sbox[t[2]];
            t[3] = sbox[t[3]];
        }
        rkey[i * 4 + 0] = rkey[(i - 8) * 4 + 0] ^ t[0];
        rkey[i * 4 + 1] = rkey[(i - 8) * 4 + 1] ^ t[1];
        rkey[i * 4 + 2] = rkey[(i - 8) * 4 + 2] ^ t[2];
        rkey[i * 4 + 3] = rkey[(i - 8) * 4 + 3] ^ t[3];
    }
}

static void aes256_encrypt(const unsigned char *in, unsigned char *out)
{
    unsigned char s[16];
    int round, i;

    mem_cpy(s, in, 16);
    for (i = 0; i < 16; i++) {
        s[i] ^= rkey[i];
    }

    for (round = 1; round <= 14; round++) {
        unsigned char t[16];

        for (i = 0; i < 16; i++) {
            s[i] = sbox[s[i]];
        }
        /* ShiftRows, column-major state. */
        for (i = 0; i < 4; i++) {
            t[i * 4 + 0] = s[((i + 0) % 4) * 4 + 0];
            t[i * 4 + 1] = s[((i + 1) % 4) * 4 + 1];
            t[i * 4 + 2] = s[((i + 2) % 4) * 4 + 2];
            t[i * 4 + 3] = s[((i + 3) % 4) * 4 + 3];
        }
        mem_cpy(s, t, 16);

        if (round != 14) {
            for (i = 0; i < 4; i++) {
                unsigned char *c = s + i * 4;
                unsigned char a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];

                c[0] = (unsigned char)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
                c[1] = (unsigned char)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
                c[2] = (unsigned char)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
                c[3] = (unsigned char)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
            }
        }
        for (i = 0; i < 16; i++) {
            s[i] ^= rkey[round * 16 + i];
        }
    }
    mem_cpy(out, s, 16);
}

/* --- GHASH and GCM, matching the emulator's construction ----------------- */

static void ghash_mul(unsigned char *x, const unsigned char *h)
{
    unsigned char z[16], v[16];
    int i, j;

    mem_set(z, 0, 16);
    mem_cpy(v, h, 16);
    for (i = 0; i < 128; i++) {
        int lsb;

        if (x[i / 8] & (0x80 >> (i % 8))) {
            for (j = 0; j < 16; j++) {
                z[j] ^= v[j];
            }
        }
        lsb = v[15] & 1;
        for (j = 15; j > 0; j--) {
            v[j] = (unsigned char)((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] >>= 1;
        if (lsb) {
            v[0] ^= 0xe1;
        }
    }
    mem_cpy(x, z, 16);
}

static void ghash_update(unsigned char *y, const unsigned char *h,
                         const unsigned char *data, unsigned long len)
{
    while (len) {
        unsigned char block[16];
        unsigned long n = len < 16 ? len : 16;
        int j;

        mem_set(block, 0, 16);
        mem_cpy(block, data, n);
        for (j = 0; j < 16; j++) {
            y[j] ^= block[j];
        }
        ghash_mul(y, h);
        data += n;
        len -= n;
    }
}

static void be64_store(unsigned char *p, unsigned long v)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = (unsigned char)(v & 0xff);
        v >>= 8;
    }
}

static void inc32(unsigned char *ctr)
{
    int i;

    for (i = 15; i >= 12; i--) {
        if (++ctr[i]) {
            break;
        }
    }
}

/*
 * @decrypt selects which buffer the tag is computed over.  GCM always
 * authenticates the *ciphertext*, which is the input when opening and the
 * output when sealing.  Getting that backwards is the classic way to write a
 * GCM that only ever talks to itself.
 */
static void gcm(const unsigned char *key, const unsigned char *iv,
                const unsigned char *aad, unsigned long aadlen,
                const unsigned char *in, unsigned char *out, unsigned long len,
                unsigned char *tag, int decrypt)
{
    unsigned char h[16], j0[16], ctr[16], stream[16], y[16], lens[16], ej0[16];
    unsigned char zero[16];
    unsigned long done = 0;
    int i;

    aes256_expand(key);
    mem_set(zero, 0, 16);
    aes256_encrypt(zero, h);

    mem_set(j0, 0, 16);
    mem_cpy(j0, iv, 12);
    j0[15] = 1;

    mem_cpy(ctr, j0, 16);
    while (done < len) {
        unsigned long n = (len - done) < 16 ? (len - done) : 16;

        inc32(ctr);
        aes256_encrypt(ctr, stream);
        for (i = 0; i < (int)n; i++) {
            out[done + i] = in[done + i] ^ stream[i];
        }
        done += n;
    }

    mem_set(y, 0, 16);
    ghash_update(y, h, aad, aadlen);
    ghash_update(y, h, decrypt ? in : out, len);
    be64_store(lens, aadlen * 8);
    be64_store(lens + 8, len * 8);
    for (i = 0; i < 16; i++) {
        y[i] ^= lens[i];
    }
    ghash_mul(y, h);
    aes256_encrypt(j0, ej0);
    for (i = 0; i < 16; i++) {
        tag[i] = y[i] ^ ej0[i];
    }
}

/* --- the guest-message protocol ------------------------------------------ */

struct msg_hdr {
    unsigned char authtag[32];
    unsigned long msg_seqno;
    unsigned char rsvd1[8];
    unsigned char algo;
    unsigned char hdr_version;
    unsigned short hdr_sz;
    unsigned char msg_type;
    unsigned char msg_version;
    unsigned short msg_sz;
    unsigned int rsvd2;
    unsigned char msg_vmpck;
    unsigned char rsvd3[35];
} __attribute__((packed));

struct report_req {
    unsigned char report_data[REPORTDATA_LEN];
    unsigned int vmpl;
    unsigned char reserved[28];
} __attribute__((packed));

static unsigned char ghcb[4096] __attribute__((aligned(4096)));
static unsigned char reqpage[4096] __attribute__((aligned(4096)));
static unsigned char rsppage[8192] __attribute__((aligned(4096)));
static unsigned char plain[4096];
static unsigned char vmpck[VMPCK_LEN];

static unsigned long *ghcb_at(unsigned int off)
{
    return (unsigned long *)&ghcb[off];
}

static void ghcb_mark(unsigned int off)
{
    unsigned int bit = GHCB_BIT(off);

    ghcb_at(GHCB_OFF_VALID_BITMAP)[bit / 64] |= 1UL << (bit % 64);
}

static void iv_of(unsigned char *iv, unsigned long seqno)
{
    int i;

    mem_set(iv, 0, 12);
    for (i = 0; i < 8; i++) {
        iv[i] = (unsigned char)((seqno >> (8 * i)) & 0xff);
    }
}

/*
 * The secrets page holds the VMPCKs. On hardware firmware tells the guest
 * where it is; here x-sev-snp-secrets-gpa places it and the address is agreed
 * out-of-band, which is what firmware is doing anyway.
 */
#define SECRETS_GPA     0x4000000UL
#define SECRETS_VMPCK0  (SECRETS_GPA + 0x20)

static unsigned long guest_request(unsigned long seqno, unsigned int vmpck_id,
                                   const unsigned char *rd, int corrupt_tag)
{
    struct msg_hdr hdr;
    struct report_req req;
    unsigned char iv[12];
    unsigned char ct[sizeof(struct report_req)];

    mem_set(&req, 0, sizeof(req));
    mem_cpy(req.report_data, rd, REPORTDATA_LEN);
    req.vmpl = 0;

    mem_set(&hdr, 0, sizeof(hdr));
    hdr.algo = AEAD_AES_256_GCM;
    hdr.hdr_version = MSG_HDR_VERSION;
    hdr.hdr_sz = MSG_HDR_LEN;
    hdr.msg_type = MSG_REPORT_REQ;
    hdr.msg_version = 1;
    hdr.msg_sz = sizeof(struct report_req);
    hdr.msg_vmpck = (unsigned char)vmpck_id;
    hdr.msg_seqno = seqno;

    iv_of(iv, seqno);
    gcm(vmpck, iv, (const unsigned char *)&hdr + MSG_AAD_OFF, MSG_AAD_LEN,
        (const unsigned char *)&req, ct, sizeof(ct), hdr.authtag, 0);
    if (corrupt_tag) {
        hdr.authtag[0] ^= 0x01;
    }

    mem_cpy(reqpage, &hdr, sizeof(hdr));
    mem_cpy(reqpage + MSG_HDR_LEN, ct, sizeof(ct));
    mem_set(rsppage, 0, sizeof(rsppage));

    mem_set(ghcb, 0, sizeof(ghcb));
    *ghcb_at(GHCB_OFF_SW_EXITCODE) = SVM_EXIT_GUEST_REQUEST;
    *ghcb_at(GHCB_OFF_SW_EXITINFO1) = (unsigned long)reqpage;
    *ghcb_at(GHCB_OFF_SW_EXITINFO2) = (unsigned long)rsppage;
    ghcb_mark(GHCB_OFF_SW_EXITCODE);
    ghcb_mark(GHCB_OFF_SW_EXITINFO1);
    ghcb_mark(GHCB_OFF_SW_EXITINFO2);
    vmgexit();
    return *ghcb_at(GHCB_OFF_SW_EXITINFO2);
}

/* Open the response in place; returns the report pointer or NULL. */
static unsigned char *open_response(unsigned long seqno)
{
    struct msg_hdr *rh = (struct msg_hdr *)rsppage;
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned long n;

    if (rh->msg_type != MSG_REPORT_RSP) {
        return 0;
    }
    if (rh->msg_seqno != seqno + 1) {
        ml_printf("FAIL: response seqno %d, expected %d\n",
                  (int)rh->msg_seqno, (int)(seqno + 1));
        failures++;
        return 0;
    }
    n = rh->msg_sz;
    if (n > sizeof(plain)) {
        return 0;
    }

    iv_of(iv, rh->msg_seqno);
    gcm(vmpck, iv, (const unsigned char *)rh + MSG_AAD_OFF, MSG_AAD_LEN,
        rsppage + MSG_HDR_LEN, plain, n, tag, 1);
    if (!mem_eq(tag, rh->authtag, 16)) {
        failures++;
        ml_printf("FAIL: the response tag did not verify\n");
        return 0;
    }
    /* status(4) report_size(4) reserved(24), then the report. */
    return plain + 32;
}

int main(void)
{
    unsigned char rd[REPORTDATA_LEN];
    unsigned char *report;
    unsigned long resp, seqno = 1;
    int i;

    ml_printf("Emulated SEV-SNP attestation-flow test\n");

    /* Register a GHCB page: the request travels over the page protocol. */
    wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_REG_GPA_REQ | (unsigned long)ghcb);
    vmgexit();
    resp = rdmsr(MSR_AMD64_SEV_ES_GHCB);
    check((resp & 0xfff) == GHCB_MSR_REG_GPA_RESP, "GHCB registration");
    wrmsr(MSR_AMD64_SEV_ES_GHCB, 0);

    /* VMPCK0 comes out of the secrets page the emulator placed. */
    mem_cpy(vmpck, (const void *)SECRETS_VMPCK0, VMPCK_LEN);
    check(!is_zero(vmpck, VMPCK_LEN),
          "the secrets page has no VMPCK: is x-sev-snp-secrets-gpa set?");

    for (i = 0; i < REPORTDATA_LEN; i++) {
        rd[i] = (unsigned char)(0x30 + i);
    }

    /* A well-formed request must succeed and come back authenticated. */
    check(guest_request(seqno, 0, rd, 0) == 0, "guest request was refused");
    report = open_response(seqno);
    check(report != 0, "the response did not open");

    if (report) {
        check(mem_eq(report + R_OFF_REPORTDATA, rd, REPORTDATA_LEN),
              "REPORT_DATA was not reflected into the report");
        check(!is_zero(report + R_OFF_MEASUREMENT, MEASUREMENT_LEN),
              "the launch measurement is zero");
        ml_printf("measurement[0..7] = %x %x %x %x %x %x %x %x\n",
                  report[R_OFF_MEASUREMENT + 0], report[R_OFF_MEASUREMENT + 1],
                  report[R_OFF_MEASUREMENT + 2], report[R_OFF_MEASUREMENT + 3],
                  report[R_OFF_MEASUREMENT + 4], report[R_OFF_MEASUREMENT + 5],
                  report[R_OFF_MEASUREMENT + 6], report[R_OFF_MEASUREMENT + 7]);

        /* And it must be unmistakably not evidence. */
        check(mem_eq(report + R_OFF_SIGNATURE, FAKE_SIG, 36),
              "the report signature is not the not-real marker");
    }

    /* A tampered tag must be refused. */
    seqno += 2;
    check(guest_request(seqno, 0, rd, 1) != 0,
          "a request with a corrupted tag was accepted");

    /* The wrong VMPCK must be refused: the keys differ per index. */
    seqno += 2;
    check(guest_request(seqno, 1, rd, 0) != 0,
          "a request sealed with the wrong VMPCK was accepted");

    /* Different REPORT_DATA must give a different report. */
    seqno += 2;
    for (i = 0; i < REPORTDATA_LEN; i++) {
        rd[i] = (unsigned char)(0xf0 - i);
    }
    check(guest_request(seqno, 0, rd, 0) == 0, "second guest request refused");
    report = open_response(seqno);
    check(report != 0, "the second response did not open");
    if (report) {
        check(mem_eq(report + R_OFF_REPORTDATA, rd, REPORTDATA_LEN),
              "the second report has the wrong REPORT_DATA");
    }

    /* The extended request must be refused: there is no certificate chain. */
    mem_set(ghcb, 0, sizeof(ghcb));
    *ghcb_at(GHCB_OFF_SW_EXITCODE) = SVM_EXIT_EXT_GUEST_REQUEST;
    *ghcb_at(GHCB_OFF_SW_EXITINFO1) = (unsigned long)reqpage;
    *ghcb_at(GHCB_OFF_SW_EXITINFO2) = (unsigned long)rsppage;
    ghcb_mark(GHCB_OFF_SW_EXITCODE);
    ghcb_mark(GHCB_OFF_SW_EXITINFO1);
    ghcb_mark(GHCB_OFF_SW_EXITINFO2);
    vmgexit();
    check(*ghcb_at(GHCB_OFF_SW_EXITINFO2) != 0,
          "SNP_EXT_GUEST_REQUEST was not refused");

    if (failures) {
        ml_printf("%d failure(s)\n", failures);
        return 1;
    }

    ml_printf("All SEV-SNP attestation-flow checks passed\n");
    return 0;
}
