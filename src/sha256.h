// chainlite — SHA-256 implemented from the FIPS 180-4 spec. Verified against
// the standard test vectors in selftest.cpp. Also: proof-of-work helpers.
#pragma once
#include "common.h"

namespace sha {

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static const uint32_t IV[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

// One 64-byte block compression; `st` is updated in place.
inline void compress(uint32_t st[8], const uint8_t blk[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

struct Ctx {
    uint32_t st[8];
    uint8_t  buf[64];
    size_t   buflen = 0;
    uint64_t total = 0;
    Ctx() { memcpy(st, IV, sizeof(st)); }
    void update(const uint8_t* p, size_t n) {
        total += n;
        while (n) {
            size_t k = std::min(n, (size_t)64 - buflen);
            memcpy(buf + buflen, p, k);
            buflen += k; p += k; n -= k;
            if (buflen == 64) { compress(st, buf); buflen = 0; }
        }
    }
    void final(uint8_t out[32]) {
        uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t z = 0;
        while (buflen != 56) update(&z, 1);
        uint8_t len[8];
        for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
        update(len, 8);
        for (int i = 0; i < 8; i++) {
            out[i * 4]     = (uint8_t)(st[i] >> 24);
            out[i * 4 + 1] = (uint8_t)(st[i] >> 16);
            out[i * 4 + 2] = (uint8_t)(st[i] >> 8);
            out[i * 4 + 3] = (uint8_t)(st[i]);
        }
    }
};

} // namespace sha

inline H256 sha256(const uint8_t* p, size_t n) {
    sha::Ctx c; c.update(p, n);
    H256 h; c.final(h.data());
    return h;
}
inline H256 sha256(const bytes& b) { return sha256(b.data(), b.size()); }
inline H256 sha256(const std::string& s) { return sha256((const uint8_t*)s.data(), s.size()); }
// Double SHA-256, Bitcoin-style: hash ids and PoW use sha256d.
inline H256 sha256d(const uint8_t* p, size_t n) { H256 h1 = sha256(p, n); return sha256(h1.data(), 32); }
inline H256 sha256d(const bytes& b) { return sha256d(b.data(), b.size()); }

// PoW: a hash "meets difficulty `bits`" when, read big-endian, it has at least
// `bits` leading zero bits. Expected work per block = 2^bits hashes.
inline int leading_zero_bits(const H256& h) {
    int n = 0;
    for (int i = 0; i < 32; i++) {
        if (h[i] == 0) { n += 8; continue; }
        uint8_t b = h[i];
        while (!(b & 0x80)) { n++; b <<= 1; }
        return n;
    }
    return 256;
}
inline bool pow_ok(const H256& h, uint32_t bits) { return (uint32_t)leading_zero_bits(h) >= bits; }
inline uint64_t work_of(uint32_t bits) { return bits >= 63 ? ~0ull : (1ull << bits); }
