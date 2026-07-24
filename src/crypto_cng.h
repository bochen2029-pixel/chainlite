// chainlite — ECDSA P-256 signatures via Windows CNG (bcrypt.dll).
// Zero external dependencies: keygen, sign, verify all come from the OS.
// (Bitcoin uses ECDSA too, on secp256k1; the concept is identical.)
#pragma once
#include "common.h"
#include "sha256.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef BCRYPT_ECDSA_PUBLIC_P256_MAGIC
#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC  0x31534345
#endif
#ifndef BCRYPT_ECDSA_PRIVATE_P256_MAGIC
#define BCRYPT_ECDSA_PRIVATE_P256_MAGIC 0x32534345
#endif

inline BCRYPT_ALG_HANDLE ecdsa_alg() {
    static BCRYPT_ALG_HANDLE h = nullptr;
    static std::once_flag once;
    std::call_once(once, [] {
        if (BCryptOpenAlgorithmProvider(&h, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0)
            h = nullptr;
    });
    return h;
}

// blob = full BCRYPT_ECCPRIVATE_BLOB (8-byte header + X + Y + d, 104 bytes for P-256)
struct KeyPair {
    Pub64 pub{};
    bytes blob;
    bool valid() const { return blob.size() == 104; }
};

inline Addr20 addr_of(const Pub64& pub) {
    H256 h = sha256(pub.data(), 64);
    Addr20 a;
    memcpy(a.data(), h.data(), 20);
    return a;
}

inline std::optional<KeyPair> kp_generate() {
    BCRYPT_ALG_HANDLE alg = ecdsa_alg();
    if (!alg) return std::nullopt;
    BCRYPT_KEY_HANDLE k = nullptr;
    if (BCryptGenerateKeyPair(alg, &k, 256, 0) != 0) return std::nullopt;
    if (BCryptFinalizeKeyPair(k, 0) != 0) { BCryptDestroyKey(k); return std::nullopt; }
    ULONG len = 0;
    if (BCryptExportKey(k, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &len, 0) != 0) { BCryptDestroyKey(k); return std::nullopt; }
    bytes blob(len);
    if (BCryptExportKey(k, nullptr, BCRYPT_ECCPRIVATE_BLOB, blob.data(), len, &len, 0) != 0) { BCryptDestroyKey(k); return std::nullopt; }
    BCryptDestroyKey(k);
    blob.resize(len);
    if (blob.size() != 104) return std::nullopt;
    KeyPair kp;
    kp.blob = blob;
    memcpy(kp.pub.data(), blob.data() + 8, 64);   // X||Y
    return kp;
}

inline std::optional<Sig64> kp_sign(const KeyPair& kp, const H256& digest) {
    BCRYPT_ALG_HANDLE alg = ecdsa_alg();
    if (!alg || !kp.valid()) return std::nullopt;
    BCRYPT_KEY_HANDLE k = nullptr;
    if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPRIVATE_BLOB, &k,
                            (PUCHAR)kp.blob.data(), (ULONG)kp.blob.size(), 0) != 0) return std::nullopt;
    Sig64 sig{};
    ULONG out = 0;
    NTSTATUS st = BCryptSignHash(k, nullptr, (PUCHAR)digest.data(), 32, sig.data(), 64, &out, 0);
    BCryptDestroyKey(k);
    if (st != 0 || out != 64) return std::nullopt;
    return sig;
}

inline bool sig_verify(const Pub64& pub, const H256& digest, const Sig64& sig) {
    BCRYPT_ALG_HANDLE alg = ecdsa_alg();
    if (!alg) return false;
    uint8_t blob[72];
    BCRYPT_ECCKEY_BLOB* h = (BCRYPT_ECCKEY_BLOB*)blob;
    h->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    h->cbKey = 32;
    memcpy(blob + 8, pub.data(), 64);
    BCRYPT_KEY_HANDLE k = nullptr;
    if (BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &k, blob, sizeof(blob), 0) != 0) return false;
    NTSTATUS st = BCryptVerifySignature(k, nullptr, (PUCHAR)digest.data(), 32, (PUCHAR)sig.data(), 64, 0);
    BCryptDestroyKey(k);
    return st == 0;
}

// Key file format: line 1 magic, line 2 hex of the 104-byte private blob.
inline bool kp_save(const KeyPair& kp, const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "wb") || !f) return false;
    std::string s = "chainlite-key-v1\n" + hexs(kp.blob) + "\n";
    fwrite(s.data(), 1, s.size(), f);
    fclose(f);
    return true;
}
inline std::optional<KeyPair> kp_load(const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") || !f) return std::nullopt;
    char buf[512] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    std::string s(buf, n);
    if (s.rfind("chainlite-key-v1\n", 0) != 0) return std::nullopt;
    std::string hx = s.substr(17);
    while (!hx.empty() && (hx.back() == '\n' || hx.back() == '\r' || hx.back() == ' ')) hx.pop_back();
    auto blob = unhex(hx);
    if (!blob || blob->size() != 104) return std::nullopt;
    KeyPair kp;
    kp.blob = *blob;
    memcpy(kp.pub.data(), kp.blob.data() + 8, 64);
    return kp;
}
// Load existing key or create + save a new one.
inline std::optional<KeyPair> kp_load_or_create(const std::string& path) {
    auto kp = kp_load(path);
    if (kp) return kp;
    kp = kp_generate();
    if (!kp) return std::nullopt;
    if (!kp_save(*kp, path)) return std::nullopt;
    return kp;
}
