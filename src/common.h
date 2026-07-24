// chainlite — common utilities: types, hex, serialization, logging, args.
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <ctime>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <optional>
#include <stdexcept>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <filesystem>
#include <random>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

using bytes  = std::vector<uint8_t>;
using H256   = std::array<uint8_t, 32>;
using Addr20 = std::array<uint8_t, 20>;
using Pub64  = std::array<uint8_t, 64>;
using Sig64  = std::array<uint8_t, 64>;

// ---------- hex ----------
inline std::string hexs(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
template <size_t N> inline std::string hexs(const std::array<uint8_t, N>& a) { return hexs(a.data(), N); }
inline std::string hexs(const bytes& b) { return hexs(b.data(), b.size()); }

inline int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
inline std::optional<bytes> unhex(const std::string& s) {
    if (s.size() % 2) return std::nullopt;
    bytes b; b.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int h = hexval(s[i]), l = hexval(s[i + 1]);
        if (h < 0 || l < 0) return std::nullopt;
        b.push_back((uint8_t)((h << 4) | l));
    }
    return b;
}
template <size_t N> inline std::optional<std::array<uint8_t, N>> unhex_n(const std::string& s) {
    auto b = unhex(s);
    if (!b || b->size() != N) return std::nullopt;
    std::array<uint8_t, N> a;
    memcpy(a.data(), b->data(), N);
    return a;
}
template <size_t N> inline bool is_zero(const std::array<uint8_t, N>& a) {
    for (auto c : a) if (c) return false;
    return true;
}

// ---------- little-endian serialization ----------
struct Writer {
    bytes b;
    void u8(uint8_t v)  { b.push_back(v); }
    void u16(uint16_t v){ b.push_back(v & 0xff); b.push_back((v >> 8) & 0xff); }
    void u32(uint32_t v){ for (int i = 0; i < 4; i++) b.push_back((v >> (8 * i)) & 0xff); }
    void u64(uint64_t v){ for (int i = 0; i < 8; i++) b.push_back((uint8_t)((v >> (8 * i)) & 0xff)); }
    void raw(const uint8_t* p, size_t n) { b.insert(b.end(), p, p + n); }
    template <size_t N> void arr(const std::array<uint8_t, N>& a) { raw(a.data(), N); }
    void blob(const bytes& v) { raw(v.data(), v.size()); }
};
struct Reader {
    const uint8_t* p; size_t n, off = 0;
    Reader(const uint8_t* p_, size_t n_) : p(p_), n(n_) {}
    Reader(const bytes& b) : p(b.data()), n(b.size()) {}
    void need(size_t k) { if (off + k > n) throw std::runtime_error("short read"); }
    uint8_t  u8()  { need(1); return p[off++]; }
    uint16_t u16() { need(2); uint16_t v = (uint16_t)(p[off] | (p[off + 1] << 8)); off += 2; return v; }
    uint32_t u32() { need(4); uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | p[off + i]; off += 4; return v; }
    uint64_t u64() { need(8); uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[off + i]; off += 8; return v; }
    template <size_t N> std::array<uint8_t, N> arr() { need(N); std::array<uint8_t, N> a; memcpy(a.data(), p + off, N); off += N; return a; }
    bytes blob(size_t k) { need(k); bytes b(p + off, p + off + k); off += k; return b; }
    size_t remaining() const { return n - off; }
};

// ---------- misc ----------
inline uint64_t now_s()  { return (uint64_t)time(nullptr); }
inline uint64_t now_ms() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline std::string strf(const char* fmt, ...) {
    char buf[4096];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return std::string(buf);
}
inline void logl(const char* tag, const std::string& msg) {
    time_t t = time(nullptr);
    struct tm tmv; localtime_s(&tmv, &t);
    printf("%02d:%02d:%02d [%-5s] %s\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, tag, msg.c_str());
    fflush(stdout);
}
inline std::mt19937_64& rng() {
    static thread_local std::mt19937_64 g(
        (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count()
        ^ ((uint64_t)GetCurrentProcessId() << 32)
        ^ ((uint64_t)GetCurrentThreadId() << 16));
    return g;
}

// ---------- command-line args:  --key value  [--flag value ...]  positionals ----------
struct Args {
    std::map<std::string, std::string> kv;
    std::vector<std::string> pos;
    void parse(int argc, char** argv) {
        for (int i = 1; i < argc; i++) {
            std::string a = argv[i];
            if (a.rfind("--", 0) == 0) {
                std::string k = a.substr(2);
                if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0) kv[k] = argv[++i];
                else kv[k] = "1";
            } else pos.push_back(a);
        }
    }
    std::string get(const std::string& k, const std::string& def = "") const {
        auto it = kv.find(k); return it == kv.end() ? def : it->second;
    }
    bool has(const std::string& k) const { return kv.count(k) > 0; }
};
