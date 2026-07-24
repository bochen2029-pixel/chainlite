// chainlite — tiny blocking HTTP/1.1 client (used by clctl and the GPU miner).
#pragma once
#include "common.h"

// Returns HTTP status code, or -1 on connection failure. Body written to `out`.
inline int http_req(const std::string& host, uint16_t port, const std::string& method,
                    const std::string& path, const std::string& body, std::string& out) {
    out.clear();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
    DWORD tmo = 8000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tmo, sizeof(tmo));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { closesocket(s); return -1; }
    if (connect(s, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(s); return -1; }

    std::string req = strf("%s %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Length: %zu\r\n"
                           "Connection: close\r\n\r\n",
                           method.c_str(), path.c_str(), host.c_str(), (unsigned)port, body.size()) + body;
    size_t off = 0;
    while (off < req.size()) {
        int n = send(s, req.data() + off, (int)(req.size() - off), 0);
        if (n <= 0) { closesocket(s); return -1; }
        off += n;
    }
    std::string resp;
    char buf[16384];
    for (;;) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, n);
        if (resp.size() > 64u * 1024 * 1024) break;
    }
    closesocket(s);

    size_t he = resp.find("\r\n\r\n");
    if (he == std::string::npos) return -1;
    int code = -1;
    size_t sp = resp.find(' ');
    if (sp != std::string::npos && sp + 4 <= resp.size()) code = atoi(resp.c_str() + sp + 1);
    out = resp.substr(he + 4);
    return code;
}

// Naive JSON field extractors — only for JSON that chainlite's own RPC emits.
inline std::string extract_json_str(const std::string& body, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    size_t p = body.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t e = body.find('"', p);
    return e == std::string::npos ? "" : body.substr(p, e - p);
}
inline long long extract_json_int(const std::string& body, const std::string& key, long long def = -1) {
    std::string pat = "\"" + key + "\":";
    size_t p = body.find(pat);
    if (p == std::string::npos) return def;
    p += pat.size();
    return atoll(body.c_str() + p);
}
