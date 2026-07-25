// chainlite — minimal HTTP server for the node's local RPC (127.0.0.1 only).
// One request per connection, handled sequentially; plenty for local use.
//
// Browser-facing security. The RPC listens on loopback, but "loopback" is NOT a
// trust boundary for a browser: every page you visit can issue requests to
// 127.0.0.1. Three defences, all necessary:
//
//   1. Host allow-list  - blocks DNS rebinding, where an attacker's domain
//      re-resolves to 127.0.0.1 so their page becomes *same-origin* with us.
//      A same-origin attacker gets past CORS entirely, so this check is what
//      actually stops it. Only literal loopback Host values are served.
//   2. Origin allow-list - Access-Control-Allow-Origin is echoed ONLY for the
//      sibling nodes of this network (never "*"). Any other origin gets no CORS
//      header, so the browser refuses to hand the response body to the script.
//   3. X-Chainlite header on writes - a cross-origin page cannot set a custom
//      header without a preflight, and preflights are answered only for
//      allow-listed origins. This is what stops drive-by POST /submit, which
//      CORS alone does not (a "simple" request is still delivered).
#pragma once
#include "common.h"

struct HttpReq {
    std::string method, path;
    std::map<std::string, std::string> query;
    std::map<std::string, std::string> headers;   // keys lowercased
    std::string body;
    std::string header(const std::string& k) const {
        auto it = headers.find(k);
        return it == headers.end() ? std::string() : it->second;
    }
};
struct HttpResp {
    int code = 200;
    std::string ctype = "application/json";
    std::string body;
    std::vector<std::pair<std::string, std::string>> extra;  // extra response headers
};

// "http://127.0.0.1:8501" -> 8501, or 0 if this is not a loopback http origin.
// Only http is accepted: an https page must not be able to reach the plain-http RPC.
inline uint16_t loopback_origin_port(const std::string& origin) {
    static const char* pre[] = { "http://127.0.0.1:", "http://localhost:", "http://[::1]:" };
    for (const char* p : pre) {
        size_t n = strlen(p);
        if (origin.size() > n && origin.compare(0, n, p) == 0) {
            const std::string tail = origin.substr(n);
            if (tail.empty() || tail.find_first_not_of("0123456789") != std::string::npos) return 0;
            unsigned long v = strtoul(tail.c_str(), nullptr, 10);
            return v > 0 && v <= 65535 ? (uint16_t)v : 0;
        }
    }
    return 0;
}
// A Host header is acceptable only when it names loopback literally. Anything
// else (a real domain) means the request arrived via DNS rebinding.
inline bool loopback_host(const std::string& host) {
    if (host.empty()) return false;
    std::string h = host;
    if (h[0] == '[') {                       // [::1]:8501
        size_t e = h.find(']');
        if (e == std::string::npos) return false;
        std::string inner = h.substr(1, e - 1);
        return inner == "::1";
    }
    size_t c = h.rfind(':');
    if (c != std::string::npos && h.find_first_not_of("0123456789", c + 1) == std::string::npos)
        h = h.substr(0, c);
    return h == "127.0.0.1" || h == "localhost" || h == "::1";
}

inline std::string url_decode(const std::string& s) {
    std::string o;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int h = hexval(s[i + 1]), l = hexval(s[i + 2]);
            if (h >= 0 && l >= 0) { o += (char)((h << 4) | l); i += 2; continue; }
        }
        o += (s[i] == '+') ? ' ' : s[i];
    }
    return o;
}

class RpcServer {
public:
    std::function<HttpResp(const HttpReq&)> handler;
    // Ports of this network's nodes (including our own). A browser page served by
    // one node legitimately queries its siblings, so those origins - and only
    // those - get CORS access.
    std::set<uint16_t> sibling_ports;

    bool start(uint16_t port) {
        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) return false;
        // Deliberately NO SO_REUSEADDR: on Windows it lets a *different* process
        // bind a port we already hold, which silently produced two launcher
        // instances sharing one port range (and would let any local process
        // hijack this RPC port). We want the second bind to fail loudly.
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (bind(listener, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(listener); return false; }
        if (listen(listener, 16) != 0) { closesocket(listener); return false; }
        running = true;
        th = std::thread([this] { loop(); });
        return true;
    }
    void stop() {
        running = false;
        if (listener != INVALID_SOCKET) { closesocket(listener); listener = INVALID_SOCKET; }
        if (th.joinable()) th.join();
    }

private:
    SOCKET listener = INVALID_SOCKET;
    std::thread th;
    std::atomic<bool> running{false};

    void loop() {
        while (running) {
            SOCKET c = accept(listener, nullptr, nullptr);
            if (c == INVALID_SOCKET) {
                if (!running) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                continue;
            }
            DWORD tmo = 5000;
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tmo, sizeof(tmo));
            int nd = 1;
            setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char*)&nd, sizeof(nd));
            handle(c);
            closesocket(c);
        }
    }

    void handle(SOCKET c) {
        std::string req;
        size_t hdr_end = std::string::npos;
        char buf[8192];
        while (req.size() < 1u * 1024 * 1024) {
            int n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) return;
            req.append(buf, n);
            hdr_end = req.find("\r\n\r\n");
            if (hdr_end != std::string::npos) break;
        }
        if (hdr_end == std::string::npos) return;

        std::string head = req.substr(0, hdr_end);
        size_t le = head.find("\r\n");
        std::string line = (le == std::string::npos) ? head : head.substr(0, le);
        size_t s1 = line.find(' '), s2 = line.rfind(' ');
        if (s1 == std::string::npos || s2 == std::string::npos || s2 <= s1) return;

        HttpReq r;
        r.method = line.substr(0, s1);
        std::string full = line.substr(s1 + 1, s2 - s1 - 1);
        size_t q = full.find('?');
        r.path = (q == std::string::npos) ? full : full.substr(0, q);
        if (q != std::string::npos) {
            std::string qs = full.substr(q + 1);
            size_t pos = 0;
            while (pos < qs.size()) {
                size_t amp = qs.find('&', pos);
                if (amp == std::string::npos) amp = qs.size();
                std::string kv = qs.substr(pos, amp - pos);
                size_t eq = kv.find('=');
                if (eq != std::string::npos)
                    r.query[url_decode(kv.substr(0, eq))] = url_decode(kv.substr(eq + 1));
                pos = amp + 1;
            }
        }

        // --- headers (keys lowercased; first occurrence wins) ---
        {
            size_t p = (le == std::string::npos) ? head.size() : le + 2;
            while (p < head.size()) {
                size_t e = head.find("\r\n", p);
                if (e == std::string::npos) e = head.size();
                size_t colon = head.find(':', p);
                if (colon != std::string::npos && colon < e) {
                    std::string k = head.substr(p, colon - p);
                    std::string v = head.substr(colon + 1, e - colon - 1);
                    std::transform(k.begin(), k.end(), k.begin(),
                                   [](unsigned char ch) { return (char)tolower(ch); });
                    size_t b = v.find_first_not_of(" \t");
                    size_t f = v.find_last_not_of(" \t");
                    v = (b == std::string::npos) ? "" : v.substr(b, f - b + 1);
                    r.headers.emplace(k, v);
                }
                p = e + 2;
            }
        }

        size_t clen = (size_t)atoll(r.header("content-length").c_str());
        if (clen > 4u * 1024 * 1024) return;
        r.body = req.substr(hdr_end + 4);
        while (r.body.size() < clen) {
            int n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            r.body.append(buf, n);
        }

        // --- DNS-rebinding guard: only literal loopback Host values are served ---
        if (!loopback_host(r.header("host"))) {
            // Length is computed, never hand-written: a Content-Length larger than
            // the body leaves a conforming client waiting for bytes that never come.
            const std::string body = "chainlite: request rejected (Host must be 127.0.0.1)\r\n";
            send_all(c, strf("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n"
                             "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                             body.size()) + body);
            return;
        }

        // --- CORS: only this network's sibling nodes, never "*" ---
        const std::string origin = r.header("origin");
        uint16_t oport = origin.empty() ? 0 : loopback_origin_port(origin);
        const bool cors_ok = oport != 0 && sibling_ports.count(oport) > 0;

        if (r.method == "OPTIONS") {   // preflight
            std::string o = cors_ok
                ? strf("HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: %s\r\n"
                       "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                       "Access-Control-Allow-Headers: Content-Type, X-Chainlite\r\n"
                       "Access-Control-Max-Age: 600\r\nVary: Origin\r\n"
                       "Content-Length: 0\r\nConnection: close\r\n\r\n", origin.c_str())
                : "HTTP/1.1 403 Forbidden\r\nVary: Origin\r\nContent-Length: 0\r\n"
                  "Connection: close\r\n\r\n";
            send_all(c, o);
            return;
        }

        // --- CSRF guard on state-changing endpoints ---
        // CORS does not stop a cross-origin POST from being *delivered* (a
        // text/plain body is a "simple request"), it only hides the response.
        // Requiring a custom header does stop it: setting one forces a preflight,
        // and preflights are refused above for any non-sibling origin.
        HttpResp resp;
        if (r.method == "POST" && r.header("x-chainlite").empty()) {
            resp = { 403, "application/json",
                     "{\"error\":\"missing X-Chainlite header (cross-site POST blocked)\"}" };
        } else if (!origin.empty() && !cors_ok) {
            // A browser page from an unknown origin. The response would be hidden
            // from it anyway; refuse outright so it cannot be used as an oracle.
            resp = { 403, "application/json", "{\"error\":\"origin not allowed\"}" };
        } else {
            resp = handler ? handler(r) : HttpResp{ 404, "text/plain", "no handler" };
        }

        const char* status = resp.code == 200 ? "200 OK"
                           : resp.code == 400 ? "400 Bad Request"
                           : resp.code == 403 ? "403 Forbidden"
                           : resp.code == 404 ? "404 Not Found" : "500 Internal Server Error";
        std::string out = strf("HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                               "X-Content-Type-Options: nosniff\r\nVary: Origin\r\n",
                               status, resp.ctype.c_str(), resp.body.size());
        if (cors_ok) out += "Access-Control-Allow-Origin: " + origin + "\r\n";
        for (auto& kv : resp.extra) out += kv.first + ": " + kv.second + "\r\n";
        out += "Connection: close\r\n\r\n" + resp.body;
        send_all(c, out);
    }

    static void send_all(SOCKET c, const std::string& out) {
        size_t off = 0;
        while (off < out.size()) {
            int n = send(c, out.data() + off, (int)(out.size() - off), 0);
            if (n <= 0) break;
            off += n;
        }
    }
};
