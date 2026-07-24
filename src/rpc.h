// chainlite — minimal HTTP server for the node's local RPC (127.0.0.1 only).
// One request per connection, handled sequentially; plenty for local use.
#pragma once
#include "common.h"

struct HttpReq {
    std::string method, path;
    std::map<std::string, std::string> query;
    std::string body;
};
struct HttpResp {
    int code = 200;
    std::string ctype = "application/json";
    std::string body;
};

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

    bool start(uint16_t port) {
        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) return false;
        int yes = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
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

        size_t clen = 0;
        {   // find Content-Length (case-insensitive scan)
            std::string lower = head;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char ch) { return (char)tolower(ch); });
            size_t p = lower.find("content-length:");
            if (p != std::string::npos) clen = (size_t)atoll(lower.c_str() + p + 15);
        }
        if (clen > 4u * 1024 * 1024) return;
        r.body = req.substr(hdr_end + 4);
        while (r.body.size() < clen) {
            int n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            r.body.append(buf, n);
        }

        HttpResp resp = handler ? handler(r) : HttpResp{ 404, "text/plain", "no handler" };
        const char* status = resp.code == 200 ? "200 OK"
                           : resp.code == 400 ? "400 Bad Request"
                           : resp.code == 404 ? "404 Not Found" : "500 Internal Server Error";
        std::string out = strf("HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                               "Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                               status, resp.ctype.c_str(), resp.body.size()) + resp.body;
        size_t off = 0;
        while (off < out.size()) {
            int n = send(c, out.data() + off, (int)(out.size() - off), 0);
            if (n <= 0) break;
            off += n;
        }
    }
};
