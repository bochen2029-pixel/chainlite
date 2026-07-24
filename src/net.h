// chainlite — P2P gossip over TCP (loopback by default). Message framing:
// [u32 payload_len][u8 type][payload]. Each node keeps outbound connections to
// its configured peers and accepts inbound ones; HELLO handshake checks net id.
#pragma once
#include "common.h"
#include "core.h"

enum MsgType : uint8_t {
    M_HELLO      = 1,  // u32 net_id, u32 version, u16 listen_port
    M_TIP        = 2,  // u64 height, u64 work, 32B tip hash
    M_GET_BLOCKS = 3,  // u64 start_height, u32 max_count
    M_BLOCKS     = 4,  // u32 n, then n x (u32 len, raw block)
    M_TX         = 5,  // raw tx
    M_BLOCK      = 6,  // raw block (new tip push)
};

struct Peer {
    SOCKET s = INVALID_SOCKET;
    std::string label;
    std::string target;      // nonempty => outbound; used as the reconnect key
    bool connecting = false;
    bool ready = false;      // HELLO exchanged
    bool dead = false;
    bool dedup_drop = false; // dropped as a redundant duplicate link, not a real disconnect
    uint16_t peer_port = 0;  // peer's advertised listen port (from HELLO)
    bytes inbuf, outbuf;
    uint64_t tip_height = 0, tip_work = 0;
    H256 tip_hash{};
};

class P2P {
public:
    std::function<void(int)> on_ready;                       // handshake complete
    std::function<void(int)> on_gone;                        // peer disconnected
    std::function<void(int, uint8_t, bytes&&)> on_msg;       // TIP/GET_BLOCKS/BLOCKS/TX/BLOCK

    bool start(uint16_t port, const std::vector<std::string>& targets_, uint32_t netid) {
        net_id = netid;
        listen_port = port;
        targets = targets_;
        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) return false;
        int yes = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (bind(listener, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(listener); return false; }
        if (listen(listener, 8) != 0) { closesocket(listener); return false; }
        set_nonblocking(listener);
        running = true;
        th = std::thread([this] { loop(); });
        return true;
    }
    void stop() {
        running = false;
        if (th.joinable()) th.join();
        std::lock_guard<std::mutex> g(mtx);
        for (auto& [id, p] : peers) if (p.s != INVALID_SOCKET) closesocket(p.s);
        peers.clear();
        if (listener != INVALID_SOCKET) { closesocket(listener); listener = INVALID_SOCKET; }
    }

    void send_to(int peer, uint8_t type, const bytes& payload) {
        std::lock_guard<std::mutex> g(mtx);
        auto it = peers.find(peer);
        if (it == peers.end() || it->second.dead) return;
        frame_into(it->second.outbuf, type, payload);
    }
    void broadcast(uint8_t type, const bytes& payload, int except = -1) {
        std::lock_guard<std::mutex> g(mtx);
        for (auto& [id, p] : peers)
            if (p.ready && !p.dead && id != except) frame_into(p.outbuf, type, payload);
    }
    int ready_count() {
        std::lock_guard<std::mutex> g(mtx);
        int n = 0;
        for (auto& [id, p] : peers) if (p.ready && !p.dead) n++;
        return n;
    }
    bool peer_tip(int id, uint64_t& h, uint64_t& w, H256& hash) {
        std::lock_guard<std::mutex> g(mtx);
        auto it = peers.find(id);
        if (it == peers.end() || !it->second.ready) return false;
        h = it->second.tip_height; w = it->second.tip_work; hash = it->second.tip_hash;
        return true;
    }
    std::string peer_label(int id) {
        std::lock_guard<std::mutex> g(mtx);
        auto it = peers.find(id);
        return it == peers.end() ? "?" : it->second.label;
    }

private:
    uint32_t net_id = 0;
    uint16_t listen_port = 0;
    SOCKET listener = INVALID_SOCKET;
    std::vector<std::string> targets;
    std::mutex mtx;
    std::map<int, Peer> peers;
    int next_id = 1;
    std::thread th;
    std::atomic<bool> running{false};
    uint64_t last_reconnect = 0;

    struct Ev { int kind; int peer; uint8_t type; bytes payload; };  // kind: 0 ready, 1 msg, 2 gone

    static void set_nonblocking(SOCKET s) { u_long m = 1; ioctlsocket(s, FIONBIO, &m); }
    static void set_nodelay(SOCKET s) { int y = 1; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&y, sizeof(y)); }
    static void frame_into(bytes& out, uint8_t type, const bytes& payload) {
        uint32_t len = (uint32_t)payload.size();
        for (int i = 0; i < 4; i++) out.push_back((len >> (8 * i)) & 0xff);
        out.push_back(type);
        out.insert(out.end(), payload.begin(), payload.end());
    }
    void queue_hello(Peer& p) {
        Writer w;
        w.u32(net_id); w.u32(CL_VERSION); w.u16(listen_port);
        frame_into(p.outbuf, M_HELLO, w.b);
    }
    void try_connect_targets() {
        for (auto& t : targets) {
            bool have = false;
            for (auto& [id, p] : peers) if (p.target == t && !p.dead) { have = true; break; }
            if (have) continue;
            size_t c = t.rfind(':');
            if (c == std::string::npos) continue;
            std::string host = t.substr(0, c);
            uint16_t port = (uint16_t)atoi(t.c_str() + c + 1);
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) continue;
            set_nonblocking(s);
            set_nodelay(s);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(port);
            if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) { closesocket(s); continue; }
            int rc = connect(s, (sockaddr*)&a, sizeof(a));
            if (rc != 0 && WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(s); continue; }
            Peer p;
            p.s = s; p.label = t; p.target = t; p.connecting = (rc != 0);
            if (!p.connecting) queue_hello(p);
            peers[next_id++] = std::move(p);
        }
    }

    void loop() {
        std::vector<Ev> evs;
        while (running) {
            evs.clear();

            // Build the fd_sets under a brief lock, then release it and block in
            // select() UNLOCKED. Only this thread ever adds/removes peers, so the
            // map is stable across the unlocked wait; other threads only append to
            // outbuf / read tip fields, both of which stay valid. Holding the lock
            // across a 100ms select() would pin the network mutex ~99% of the time
            // and starve RPC/miner threads that need it — the cause of multi-second
            // RPC stalls.
            fd_set rf, wf, ef;
            FD_ZERO(&rf); FD_ZERO(&wf); FD_ZERO(&ef);
            FD_SET(listener, &rf);
            {
                std::lock_guard<std::mutex> g(mtx);
                uint64_t t = now_ms();
                if (t - last_reconnect > 2000) { last_reconnect = t; try_connect_targets(); }
                for (auto& [id, p] : peers) {
                    if (p.dead) continue;
                    if (p.connecting) { FD_SET(p.s, &wf); FD_SET(p.s, &ef); }
                    else {
                        FD_SET(p.s, &rf);
                        if (!p.outbuf.empty()) FD_SET(p.s, &wf);
                    }
                }
            }
            timeval tv{ 0, 100000 };
            int rc = select(0, &rf, &wf, &ef, &tv);
            {
                std::lock_guard<std::mutex> g(mtx);
                if (rc > 0) {
                    if (FD_ISSET(listener, &rf)) {
                        for (;;) {
                            SOCKET c = accept(listener, nullptr, nullptr);
                            if (c == INVALID_SOCKET) break;
                            set_nonblocking(c);
                            set_nodelay(c);
                            Peer p;
                            p.s = c;
                            sockaddr_in sa{}; int sl = sizeof(sa);
                            if (getpeername(c, (sockaddr*)&sa, &sl) == 0)
                                p.label = strf("in:%u", (unsigned)ntohs(sa.sin_port));
                            else p.label = "in:?";
                            queue_hello(p);
                            peers[next_id++] = std::move(p);
                        }
                    }
                    for (auto& [id, p] : peers) {
                        if (p.dead) continue;
                        if (p.connecting) {
                            if (FD_ISSET(p.s, &ef)) { p.dead = true; continue; }
                            if (FD_ISSET(p.s, &wf)) {
                                int err = 0, el = sizeof(err);
                                getsockopt(p.s, SOL_SOCKET, SO_ERROR, (char*)&err, &el);
                                if (err != 0) { p.dead = true; continue; }
                                p.connecting = false;
                                queue_hello(p);
                            }
                            continue;
                        }
                        if (FD_ISSET(p.s, &rf)) {
                            for (;;) {
                                char buf[65536];
                                int n = recv(p.s, buf, sizeof(buf), 0);
                                if (n > 0) {
                                    p.inbuf.insert(p.inbuf.end(), buf, buf + n);
                                    if (p.inbuf.size() > 16u * 1024 * 1024) { p.dead = true; break; }
                                } else if (n == 0) { p.dead = true; break; }
                                else {
                                    if (WSAGetLastError() != WSAEWOULDBLOCK) p.dead = true;
                                    break;
                                }
                            }
                            if (!p.dead) parse_frames(id, p, evs);
                        }
                        if (!p.dead && !p.outbuf.empty() && FD_ISSET(p.s, &wf)) {
                            int n = send(p.s, (const char*)p.outbuf.data(), (int)p.outbuf.size(), 0);
                            if (n > 0) p.outbuf.erase(p.outbuf.begin(), p.outbuf.begin() + n);
                            else if (n < 0 && WSAGetLastError() != WSAEWOULDBLOCK) p.dead = true;
                        }
                    }
                }
                for (auto it = peers.begin(); it != peers.end();) {
                    if (it->second.dead) {
                        if (it->second.s != INVALID_SOCKET) closesocket(it->second.s);
                        if (it->second.ready) evs.push_back({ 2, it->first, 0, {} });
                        it = peers.erase(it);
                    } else ++it;
                }
            }
            for (auto& e : evs) {
                if (e.kind == 0) { if (on_ready) on_ready(e.peer); }
                else if (e.kind == 2) { if (on_gone) on_gone(e.peer); }
                else { if (on_msg) on_msg(e.peer, e.type, std::move(e.payload)); }
            }
        }
    }

    void parse_frames(int id, Peer& p, std::vector<Ev>& evs) {
        for (;;) {
            if (p.inbuf.size() < 5) return;
            uint32_t len = (uint32_t)p.inbuf[0] | ((uint32_t)p.inbuf[1] << 8) |
                           ((uint32_t)p.inbuf[2] << 16) | ((uint32_t)p.inbuf[3] << 24);
            if (len > 8u * 1024 * 1024) { p.dead = true; return; }
            if (p.inbuf.size() < 5 + (size_t)len) return;
            uint8_t type = p.inbuf[4];
            bytes payload(p.inbuf.begin() + 5, p.inbuf.begin() + 5 + len);
            p.inbuf.erase(p.inbuf.begin(), p.inbuf.begin() + 5 + len);
            if (type == M_HELLO) {
                try {
                    Reader r(payload);
                    uint32_t nid = r.u32();
                    r.u32();  // version
                    uint16_t their_port = r.u16();
                    if (nid != net_id) { p.dead = true; return; }
                    p.peer_port = their_port;
                    // Dedup: a pair of nodes each dials the other, so two TCP links
                    // form. Keep exactly one, chosen deterministically so both sides
                    // agree: the lower-port node is the canonical dialer.
                    bool i_should_dial = listen_port < their_port;
                    bool is_outbound = !p.target.empty();
                    if (their_port != 0 && i_should_dial != is_outbound) {
                        p.dead = true;
                        p.dedup_drop = true;   // silent: the sibling link stays up
                        return;
                    }
                    if (!p.ready) { p.ready = true; evs.push_back({ 0, id, 0, {} }); }
                } catch (...) { p.dead = true; return; }
            } else if (type == M_TIP) {
                try {
                    Reader r(payload);
                    p.tip_height = r.u64();
                    p.tip_work = r.u64();
                    p.tip_hash = r.arr<32>();
                    evs.push_back({ 1, id, type, std::move(payload) });
                } catch (...) { p.dead = true; return; }
            } else {
                evs.push_back({ 1, id, type, std::move(payload) });
            }
        }
    }
};
