// chainlite node implementation — a full validating node: P2P gossip, CPU miner,
// HTTP RPC, SQLite persistence. Run three of these on loopback and you have a
// network. Exposed as node_run(args) so both clnode.exe (one node per process)
// and chainlite.exe (the all-in-one launcher) share exactly this code.
//
//   clnode --datadir data\node1 --p2p-port 7501 --rpc-port 8501
//          --peers 127.0.0.1:7502,127.0.0.1:7503 --mine on [--bits 20]
//          [--heartbeat 60] [--netid N]
#pragma once
#include "common.h"
#include "viewer_html.h"   // generated from web\viewer.html by tools\embed.ps1
#include "core.h"
#include "net.h"
#include "rpc.h"

struct App {
    Params params;
    std::mutex mtx;                 // guards chain, pool, sync state, work_cache
    Chain chain;
    Mempool pool;
    sq::Db db;
    P2P p2p;
    RpcServer rpc;
    KeyPair key;
    Addr20 miner_addr{};
    bool mine_on = true;
    uint64_t heartbeat_s = 0;
    std::string webroot;     // directory holding viewer.html (served at GET /)
    std::string rpc_peers;   // comma-separated RPC ports of the whole network, for GET /nodes
    uint16_t    rpc_port = 0;
    std::atomic<bool> running{true};
    std::atomic<uint64_t> tip_seq{0};   // bumped on every chain change; aborts the miner

    // sync state machine (guarded by mtx)
    int sync_peer = -1;
    int sync_mode = 0;              // 0 idle, 1 extend-from-tip, 2 full re-download
    uint64_t sync_extend_got = 0;
    std::vector<Block> cand;
    uint64_t sync_last_ms = 0;

    // outstanding getwork candidates for the external (GPU) miner
    std::map<H256, std::vector<Tx>> work_cache;
};

static App* g_app = nullptr;
static BOOL WINAPI ctrl_handler(DWORD) {
    if (g_app) g_app->running = false;
    return TRUE;
}

// ---- helpers (call with a.mtx HELD unless noted) ----
static bytes tip_payload(App& a) {
    Writer w;
    w.u64(a.chain.height());
    w.u64(a.chain.work);
    w.arr(a.chain.tip_hash());
    return w.b;
}
static void announce_tip(App& a, int except = -1) {  // mtx held (lock order app->net is safe)
    a.p2p.broadcast(M_TIP, tip_payload(a), except);
}
static void post_chain_change(App& a) {
    a.pool.purge(a.chain.st);
    a.work_cache.clear();
    a.tip_seq++;
}
static void reset_sync(App& a) {
    a.sync_peer = -1;
    a.sync_mode = 0;
    a.sync_extend_got = 0;
    a.cand.clear();
}
static void request_blocks(App& a, int peer, uint64_t start) {
    Writer w;
    w.u64(start);
    w.u32(200);
    a.p2p.send_to(peer, M_GET_BLOCKS, w.b);
    a.sync_last_ms = now_ms();
}
static void maybe_sync(App& a, int peer) {
    if (a.sync_peer != -1) return;
    uint64_t ph = 0, pw = 0; H256 phash{};
    if (!a.p2p.peer_tip(peer, ph, pw, phash)) return;
    if (pw <= a.chain.work) return;
    a.sync_peer = peer;
    a.sync_mode = 1;
    a.sync_extend_got = 0;
    a.cand.clear();
    logl("sync", strf("behind peer %s (their work %llu height %llu vs ours %llu/%llu) - syncing",
                      a.p2p.peer_label(peer).c_str(), (unsigned long long)pw, (unsigned long long)ph,
                      (unsigned long long)a.chain.work, (unsigned long long)a.chain.height()));
    request_blocks(a, peer, a.chain.height() + 1);
}

static void handle_blocks(App& a, int peer, std::vector<Block>&& v) {
    std::lock_guard<std::mutex> g(a.mtx);
    if (peer != a.sync_peer) return;
    a.sync_last_ms = now_ms();
    uint64_t ph = 0, pw = 0; H256 phash{};
    bool have_tip = a.p2p.peer_tip(peer, ph, pw, phash);

    if (a.sync_mode == 1) {
        size_t okc = 0;
        std::string err;
        for (auto& b : v) {
            err = a.chain.connect_block(b);
            if (!err.empty()) break;
            okc++;
        }
        if (okc > 0) post_chain_change(a);
        if (!err.empty() && okc == 0 && a.sync_extend_got == 0) {
            // peer's history diverges from ours -> download their whole chain and compare work
            logl("sync", strf("fork detected vs %s (%s) - downloading full candidate chain",
                              a.p2p.peer_label(peer).c_str(), err.c_str()));
            a.sync_mode = 2;
            a.cand.clear();
            request_blocks(a, peer, 0);
            return;
        }
        a.sync_extend_got += okc;
        if (have_tip && a.chain.work >= pw) {
            logl("sync", strf("caught up: height %llu work %llu",
                              (unsigned long long)a.chain.height(), (unsigned long long)a.chain.work));
            announce_tip(a);
            reset_sync(a);
            return;
        }
        if (okc > 0 && !v.empty()) { request_blocks(a, peer, a.chain.height() + 1); return; }
        reset_sync(a);  // stalled or junk; a later TIP will retrigger
        return;
    }
    if (a.sync_mode == 2) {
        for (auto& b : v) a.cand.push_back(std::move(b));
        if (a.cand.size() > 500000) { reset_sync(a); return; }
        bool complete = v.empty() ||
            (!a.cand.empty() && have_tip && a.cand.back().h.height >= ph);
        if (!complete) { request_blocks(a, peer, a.cand.size()); return; }
        uint64_t old_h = a.chain.height();
        uint64_t fork = 0;
        std::string err = a.chain.try_replace(a.cand, &fork);
        if (err.empty()) {
            logl("chain", strf("REORG: forked at height %llu, %llu -> %llu (tip %s) via %s",
                              (unsigned long long)fork, (unsigned long long)old_h,
                              (unsigned long long)a.chain.height(),
                              hexs(a.chain.tip_hash()).substr(0, 16).c_str(),
                              a.p2p.peer_label(peer).c_str()));
            post_chain_change(a);
            announce_tip(a);
        } else {
            logl("sync", strf("candidate chain rejected: %s", err.c_str()));
        }
        reset_sync(a);
    }
}

static void wire_p2p(App& a) {
    a.p2p.on_ready = [&a](int peer) {
        std::lock_guard<std::mutex> g(a.mtx);
        logl("net", strf("peer connected: %s (%d ready)", a.p2p.peer_label(peer).c_str(), a.p2p.ready_count()));
        a.p2p.send_to(peer, M_TIP, tip_payload(a));
    };
    a.p2p.on_gone = [&a](int peer) {
        std::lock_guard<std::mutex> g(a.mtx);
        logl("net", strf("peer disconnected: %s", a.p2p.peer_label(peer).c_str()));
        if (peer == a.sync_peer) reset_sync(a);
    };
    a.p2p.on_msg = [&a](int peer, uint8_t type, bytes&& payload) {
        switch (type) {
        case M_TIP: {
            std::lock_guard<std::mutex> g(a.mtx);
            maybe_sync(a, peer);
            break;
        }
        case M_GET_BLOCKS: {
            uint64_t start; uint32_t cnt;
            try { Reader r(payload); start = r.u64(); cnt = r.u32(); }
            catch (...) { break; }
            cnt = std::min(cnt, 200u);
            Writer w;
            std::lock_guard<std::mutex> g(a.mtx);
            uint64_t n = 0;
            std::vector<bytes> raws;
            for (uint64_t h = start; h < a.chain.blocks.size() && n < cnt; h++, n++)
                raws.push_back(a.chain.blocks[h].serialize());
            w.u32((uint32_t)raws.size());
            for (auto& r2 : raws) { w.u32((uint32_t)r2.size()); w.blob(r2); }
            a.p2p.send_to(peer, M_BLOCKS, w.b);
            break;
        }
        case M_BLOCKS: {
            std::vector<Block> v;
            try {
                Reader r(payload);
                uint32_t n = r.u32();
                if (n > 500) break;
                for (uint32_t i = 0; i < n; i++) {
                    uint32_t len = r.u32();
                    auto b = Block::parse(r.blob(len));
                    if (!b) throw std::runtime_error("bad block");
                    v.push_back(std::move(*b));
                }
            } catch (...) { break; }
            handle_blocks(a, peer, std::move(v));
            break;
        }
        case M_TX: {
            Tx t;
            try { Reader r(payload); t = Tx::parse(r); if (r.remaining()) break; }
            catch (...) { break; }
            bool fresh = false;
            {
                std::lock_guard<std::mutex> g(a.mtx);
                H256 id = t.txid();
                if (a.pool.has(id) || a.chain.txidx.count(id)) break;
                std::string err = a.pool.add(t, a.chain.st, a.params);
                if (err.empty()) {
                    fresh = true;
                    logl("mpool", strf("tx %s from %s (mempool: %zu)",
                                       hexs(id).substr(0, 16).c_str(),
                                       a.p2p.peer_label(peer).c_str(), a.pool.size()));
                }
            }
            if (fresh) a.p2p.broadcast(M_TX, payload, peer);
            break;
        }
        case M_BLOCK: {
            auto b = Block::parse(payload);
            if (!b) break;
            bool accepted = false;
            {
                std::lock_guard<std::mutex> g(a.mtx);
                if (a.chain.has_block(b->h.hash())) break;
                std::string err = a.chain.connect_block(*b);
                if (err.empty()) {
                    accepted = true;
                    logl("chain", strf("new tip height %llu %s (%zu txs, via %s)",
                                       (unsigned long long)b->h.height,
                                       hexs(b->h.hash()).substr(0, 16).c_str(),
                                       b->txs.size(), a.p2p.peer_label(peer).c_str()));
                    post_chain_change(a);
                    announce_tip(a, peer);
                } else if (b->h.height > a.chain.height()) {
                    maybe_sync(a, peer);
                }
            }
            if (accepted) a.p2p.broadcast(M_BLOCK, payload, peer);
            break;
        }
        }
    };
}

// ---- miner ----
static void miner_thread(App& a) {
    while (a.running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        if (!a.mine_on) continue;

        uint64_t seq = 0;
        Block cand;
        bool have = false;
        {
            std::lock_guard<std::mutex> g(a.mtx);
            seq = a.tip_seq.load();
            uint64_t height = a.chain.height() + 1;
            auto txs = a.pool.collect(a.chain.st, a.params, height);
            bool hb_due = a.heartbeat_s > 0 &&
                          now_s() >= a.chain.tip().h.time + a.heartbeat_s;
            if (!txs.empty() || hb_due) {
                Tx cb;
                cb.type = TX_COINBASE;
                cb.net_id = a.params.net_id;
                cb.to = a.miner_addr;
                cb.amount = a.params.reward;
                cb.nonce = height;
                cand.txs.clear();
                cand.txs.push_back(cb);
                for (auto& t : txs) cand.txs.push_back(t);
                std::vector<H256> ids;
                for (auto& t : cand.txs) ids.push_back(t.txid());
                cand.h.version = CL_VERSION;
                cand.h.net_id = a.params.net_id;
                cand.h.prev = a.chain.tip_hash();
                cand.h.merkle = merkle_root(ids);
                cand.h.height = height;
                cand.h.time = now_s();
                cand.h.bits = a.params.bits;
                have = true;
            }
        }
        if (!have) continue;

        // Randomized pre-mining delay so nodes don't solve in lockstep. This is
        // the key to convergence: with blocks this cheap to mine, whoever draws
        // the shortest delay mines first and the others must reorg to it before
        // their own delay elapses. Too small a window (< reorg time) and equal-
        // height forks persist forever; ~1s comfortably clears a loopback reorg.
        uint64_t jit = rng()() % 1200;
        uint64_t t0 = now_ms();
        while (now_ms() - t0 < jit && a.running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (a.tip_seq.load() != seq) break;
        }
        if (a.tip_seq.load() != seq) continue;

        bytes hdr = cand.h.serialize();
        uint64_t nonce = rng()();
        bool found = false;
        uint64_t tried = 0;
        while (a.running && a.tip_seq.load() == seq && !found) {
            for (int i = 0; i < 100000; i++) {
                for (int k = 0; k < 8; k++) hdr[NONCE_OFFSET + k] = (uint8_t)(nonce >> (8 * k));
                H256 h = sha256d(hdr.data(), hdr.size());
                if (pow_ok(h, cand.h.bits)) { found = true; break; }
                nonce++;
            }
            tried += 100000;
            if (tried > (1ull << 40)) break;  // give up eventually (should never happen)
        }
        if (!found || a.tip_seq.load() != seq) continue;

        cand.h.nonce = nonce;
        bytes raw;
        bool ok = false;
        {
            std::lock_guard<std::mutex> g(a.mtx);
            if (a.tip_seq.load() != seq) continue;
            std::string err = a.chain.connect_block(cand);
            if (err.empty()) {
                ok = true;
                logl("mine", strf("MINED block height %llu %s (%zu txs, reward %llu -> %s)",
                                  (unsigned long long)cand.h.height,
                                  hexs(cand.h.hash()).substr(0, 16).c_str(),
                                  cand.txs.size(), (unsigned long long)a.params.reward,
                                  hexs(a.miner_addr).substr(0, 12).c_str()));
                post_chain_change(a);
                raw = cand.serialize();
                announce_tip(a);
            }
        }
        if (ok) a.p2p.broadcast(M_BLOCK, raw);
    }
}

// ---- periodic housekeeping ----
static void periodic_thread(App& a) {
    int tick = 0;
    while (a.running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        tick++;
        if (tick % 40 == 0) {  // every 10 s: keepalive tip announce
            std::lock_guard<std::mutex> g(a.mtx);
            announce_tip(a);
        }
        if (tick % 240 == 0) {  // every 60 s: status line
            std::lock_guard<std::mutex> g(a.mtx);
            logl("node", strf("height %llu work %llu peers %d mempool %zu",
                              (unsigned long long)a.chain.height(), (unsigned long long)a.chain.work,
                              a.p2p.ready_count(), a.pool.size()));
        }
        {
            std::lock_guard<std::mutex> g(a.mtx);
            if (a.sync_peer != -1 && now_ms() - a.sync_last_ms > 20000) {
                logl("sync", "sync timed out; resetting");
                reset_sync(a);
            }
        }
    }
}

// ---- RPC ----
static std::string json_block_summary(const Block& b) {
    return strf("{\"height\":%llu,\"hash\":\"%s\",\"time\":%llu,\"ntx\":%zu}",
                (unsigned long long)b.h.height, hexs(b.h.hash()).c_str(),
                (unsigned long long)b.h.time, b.txs.size());
}

// Read a whole file into a string ("" if missing). Used to serve the web viewer.
static std::string read_file(const std::string& path) {
    FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") || !f) return "";
    std::string s;
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) s.append(buf, n);
    fclose(f);
    return s;
}

static HttpResp handle_rpc(App& a, const HttpReq& r) {
    auto err400 = [](const std::string& e) {
        return HttpResp{ 400, "application/json", "{\"error\":\"" + e + "\"}" };
    };
    auto err404 = [](const std::string& e) {
        return HttpResp{ 404, "application/json", "{\"error\":\"" + e + "\"}" };
    };

    // Serve the web viewer (notes + explorer + wallet) at / and /app.
    // web\viewer.html wins when present so editing it hot-reloads during development;
    // otherwise fall back to the copy compiled into the binary, which is what makes
    // chainlite.exe portable (no web\ folder needed alongside it).
    if (r.path == "/" || r.path == "/app" || r.path == "/viewer.html") {
        std::string html = a.webroot.empty() ? "" : read_file(a.webroot + "\\viewer.html");
        if (html.empty()) html = viewer_html();
        if (!html.empty()) return { 200, "text/html; charset=utf-8", html };
        return { 200, "text/plain",
            "chainlite node RPC (no web viewer embedded or found)\n"
            "Endpoints: GET /help for the list.\n" };
    }
    if (r.path == "/help") {
        return { 200, "text/plain",
            "chainlite node RPC\n"
            "  GET  /            web viewer (explorer + wallet)\n"
            "  GET  /status\n"
            "  GET  /balance?addr=<hex40>\n"
            "  GET  /block?height=N | /block?hash=<hex64>\n"
            "  GET  /tx?id=<hex64>\n"
            "  GET  /mempool\n"
            "  GET  /records?limit=N[&addr=<hex40>]   (notes feed: every RECORD tx)\n"
            "  GET  /tail?n=N\n"
            "  GET  /prove?txid=<hex64>          (merkle inclusion proof)\n"
            "  POST /submit        body=<hex tx>\n"
            "  GET  /work?addr=<hex40>           (mining work for external miner)\n"
            "  POST /submitwork    body=<hex 100-byte header>\n" };
    }

    // Lets the web viewer discover its sibling nodes instead of assuming 8501-8503,
    // so a launcher that shifts ports (e.g. when the defaults are taken) still works.
    if (r.path == "/nodes") {
        std::string list;
        std::string src = a.rpc_peers.empty() ? std::to_string(a.rpc_port) : a.rpc_peers;
        size_t pos = 0;
        bool first = true;
        while (pos < src.size()) {
            size_t c = src.find(',', pos);
            if (c == std::string::npos) c = src.size();
            std::string t = src.substr(pos, c - pos);
            if (!t.empty()) { list += (first ? "" : ",") + t; first = false; }
            pos = c + 1;
        }
        return { 200, "application/json",
                 strf("{\"self\":%u,\"rpc\":[%s]}", a.rpc_port, list.c_str()) };
    }

    std::lock_guard<std::mutex> g(a.mtx);

    if (r.path == "/status") {
        return { 200, "application/json", strf(
            "{\"height\":%llu,\"tip\":\"%s\",\"work\":%llu,\"peers\":%d,\"mempool\":%zu,"
            "\"mining\":%s,\"miner_addr\":\"%s\",\"net_id\":%u,\"bits\":%u,\"reward\":%llu}",
            (unsigned long long)a.chain.height(), hexs(a.chain.tip_hash()).c_str(),
            (unsigned long long)a.chain.work, a.p2p.ready_count(), a.pool.size(),
            a.mine_on ? "true" : "false", hexs(a.miner_addr).c_str(),
            a.params.net_id, a.params.bits, (unsigned long long)a.params.reward) };
    }
    if (r.path == "/balance") {
        auto ad = unhex_n<20>(r.query.count("addr") ? r.query.at("addr") : "");
        if (!ad) return err400("need addr=<hex40>");
        auto it = a.chain.st.find(*ad);
        uint64_t bal = it == a.chain.st.end() ? 0 : it->second.balance;
        uint64_t non = it == a.chain.st.end() ? 0 : it->second.nonce;
        return { 200, "application/json", strf("{\"addr\":\"%s\",\"balance\":%llu,\"nonce\":%llu}",
                 hexs(*ad).c_str(), (unsigned long long)bal, (unsigned long long)non) };
    }
    if (r.path == "/block") {
        const Block* b = nullptr;
        if (r.query.count("height")) {
            uint64_t h = strtoull(r.query.at("height").c_str(), nullptr, 10);
            if (h < a.chain.blocks.size()) b = &a.chain.blocks[h];
        } else if (r.query.count("hash")) {
            auto want = unhex_n<32>(r.query.at("hash"));
            if (want) for (size_t i = 0; i < a.chain.hashes.size(); i++)
                if (a.chain.hashes[i] == *want) { b = &a.chain.blocks[i]; break; }
        }
        if (!b) return err404("block not found");
        std::string txids;
        for (size_t i = 0; i < b->txs.size(); i++)
            txids += (i ? ",\"" : "\"") + hexs(b->txs[i].txid()) + "\"";
        return { 200, "application/json", strf(
            "{\"height\":%llu,\"hash\":\"%s\",\"prev\":\"%s\",\"merkle\":\"%s\","
            "\"time\":%llu,\"bits\":%u,\"nonce\":%llu,\"ntx\":%zu,\"txids\":[",
            (unsigned long long)b->h.height, hexs(b->h.hash()).c_str(), hexs(b->h.prev).c_str(),
            hexs(b->h.merkle).c_str(), (unsigned long long)b->h.time, b->h.bits,
            (unsigned long long)b->h.nonce, b->txs.size()) + txids + "]}" };
    }
    if (r.path == "/tx") {
        auto id = unhex_n<32>(r.query.count("id") ? r.query.at("id") : "");
        if (!id) return err400("need id=<hex64>");
        auto it = a.chain.txidx.find(*id);
        if (it != a.chain.txidx.end()) {
            const Block& b = a.chain.blocks[it->second.first];
            const Tx& t = b.txs[it->second.second];
            uint64_t conf = a.chain.height() - b.h.height + 1;
            return { 200, "application/json", strf(
                "{\"txid\":\"%s\",\"status\":\"confirmed\",\"height\":%llu,\"index\":%u,"
                "\"confirmations\":%llu,\"type\":%u,\"from\":\"%s\",\"to\":\"%s\","
                "\"amount\":%llu,\"nonce\":%llu,\"payload_hex\":\"%s\"}",
                hexs(*id).c_str(), (unsigned long long)b.h.height, it->second.second,
                (unsigned long long)conf, t.type,
                t.type == TX_COINBASE ? "coinbase" : hexs(addr_of(t.from)).c_str(),
                hexs(t.to).c_str(), (unsigned long long)t.amount,
                (unsigned long long)t.nonce, hexs(t.payload).c_str()) };
        }
        auto mt = a.pool.find(*id);
        if (mt) return { 200, "application/json",
            strf("{\"txid\":\"%s\",\"status\":\"pending\"}", hexs(*id).c_str()) };
        return err404("tx not found (it may have been dropped in a reorg; resubmit)");
    }
    if (r.path == "/mempool") {
        std::string ids;
        bool first = true;
        for (auto& [k, t] : a.pool.m) {
            ids += (first ? "\"" : ",\"") + hexs(t.txid()) + "\"";
            first = false;
        }
        return { 200, "application/json",
                 strf("{\"count\":%zu,\"txids\":[", a.pool.size()) + ids + "]}" };
    }
    // Every RECORD tx (the "notes" feed), newest first. Pending mempool records are
    // listed ahead of confirmed ones so a just-posted note shows up immediately.
    // Payloads are returned as hex, so arbitrary note text needs no JSON escaping.
    if (r.path == "/records") {
        uint64_t limit = r.query.count("limit") ? strtoull(r.query.at("limit").c_str(), nullptr, 10) : 50;
        if (limit == 0 || limit > 500) limit = 500;
        std::optional<Addr20> only;
        if (r.query.count("addr")) {
            auto ad = unhex_n<20>(r.query.at("addr"));
            if (!ad) return err400("bad addr");
            only = *ad;
        }
        std::string out = "{\"records\":[";
        size_t n = 0;
        auto emit = [&](const Tx& t, const char* status, uint64_t height, uint64_t time, uint64_t conf) {
            if (n) out += ",";
            out += strf("{\"txid\":\"%s\",\"status\":\"%s\",\"height\":%llu,\"time\":%llu,"
                        "\"confirmations\":%llu,\"from\":\"%s\",\"payload_hex\":\"%s\"}",
                        hexs(t.txid()).c_str(), status, (unsigned long long)height,
                        (unsigned long long)time, (unsigned long long)conf,
                        hexs(addr_of(t.from)).c_str(), hexs(t.payload).c_str());
            n++;
        };
        for (auto& kv : a.pool.m) {
            if (n >= limit) break;
            const Tx& t = kv.second;
            if (t.type != TX_RECORD) continue;
            if (only && addr_of(t.from) != *only) continue;
            emit(t, "pending", 0, 0, 0);
        }
        for (size_t h = a.chain.blocks.size(); h-- > 0 && n < limit; ) {
            const Block& b = a.chain.blocks[h];
            for (size_t i = b.txs.size(); i-- > 0 && n < limit; ) {
                const Tx& t = b.txs[i];
                if (t.type != TX_RECORD) continue;
                if (only && addr_of(t.from) != *only) continue;
                emit(t, "confirmed", b.h.height, b.h.time, a.chain.height() - b.h.height + 1);
            }
        }
        return { 200, "application/json", out + "]}" };
    }
    if (r.path == "/tail") {
        uint64_t n = r.query.count("n") ? strtoull(r.query.at("n").c_str(), nullptr, 10) : 10;
        n = std::min(n, (uint64_t)100);
        std::string out = "{\"blocks\":[";
        uint64_t total = a.chain.blocks.size();
        uint64_t start = total > n ? total - n : 0;
        for (uint64_t i = start; i < total; i++)
            out += (i > start ? "," : "") + json_block_summary(a.chain.blocks[i]);
        return { 200, "application/json", out + "]}" };
    }
    if (r.path == "/submit" && r.method == "POST") {
        auto raw = unhex(r.body);
        if (!raw) return err400("body must be hex");
        Tx t;
        try { Reader rd(*raw); t = Tx::parse(rd); if (rd.remaining()) throw std::runtime_error("trailing bytes"); }
        catch (std::exception& e) { return err400(std::string("parse: ") + e.what()); }
        H256 id = t.txid();
        if (a.pool.has(id) || a.chain.txidx.count(id)) return err400("duplicate tx");
        std::string err = a.pool.add(t, a.chain.st, a.params);
        if (!err.empty()) return err400(err);
        logl("mpool", strf("tx %s via rpc (mempool: %zu)", hexs(id).substr(0, 16).c_str(), a.pool.size()));
        a.p2p.broadcast(M_TX, *raw);
        return { 200, "application/json", strf("{\"txid\":\"%s\",\"status\":\"pending\"}", hexs(id).c_str()) };
    }
    if (r.path == "/prove") {
        auto id = unhex_n<32>(r.query.count("txid") ? r.query.at("txid") : "");
        if (!id) return err400("need txid=<hex64>");
        auto it = a.chain.txidx.find(*id);
        if (it == a.chain.txidx.end()) return err404("tx not confirmed on this chain");
        const Block& b = a.chain.blocks[it->second.first];
        std::vector<H256> leaves;
        for (auto& t : b.txs) leaves.push_back(t.txid());
        auto steps = merkle_proof(leaves, it->second.second);
        std::string out = "CHAINLITE-PROOF v1\n";
        out += "txid " + hexs(*id) + "\n";
        out += strf("height %llu\n", (unsigned long long)b.h.height);
        out += strf("index %u\n", it->second.second);
        out += "blockhash " + hexs(b.h.hash()) + "\n";
        out += "header " + hexs(b.h.serialize()) + "\n";
        for (auto& s : steps)
            out += std::string("sibling ") + (s.left ? "L" : "R") + " " + hexs(s.h) + "\n";
        out += "end\n";
        return { 200, "text/plain", out };
    }
    if (r.path == "/work") {
        Addr20 payto = a.miner_addr;
        if (r.query.count("addr")) {
            auto ad = unhex_n<20>(r.query.at("addr"));
            if (!ad) return err400("bad addr");
            payto = *ad;
        }
        uint64_t height = a.chain.height() + 1;
        auto txs = a.pool.collect(a.chain.st, a.params, height);
        Tx cb;
        cb.type = TX_COINBASE; cb.net_id = a.params.net_id;
        cb.to = payto; cb.amount = a.params.reward; cb.nonce = height;
        std::vector<Tx> all;
        all.push_back(cb);
        for (auto& t : txs) all.push_back(t);
        std::vector<H256> ids;
        for (auto& t : all) ids.push_back(t.txid());
        BlockHeader h;
        h.version = CL_VERSION; h.net_id = a.params.net_id;
        h.prev = a.chain.tip_hash(); h.merkle = merkle_root(ids);
        h.height = height; h.time = now_s(); h.bits = a.params.bits; h.nonce = 0;
        if (a.work_cache.size() > 64) a.work_cache.clear();
        a.work_cache[h.merkle] = std::move(all);
        return { 200, "application/json", strf(
            "{\"header\":\"%s\",\"bits\":%u,\"height\":%llu,\"tip\":\"%s\",\"ntx\":%zu}",
            hexs(h.serialize()).c_str(), h.bits, (unsigned long long)height,
            hexs(a.chain.tip_hash()).c_str(), a.work_cache[h.merkle].size()) };
    }
    if (r.path == "/submitwork" && r.method == "POST") {
        auto raw = unhex(r.body);
        if (!raw || raw->size() != HEADER_SIZE) return err400("body must be hex of 100-byte header");
        BlockHeader h;
        try { Reader rd(*raw); h = BlockHeader::parse(rd); }
        catch (...) { return err400("bad header"); }
        auto it = a.work_cache.find(h.merkle);
        if (it == a.work_cache.end()) return err400("unknown work (stale tip?)");
        Block b;
        b.h = h;
        b.txs = it->second;
        std::string err = a.chain.connect_block(b);
        if (!err.empty()) return err400("rejected: " + err);
        logl("mine", strf("MINED block height %llu %s via external miner (%zu txs)",
                          (unsigned long long)b.h.height, hexs(b.h.hash()).substr(0, 16).c_str(),
                          b.txs.size()));
        post_chain_change(a);
        announce_tip(a);
        a.p2p.broadcast(M_BLOCK, b.serialize());
        return { 200, "application/json", strf("{\"ok\":true,\"height\":%llu,\"hash\":\"%s\"}",
                 (unsigned long long)b.h.height, hexs(b.h.hash()).c_str()) };
    }
    return err404("unknown endpoint (GET / for help)");
}

// Run a full node until Ctrl+C / shutdown. Caller does WSAStartup + arg parsing,
// so this is reusable by both clnode.exe and the all-in-one chainlite.exe.
inline int node_run(const Args& args) {
    App a;
    g_app = &a;
    a.params.bits = (uint32_t)strtoul(args.get("bits", "20").c_str(), nullptr, 10);
    if (args.has("netid")) a.params.net_id = (uint32_t)strtoul(args.get("netid").c_str(), nullptr, 10);
    a.heartbeat_s = strtoull(args.get("heartbeat", "0").c_str(), nullptr, 10);
    a.mine_on = args.get("mine", "on") != "off";
    std::string datadir = args.get("datadir", "data\\node1");
    uint16_t p2p_port = (uint16_t)atoi(args.get("p2p-port", "7501").c_str());
    uint16_t rpc_port = (uint16_t)atoi(args.get("rpc-port", "8501").c_str());
    {   // web viewer lives in <exe_dir>\..\web by default (exe is in bin\)
        char exe[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, exe, MAX_PATH);
        std::string exedir = exe;
        size_t sl = exedir.find_last_of("\\/");
        exedir = (sl == std::string::npos) ? "." : exedir.substr(0, sl);
        a.webroot = args.get("webroot", exedir + "\\..\\web");
    }
    a.rpc_port  = rpc_port;
    a.rpc_peers = args.get("rpc-peers", "");
    std::vector<std::string> peers;
    {
        std::string ps = args.get("peers", "");
        size_t pos = 0;
        while (pos < ps.size()) {
            size_t c = ps.find(',', pos);
            if (c == std::string::npos) c = ps.size();
            std::string t = ps.substr(pos, c - pos);
            if (!t.empty() && t != "none") peers.push_back(t);
            pos = c + 1;
        }
    }

    std::error_code ec;
    std::filesystem::create_directories(datadir, ec);
    if (!sq::load()) {
        logl("fatal", "could not load winsqlite3.dll (ships with Windows 10+)");
        return 1;
    }
    if (!a.db.open(datadir + "\\chain.db")) {
        logl("fatal", "could not open " + datadir + "\\chain.db");
        return 1;
    }
    auto kp = kp_load_or_create(datadir + "\\node.key");
    if (!kp) { logl("fatal", "could not create node key (CNG)"); return 1; }
    a.key = *kp;
    a.miner_addr = addr_of(a.key.pub);

    a.chain.params = a.params;
    std::string err = a.chain.init(&a.db);
    if (!err.empty()) { logl("fatal", "chain init: " + err); return 1; }

    logl("node", "chainlite node starting");
    logl("node", strf("  datadir   %s", datadir.c_str()));
    logl("node", strf("  p2p       127.0.0.1:%u   rpc http://127.0.0.1:%u", p2p_port, rpc_port));
    logl("node", strf("  viewer    http://127.0.0.1:%u/   (web: %s)", rpc_port, a.webroot.c_str()));
    logl("node", strf("  netid     %u   bits %u   reward %llu   mine %s   heartbeat %llus",
                      a.params.net_id, a.params.bits, (unsigned long long)a.params.reward,
                      a.mine_on ? "on" : "off", (unsigned long long)a.heartbeat_s));
    logl("node", strf("  genesis   %s", hexs(a.chain.hashes[0]).c_str()));
    logl("node", strf("  tip       height %llu %s (work %llu)",
                      (unsigned long long)a.chain.height(),
                      hexs(a.chain.tip_hash()).substr(0, 16).c_str(),
                      (unsigned long long)a.chain.work));
    logl("node", strf("  miner addr %s", hexs(a.miner_addr).c_str()));
    for (auto& p : peers) logl("node", strf("  peer      %s", p.c_str()));

    wire_p2p(a);
    if (!a.p2p.start(p2p_port, peers, a.params.net_id)) {
        logl("fatal", strf("could not listen on p2p port %u (already in use?)", p2p_port));
        return 1;
    }
    a.rpc.handler = [&a](const HttpReq& r) { return handle_rpc(a, r); };
    if (!a.rpc.start(rpc_port)) {
        logl("fatal", strf("could not listen on rpc port %u (already in use?)", rpc_port));
        return 1;
    }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    std::thread tm([&a] { miner_thread(a); });
    std::thread tp([&a] { periodic_thread(a); });
    while (a.running) std::this_thread::sleep_for(std::chrono::milliseconds(100));

    logl("node", "shutting down");
    a.rpc.stop();
    a.p2p.stop();
    tm.join();
    tp.join();
    return 0;
}
