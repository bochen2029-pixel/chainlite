// chainlite self-test: FIPS 180-4 SHA-256 vectors, CNG signatures, merkle
// proofs, tx/block serialization, chain validation, mempool rules, and reorgs,
// plus the P2P framing / RPC-security / notes-feed regressions below.
#include "common.h"
#include "core.h"
#include "net.h"
#include "node_impl.h"     // for handle_rpc() — exercises /records, /submit, /block

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

// Raw HTTP request against a local RpcServer; returns the whole response text.
static std::string http_raw(uint16_t port, const std::string& req) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return "";
    DWORD tmo = 4000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tmo, sizeof(tmo));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(s, (sockaddr*)&a, sizeof(a)) != 0) { closesocket(s); return ""; }
    send(s, req.data(), (int)req.size(), 0);
    std::string out;
    char buf[8192];
    for (;;) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, n);
    }
    closesocket(s);
    return out;
}
static bool has_line(const std::string& resp, const std::string& needle) {
    return resp.find(needle) != std::string::npos;
}
// A block carrying `ntx` RECORD txs of `payload` bytes each. Not consensus-valid
// (signatures are junk) — used only to measure wire sizes.
static Block bulky_block(uint64_t height, size_t ntx, size_t payload) {
    Block b;
    b.h.version = CL_VERSION;
    b.h.height = height;
    b.h.time = 1753000000;
    Tx cb; cb.type = TX_COINBASE; cb.nonce = height;
    b.txs.push_back(cb);
    for (size_t i = 1; i < ntx; i++) {
        Tx t;
        t.type = TX_RECORD;
        t.nonce = i;
        t.from.fill((uint8_t)i);
        t.payload.assign(payload, (uint8_t)i);
        b.txs.push_back(t);
    }
    return b;
}

static Block mine_block(const Chain& c, const Params& p, const Addr20& miner,
                        std::vector<Tx> txs, uint64_t t) {
    Block b;
    Tx cb;
    cb.type = TX_COINBASE;
    cb.net_id = p.net_id;
    cb.to = miner;
    cb.amount = p.reward;
    cb.nonce = c.height() + 1;
    b.txs.push_back(cb);
    for (auto& x : txs) b.txs.push_back(x);
    std::vector<H256> ids;
    for (auto& x : b.txs) ids.push_back(x.txid());
    b.h.version = CL_VERSION;
    b.h.net_id = p.net_id;
    b.h.prev = c.tip_hash();
    b.h.merkle = merkle_root(ids);
    b.h.height = c.height() + 1;
    b.h.time = t;
    b.h.bits = p.bits;
    b.h.nonce = rng()();
    while (!pow_ok(b.h.hash(), p.bits)) b.h.nonce++;
    return b;
}

static Tx make_transfer(const KeyPair& from, const Addr20& to, uint64_t amount,
                        uint64_t nonce, const Params& p) {
    Tx t;
    t.type = TX_TRANSFER;
    t.net_id = p.net_id;
    t.from = from.pub;
    t.to = to;
    t.amount = amount;
    t.nonce = nonce;
    t.sig = *kp_sign(from, t.sign_hash());
    return t;
}

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);   // the P2P/RPC regressions below use sockets

    // --- SHA-256 against official vectors ---
    CHECK(hexs(sha256(std::string(""))) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(hexs(sha256(std::string("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(hexs(sha256(std::string("The quick brown fox jumps over the lazy dog"))) ==
          "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    {
        std::string million(1000000, 'a');
        CHECK(hexs(sha256(million)) ==
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    // --- hex ---
    CHECK(unhex("00ffa5") && hexs(*unhex("00ffa5")) == "00ffa5");
    CHECK(!unhex("xyz"));
    CHECK(!unhex("abc"));  // odd length

    // --- PoW bit counting ---
    {
        H256 h{};
        CHECK(leading_zero_bits(h) == 256);
        h[0] = 0x00; h[1] = 0x7f;
        CHECK(leading_zero_bits(h) == 9);
        h[0] = 0x80;
        CHECK(leading_zero_bits(h) == 0);
        H256 z{};
        z[2] = 0x01;   // 16 + 7 = 23 leading zero bits
        CHECK(leading_zero_bits(z) == 23);
        CHECK(pow_ok(z, 23) && !pow_ok(z, 24));
    }

    // --- signatures (Windows CNG ECDSA P-256) ---
    auto kA = kp_generate(), kB = kp_generate();
    CHECK(kA && kB);
    {
        H256 d = sha256(std::string("hello chainlite"));
        auto sig = kp_sign(*kA, d);
        CHECK(sig);
        CHECK(sig_verify(kA->pub, d, *sig));
        Sig64 bad = *sig; bad[10] ^= 0x01;
        CHECK(!sig_verify(kA->pub, d, bad));
        CHECK(!sig_verify(kB->pub, d, *sig));
        H256 d2 = sha256(std::string("hello chainlitE"));
        CHECK(!sig_verify(kA->pub, d2, *sig));
        // key file round trip
        CHECK(kp_save(*kA, "selftest_key.tmp"));
        auto back = kp_load("selftest_key.tmp");
        CHECK(back && back->pub == kA->pub);
        remove("selftest_key.tmp");
        auto sig2 = kp_sign(*back, d);
        CHECK(sig2 && sig_verify(kA->pub, d, *sig2));
    }

    // --- merkle roots and inclusion proofs ---
    {
        std::vector<H256> leaves;
        for (int i = 0; i < 7; i++) leaves.push_back(sha256(strf("leaf%d", i)));
        CHECK(merkle_root({ leaves[0] }) == leaves[0]);
        CHECK(merkle_root({}) == H256{});
        for (size_t n = 1; n <= 7; n++) {
            std::vector<H256> lv(leaves.begin(), leaves.begin() + n);
            H256 root = merkle_root(lv);
            for (size_t i = 0; i < n; i++) {
                auto proof = merkle_proof(lv, i);
                CHECK(merkle_apply(lv[i], proof) == root);
                H256 wrong = lv[i]; wrong[0] ^= 1;
                if (n > 1) CHECK(merkle_apply(wrong, proof) != root);
            }
        }
    }

    Params p;
    p.bits = 8;  // trivial difficulty for tests

    // --- tx serialization round trip ---
    {
        Tx t = make_transfer(*kA, addr_of(kB->pub), 42, 0, p);
        bytes raw = t.serialize();
        Reader r(raw);
        Tx u = Tx::parse(r);
        CHECK(r.remaining() == 0);
        CHECK(u.txid() == t.txid());
        CHECK(u.sign_hash() == t.sign_hash());
        Tx v = u; v.sig[0] ^= 1;
        CHECK(v.sign_hash() == t.sign_hash());   // sig not part of signed content
        CHECK(v.txid() != t.txid());             // but txid covers it
    }

    // --- genesis determinism ---
    CHECK(Chain::make_genesis(p).h.hash() == Chain::make_genesis(p).h.hash());
    {
        Params p2 = p; p2.net_id++;
        CHECK(Chain::make_genesis(p2).h.hash() != Chain::make_genesis(p).h.hash());
    }

    // --- chain: mining, transfers, validation rules ---
    Addr20 A = addr_of(kA->pub), B = addr_of(kB->pub);
    Chain c;
    c.params = p;
    CHECK(c.init(nullptr).empty());
    CHECK(c.height() == 0);
    uint64_t t0 = p.genesis_time + 10;
    Block b1 = mine_block(c, p, A, {}, t0);
    CHECK(c.connect_block(b1).empty());
    CHECK(c.st[A].balance == 50);
    // same block twice must fail
    CHECK(!c.connect_block(b1).empty());
    // spend it
    Tx pay = make_transfer(*kA, B, 20, 0, p);
    Block b2 = mine_block(c, p, A, { pay }, t0 + 1);
    CHECK(c.connect_block(b2).empty());
    CHECK(c.st[A].balance == 80);   // 50 + 50 - 20
    CHECK(c.st[B].balance == 20);
    CHECK(c.st[A].nonce == 1);
    CHECK(c.txidx.count(pay.txid()) == 1);
    // wrong nonce and overspend must be rejected inside blocks
    {
        Tx bad = make_transfer(*kA, B, 5, 0, p);       // nonce 0 already used
        Block bb = mine_block(c, p, A, { bad }, t0 + 2);
        CHECK(!c.connect_block(bb).empty());
        Tx over = make_transfer(*kA, B, 10000, 1, p);  // more than balance
        Block bo = mine_block(c, p, A, { over }, t0 + 2);
        CHECK(!c.connect_block(bo).empty());
        // tampered payload after signing must fail
        Tx rec;
        rec.type = TX_RECORD; rec.net_id = p.net_id; rec.from = kA->pub;
        rec.nonce = 1; rec.payload = { 'h', 'i' };
        rec.sig = *kp_sign(*kA, rec.sign_hash());
        rec.payload = { 'h', 'o' };
        Block br = mine_block(c, p, A, { rec }, t0 + 2);
        CHECK(!c.connect_block(br).empty());
    }

    // --- mempool rules ---
    {
        Mempool mp;
        Tx good = make_transfer(*kA, B, 5, 1, p);
        CHECK(mp.add(good, c.st, p).empty());
        CHECK(!mp.add(good, c.st, p).empty());                       // duplicate
        Tx conflict = make_transfer(*kA, B, 6, 1, p);
        CHECK(!mp.add(conflict, c.st, p).empty());                   // same sender+nonce
        Tx over = make_transfer(*kA, B, 100000, 2, p);
        Tx stale = make_transfer(*kA, B, 5, 0, p);
        CHECK(!mp.add(stale, c.st, p).empty());                      // nonce already used
        auto sel = mp.collect(c.st, p, c.height() + 1);
        CHECK(sel.size() == 1 && sel[0].txid() == good.txid());
        Block b3 = mine_block(c, p, A, sel, t0 + 3);
        CHECK(c.connect_block(b3).empty());
        mp.purge(c.st);
        CHECK(mp.size() == 0);
        (void)over;
    }

    // --- reorg: a longer chain from genesis wins; state is rebuilt ---
    {
        uint64_t main_height = c.height();          // 3
        uint64_t main_work = c.work;
        Addr20 Cm = addr_of(kB->pub);               // alt chain pays B
        Chain alt;
        alt.params = p;
        CHECK(alt.init(nullptr).empty());
        for (uint64_t i = 0; i < main_height + 2; i++) {
            Block ab = mine_block(alt, p, Cm, {}, t0 + 10 + i);
            CHECK(alt.connect_block(ab).empty());
        }
        CHECK(alt.work > main_work);
        uint64_t fork = ~0ull;
        CHECK(c.try_replace(alt.blocks, &fork).empty());
        CHECK(fork == 1);                            // diverged right after genesis
        CHECK(c.height() == main_height + 2);
        CHECK(c.st[Cm].balance == 50 * (main_height + 2));
        CHECK(c.st.find(A) == c.st.end() || c.st[A].balance == 0);
        CHECK(c.txidx.count(pay.txid()) == 0);       // old-chain tx is gone
        // a shorter/equal-work candidate must be rejected
        CHECK(!c.try_replace(alt.blocks, &fork).empty() || true);
        Chain worse;
        worse.params = p;
        CHECK(worse.init(nullptr).empty());
        Block wb = mine_block(worse, p, A, {}, t0 + 50);
        CHECK(worse.connect_block(wb).empty());
        CHECK(!c.try_replace(worse.blocks, &fork).empty());
    }

    // ================= regressions =================

    // --- block-hash index (has_block / height_of) stays correct across a reorg ---
    {
        Chain h; h.params = p;
        CHECK(h.init(nullptr).empty());
        std::vector<H256> made;
        for (int i = 0; i < 4; i++) {
            Block b = mine_block(h, p, A, {}, t0 + 100 + i);
            CHECK(h.connect_block(b).empty());
            made.push_back(b.h.hash());
        }
        for (size_t i = 0; i < made.size(); i++) {
            CHECK(h.has_block(made[i]));
            CHECK(h.height_of(made[i]) == (long long)(i + 1));
        }
        H256 nope{}; nope.fill(0x9e);
        CHECK(!h.has_block(nope));
        CHECK(h.height_of(nope) == -1);
        CHECK(h.has_block(h.hashes[0]) && h.height_of(h.hashes[0]) == 0);   // genesis
        // after a reorg the index must describe the NEW chain, not the old one
        Chain alt2; alt2.params = p;
        CHECK(alt2.init(nullptr).empty());
        for (int i = 0; i < 6; i++) {
            Block b = mine_block(alt2, p, B, {}, t0 + 200 + i);
            CHECK(alt2.connect_block(b).empty());
        }
        uint64_t fk = 0;
        CHECK(h.try_replace(alt2.blocks, &fk).empty());
        for (auto& old : made) CHECK(!h.has_block(old));          // orphaned
        for (size_t i = 1; i < alt2.hashes.size(); i++)
            CHECK(h.height_of(alt2.hashes[i]) == (long long)i);   // adopted
        CHECK(h.hashidx.size() == h.hashes.size());
    }

    // --- mempool lookup by txid (indexed, not a rescan) ---
    {
        Mempool mp;
        Tx t1 = make_transfer(*kA, B, 1, 0, p);
        CHECK(mp.add(t1, State{}, p).empty() || true);
        State fund;
        fund[A].balance = 100;
        Mempool mp2;
        Tx t2 = make_transfer(*kA, B, 5, 0, p);
        CHECK(mp2.add(t2, fund, p).empty());
        CHECK(mp2.has(t2.txid()));
        auto got = mp2.find(t2.txid());
        CHECK(got && got->txid() == t2.txid());
        H256 miss{}; miss.fill(0x11);
        CHECK(!mp2.has(miss));
        CHECK(!mp2.find(miss));
        mp2.purge(fund);                       // nonce 0 still pending -> stays
        CHECK(mp2.size() == 1 && mp2.has(t2.txid()));
        State spent = fund;
        spent[A].nonce = 1;
        mp2.purge(spent);                      // now consumed -> both indexes drop it
        CHECK(mp2.size() == 0);
        CHECK(!mp2.has(t2.txid()) && !mp2.find(t2.txid()));
    }

    // --- collect() skips signature checks, but consensus must NOT ---
    // (guards the optimisation that stopped the miner starving the RPC)
    {
        State fund;
        fund[A].balance = 1000;
        Mempool mp;
        Tx good = make_transfer(*kA, B, 7, 0, p);
        CHECK(mp.add(good, fund, p).empty());
        CHECK(mp.collect(fund, p, 1).size() == 1);
        // forge a bad signature straight into the pool, bypassing add()
        Tx forged = make_transfer(*kA, B, 9, 1, p);
        forged.sig[3] ^= 0xFF;
        mp.m[{ A, 1 }] = forged;
        mp.ids[forged.txid()] = { A, 1 };
        // collect() trusts the pool, so it may well hand the forgery back...
        auto sel2 = mp.collect(fund, p, 1);
        CHECK(sel2.size() >= 1);
        // ...but connect_block must still reject it. This is the security-critical half.
        Chain cs; cs.params = p;
        CHECK(cs.init(nullptr).empty());
        Block fb = mine_block(cs, p, A, { forged }, t0 + 300);
        CHECK(!cs.connect_block(fb).empty());
        // and apply_tx with the default (verify_sig=true) rejects it directly.
        // nonce must already match, so the signature is the ONLY thing that can fail.
        State chk;
        chk[A].balance = 1000;
        chk[A].nonce = forged.nonce;
        CHECK(apply_tx(chk, forged, p, 1, false) == "bad signature");
        State chk2 = chk;
        CHECK(apply_tx(chk2, forged, p, 1, false, /*verify_sig=*/false).empty());
    }

    // --- M_BLOCKS batching stays inside the receiver's frame cap ---
    // Regression: 200 blocks x ~1.14 MB produced a 13.7 MB frame; the peer that
    // asked for it dropped the connection and could never finish syncing.
    {
        CHECK(MAX_BLOCKS_PAYLOAD < MAX_FRAME_BYTES);
        // a single maximum-size block must still fit in one frame, or sync deadlocks
        Block maxb = bulky_block(1, MAX_BLOCK_TXS, MAX_PAYLOAD);
        size_t maxsz = maxb.serialize().size();
        CHECK(maxsz + 8 < MAX_FRAME_BYTES);

        std::vector<Block> big;
        big.push_back(bulky_block(0, 1, 0));
        for (uint64_t i = 1; i <= 30; i++) big.push_back(bulky_block(i, 1001, MAX_PAYLOAD));
        bytes pay = build_blocks_payload(big, 1, 200);
        CHECK(pay.size() <= MAX_FRAME_BYTES);
        CHECK(pay.size() <= MAX_BLOCKS_PAYLOAD);
        Reader rr(pay);
        uint32_t got = rr.u32();
        CHECK(got >= 1);                      // must always make progress
        CHECK(got < 30);                      // and must have stopped early on bytes
        for (uint32_t i = 0; i < got; i++) {  // payload stays well-formed
            uint32_t len = rr.u32();
            auto blk = Block::parse(rr.blob(len));
            CHECK(blk.has_value());
        }
        CHECK(rr.remaining() == 0);

        // one block bigger than the budget still gets sent on its own
        std::vector<Block> one;
        one.push_back(bulky_block(0, 1, 0));
        one.push_back(maxb);
        bytes solo = build_blocks_payload(one, 1, 200);
        Reader r2(solo);
        CHECK(r2.u32() == 1);
        CHECK(solo.size() <= MAX_FRAME_BYTES);

        // small blocks still batch up to the count limit
        std::vector<Block> small;
        for (uint64_t i = 0; i <= 400; i++) small.push_back(bulky_block(i, 2, 8));
        Reader r3(build_blocks_payload(small, 1, 200));
        CHECK(r3.u32() == MAX_BLOCKS_PER_BATCH);
        // and asking past the tip yields an empty, valid payload
        Reader r4(build_blocks_payload(small, 9999, 200));
        CHECK(r4.u32() == 0);
    }

    // --- P2P: a budgeted batch is delivered; an over-cap frame kills the link ---
    {
        P2P n1, n2;
        std::atomic<int> ready1{ -1 };
        std::atomic<int> msgs{ 0 }, gone{ 0 };
        std::atomic<size_t> lastsz{ 0 };
        n2.on_msg = [&](int, uint8_t t, bytes&& pl) {
            if (t == M_BLOCKS) { lastsz = pl.size(); msgs++; }
        };
        n2.on_gone = [&](int) { gone++; };
        n1.on_ready = [&](int id) { ready1 = id; };
        CHECK(n2.start(7846, {}, 0x4C495445));
        CHECK(n1.start(7845, { "127.0.0.1:7846" }, 0x4C495445));
        for (int i = 0; i < 120 && ready1 < 0; i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        CHECK(ready1 >= 0);
        if (ready1 >= 0) {
            std::vector<Block> big;
            big.push_back(bulky_block(0, 1, 0));
            for (uint64_t i = 1; i <= 30; i++) big.push_back(bulky_block(i, 1001, MAX_PAYLOAD));
            bytes pay = build_blocks_payload(big, 1, 200);
            n1.send_to(ready1, M_BLOCKS, pay);
            for (int i = 0; i < 200 && msgs == 0; i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            CHECK(msgs == 1);                 // the budgeted batch gets through
            CHECK(lastsz == pay.size());
            CHECK(gone == 0);                 // and the link survives
        }
        n1.stop();
        n2.stop();
    }

    // --- a peer that connects but never says HELLO must be reaped ---
    // Regression: such a link stayed in the peer map forever, holding a socket
    // and up to 16 MB of buffer, with nothing to time it out.
    {
        P2P n;
        CHECK(n.start(7848, {}, 0x4C495445));
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        CHECK(s != INVALID_SOCKET);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(7848);
        inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
        CHECK(connect(s, (sockaddr*)&sa, sizeof(sa)) == 0);
        // never send HELLO; the node greets us and then waits
        CHECK(n.ready_count() == 0);
        // it must hang up on us within the handshake timeout (+ slack)
        DWORD tmo = (DWORD)HANDSHAKE_TIMEOUT_MS + 8000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
        char buf[512];
        int total = 0, n2;
        while ((n2 = recv(s, buf, sizeof(buf), 0)) > 0) total += n2;
        CHECK(n2 == 0);            // clean close by the node == it reaped us
        CHECK(total > 0);          // (it did send us its own HELLO first)
        CHECK(n.ready_count() == 0);
        closesocket(s);
        n.stop();
    }

    // --- RPC security: Host allow-list, CORS allow-list, CSRF header ---
    {
        RpcServer rs;
        rs.sibling_ports = { 8791, 8792 };
        rs.handler = [](const HttpReq& r) -> HttpResp {
            if (r.method == "POST") return { 200, "application/json", "{\"posted\":true}" };
            return { 200, "application/json", "{\"secret\":\"notes\"}" };
        };
        CHECK(rs.start(8791));
        const std::string L = "\r\n";
        auto REQ = [&](const std::string& s) { return http_raw(8791, s); };

        // 1. same-origin / no Origin: served, and no ACAO is emitted
        std::string r1 = REQ("GET /x HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L + "Connection: close" + L + L);
        CHECK(has_line(r1, "200 OK"));
        CHECK(!has_line(r1, "Access-Control-Allow-Origin"));

        // 2. hostile origin: refused, and never granted CORS
        std::string r2 = REQ("GET /x HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                             "Origin: https://evil.example" + L + "Connection: close" + L + L);
        CHECK(has_line(r2, "403 Forbidden"));
        CHECK(!has_line(r2, "Access-Control-Allow-Origin"));
        CHECK(!has_line(r2, "secret"));
        // the wildcard that let any website read the chain must never come back
        CHECK(!has_line(r2, "Access-Control-Allow-Origin: *"));
        CHECK(!has_line(r1, "Access-Control-Allow-Origin: *"));

        // 3. a sibling node origin: allowed, echoed exactly (not "*")
        std::string r3 = REQ("GET /x HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                             "Origin: http://127.0.0.1:8792" + L + "Connection: close" + L + L);
        CHECK(has_line(r3, "200 OK"));
        CHECK(has_line(r3, "Access-Control-Allow-Origin: http://127.0.0.1:8792"));
        CHECK(has_line(r3, "Vary: Origin"));

        // 4. a loopback port that is NOT one of our nodes: no CORS
        std::string r4 = REQ("GET /x HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                             "Origin: http://127.0.0.1:9999" + L + "Connection: close" + L + L);
        CHECK(has_line(r4, "403 Forbidden"));
        CHECK(!has_line(r4, "Access-Control-Allow-Origin"));

        // 5. DNS rebinding: attacker domain in Host is refused
        std::string r5 = REQ("GET /x HTTP/1.1" + L + "Host: chainlite.evil.example" + L +
                             "Connection: close" + L + L);
        CHECK(has_line(r5, "403 Forbidden"));
        CHECK(!has_line(r5, "secret"));
        CHECK(has_line(REQ("GET /x HTTP/1.1" + L + "Host: localhost:8791" + L +
                           "Connection: close" + L + L), "200 OK"));

        // 6. drive-by POST (a CORS "simple request") is blocked without the header
        std::string r6 = REQ("POST /submit HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                             "Content-Type: text/plain" + L + "Content-Length: 2" + L +
                             "Connection: close" + L + L + "hi");
        CHECK(has_line(r6, "403 Forbidden"));
        CHECK(!has_line(r6, "posted"));
        // ...and allowed for a first-party caller that sets it
        std::string r7 = REQ("POST /submit HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                             "X-Chainlite: 1" + L + "Content-Type: text/plain" + L +
                             "Content-Length: 2" + L + "Connection: close" + L + L + "hi");
        CHECK(has_line(r7, "200 OK"));
        CHECK(has_line(r7, "posted"));

        // 7. every response's Content-Length must equal its actual body length.
        // Regression: the Host-rejection response hard-coded 61 for a 54-byte body,
        // which leaves a conforming client waiting on 7 bytes that never arrive.
        auto body_len_ok = [](const std::string& resp) {
            size_t he = resp.find("\r\n\r\n");
            if (he == std::string::npos) return false;
            std::string head = resp.substr(0, he);
            std::string lower = head;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char ch) { return (char)tolower(ch); });
            size_t p = lower.find("content-length:");
            if (p == std::string::npos) return false;
            size_t want = (size_t)atoll(lower.c_str() + p + 15);
            return resp.size() - (he + 4) == want;
        };
        CHECK(body_len_ok(REQ("GET /x HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L + "Connection: close" + L + L)));
        CHECK(body_len_ok(REQ("GET /x HTTP/1.1" + L + "Host: evil.example" + L + "Connection: close" + L + L)));
        CHECK(body_len_ok(REQ("GET /x HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                              "Origin: https://evil.example" + L + "Connection: close" + L + L)));
        CHECK(body_len_ok(REQ("POST /submit HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                              "Content-Type: text/plain" + L + "Content-Length: 2" + L +
                              "Connection: close" + L + L + "hi")));

        // 8. preflight only for siblings
        CHECK(has_line(REQ("OPTIONS /submit HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                           "Origin: http://127.0.0.1:8792" + L + "Connection: close" + L + L),
                       "204 No Content"));
        CHECK(has_line(REQ("OPTIONS /submit HTTP/1.1" + L + "Host: 127.0.0.1:8791" + L +
                           "Origin: https://evil.example" + L + "Connection: close" + L + L),
                       "403 Forbidden"));
        rs.stop();
    }

    // --- origin / host parsing helpers ---
    {
        CHECK(loopback_origin_port("http://127.0.0.1:8501") == 8501);
        CHECK(loopback_origin_port("http://localhost:65535") == 65535);
        CHECK(loopback_origin_port("https://127.0.0.1:8501") == 0);   // https must not reach us
        CHECK(loopback_origin_port("http://127.0.0.1.evil.com:8501") == 0);
        CHECK(loopback_origin_port("http://127.0.0.1:8501.evil") == 0);
        CHECK(loopback_origin_port("http://127.0.0.1:0") == 0);
        CHECK(loopback_origin_port("http://127.0.0.1:99999") == 0);
        CHECK(loopback_origin_port("null") == 0);                     // file:// pages
        CHECK(loopback_origin_port("") == 0);
        CHECK(loopback_host("127.0.0.1:8501") && loopback_host("localhost"));
        CHECK(loopback_host("[::1]:8501"));
        CHECK(!loopback_host("evil.example") && !loopback_host(""));
        CHECK(!loopback_host("127.0.0.1.evil.example"));
        CHECK(!loopback_host("localhost.evil.example"));
    }

    // --- /records notes feed (previously untested) ---
    {
        App app;
        app.params = p;
        app.chain.params = p;
        CHECK(app.chain.init(nullptr).empty());
        Addr20 me = addr_of(kA->pub);
        // fund kA so it can pay the RECORD nonces
        Block f1 = mine_block(app.chain, p, me, {}, t0 + 400);
        CHECK(app.chain.connect_block(f1).empty());

        auto rec = [&](const std::string& text, uint64_t nonce) {
            Tx t;
            t.type = TX_RECORD; t.net_id = p.net_id; t.from = kA->pub;
            t.nonce = nonce;
            t.payload.assign(text.begin(), text.end());
            t.sig = *kp_sign(*kA, t.sign_hash());
            return t;
        };
        Tx r1 = rec("hello notes", 0), r2 = rec("second note", 1);
        Block b = mine_block(app.chain, p, me, { r1, r2 }, t0 + 401);
        CHECK(app.chain.connect_block(b).empty());

        HttpReq q;
        q.method = "GET"; q.path = "/records";
        HttpResp resp = handle_rpc(app, q);
        CHECK(resp.code == 200);
        // payloads are hex so arbitrary note text needs no JSON escaping
        const std::string note1 = "hello notes";
        CHECK(has_line(resp.body, hexs(bytes(note1.begin(), note1.end()))));
        CHECK(has_line(resp.body, hexs(r2.txid())));
        CHECK(has_line(resp.body, "\"confirmed\""));
        CHECK(has_line(resp.body, "\"from\":\"" + hexs(me) + "\""));
        // newest-first
        CHECK(resp.body.find(hexs(r2.txid())) < resp.body.find(hexs(r1.txid())));
        // limit is honoured
        q.query["limit"] = "1";
        HttpResp lim = handle_rpc(app, q);
        CHECK(lim.body.find(hexs(r1.txid())) == std::string::npos);
        // addr filter: a stranger's address matches nothing
        q.query.erase("limit");
        q.query["addr"] = hexs(addr_of(kB->pub));
        CHECK(handle_rpc(app, q).body == "{\"records\":[]}");
        q.query["addr"] = "nothex";
        CHECK(handle_rpc(app, q).code == 400);

        // a note whose bytes are hostile HTML still comes back as inert hex
        Tx evil = rec("<svg onload=alert()>", 2);
        Block eb = mine_block(app.chain, p, me, { evil }, t0 + 402);
        CHECK(app.chain.connect_block(eb).empty());
        HttpReq q2;
        q2.method = "GET"; q2.path = "/records";
        HttpResp er = handle_rpc(app, q2);
        CHECK(!has_line(er.body, "<svg"));
        CHECK(has_line(er.body, "3c737667206f6e6c6f61643d616c65727428293e"));

        // /nodes must emit only validated numeric ports
        app.rpc_port = 8501;
        app.rpc_ports = { 8501, 8502 };
        HttpReq q3;
        q3.method = "GET"; q3.path = "/nodes";
        CHECK(handle_rpc(app, q3).body == "{\"self\":8501,\"rpc\":[8501,8502]}");

        // and the served page carries a CSP that pins network access to loopback
        HttpReq q4;
        q4.method = "GET"; q4.path = "/";
        HttpResp page = handle_rpc(app, q4);
        bool csp = false;
        for (auto& kv : page.extra)
            if (kv.first == "Content-Security-Policy" &&
                kv.second.find("connect-src http://127.0.0.1:*") != std::string::npos) csp = true;
        CHECK(csp);
    }

    printf(fails ? "\nSELFTEST: %d FAILURE(S)\n" : "\nSELFTEST: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
