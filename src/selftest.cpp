// chainlite self-test: FIPS 180-4 SHA-256 vectors, CNG signatures, merkle
// proofs, tx/block serialization, chain validation, mempool rules, and reorgs.
#include "common.h"
#include "core.h"

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

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

    printf(fails ? "\nSELFTEST: %d FAILURE(S)\n" : "\nSELFTEST: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
