// chainlite — consensus core: transactions, blocks, merkle proofs, account
// state, chain validation + reorg, mempool, SQLite persistence.
#pragma once
#include "common.h"
#include "sha256.h"
#include "crypto_cng.h"
#include "sqlite_shim.h"

// ---------- consensus parameters ----------
struct Params {
    uint32_t net_id       = 0x4C495445;   // "LITE"
    uint32_t bits         = 20;           // fixed PoW difficulty (leading zero bits)
    uint64_t reward       = 50;           // coinbase reward per block (integer LITE)
    uint64_t genesis_time = 1753000000;   // fixed => deterministic genesis
};
constexpr uint32_t CL_VERSION      = 1;
constexpr size_t   MAX_PAYLOAD     = 1024;
constexpr size_t   MAX_BLOCK_TXS   = 5000;
constexpr uint64_t MAX_TIME_SKEW_S = 7200;

// ---------- transactions ----------
enum TxType : uint8_t { TX_COINBASE = 0, TX_TRANSFER = 1, TX_RECORD = 2 };

struct Tx {
    uint8_t  type = TX_TRANSFER;
    uint32_t net_id = 0;
    Pub64    from{};      // sender public key (zeros for coinbase)
    Addr20   to{};        // recipient address (miner for coinbase, unused for record)
    uint64_t amount = 0;
    uint64_t nonce  = 0;  // sender's tx counter; coinbase: block height
    bytes    payload;     // RECORD data (<= MAX_PAYLOAD)
    Sig64    sig{};       // zeros for coinbase

    void ser(Writer& w, bool with_sig) const {
        w.u8(type); w.u32(net_id); w.arr(from); w.arr(to);
        w.u64(amount); w.u64(nonce);
        w.u16((uint16_t)payload.size()); w.blob(payload);
        if (with_sig) w.arr(sig);
    }
    bytes serialize() const { Writer w; ser(w, true); return w.b; }
    H256 sign_hash() const { Writer w; ser(w, false); return sha256d(w.b); }
    H256 txid() const { Writer w; ser(w, true); return sha256d(w.b); }

    static Tx parse(Reader& r) {
        Tx t;
        t.type = r.u8(); t.net_id = r.u32();
        t.from = r.arr<64>(); t.to = r.arr<20>();
        t.amount = r.u64(); t.nonce = r.u64();
        uint16_t pl = r.u16();
        if (pl > MAX_PAYLOAD) throw std::runtime_error("payload too big");
        t.payload = r.blob(pl);
        t.sig = r.arr<64>();
        return t;
    }
};

// ---------- block header (100 bytes) ----------
constexpr size_t HEADER_SIZE  = 100;
constexpr size_t NONCE_OFFSET = 92;   // little-endian u64 nonce lives at bytes 92..99

struct BlockHeader {
    uint32_t version = CL_VERSION;
    uint32_t net_id  = 0;
    H256     prev{};
    H256     merkle{};
    uint64_t height = 0;
    uint64_t time   = 0;
    uint32_t bits   = 0;
    uint64_t nonce  = 0;

    void ser(Writer& w) const {
        w.u32(version); w.u32(net_id); w.arr(prev); w.arr(merkle);
        w.u64(height); w.u64(time); w.u32(bits); w.u64(nonce);
    }
    bytes serialize() const { Writer w; ser(w); return w.b; }
    H256 hash() const { Writer w; ser(w); return sha256d(w.b); }
    static BlockHeader parse(Reader& r) {
        BlockHeader h;
        h.version = r.u32(); h.net_id = r.u32();
        h.prev = r.arr<32>(); h.merkle = r.arr<32>();
        h.height = r.u64(); h.time = r.u64(); h.bits = r.u32(); h.nonce = r.u64();
        return h;
    }
};

struct Block {
    BlockHeader h;
    std::vector<Tx> txs;

    bytes serialize() const {
        Writer w;
        h.ser(w);
        w.u32((uint32_t)txs.size());
        for (auto& t : txs) t.ser(w, true);
        return w.b;
    }
    static std::optional<Block> parse(const bytes& raw) {
        try {
            Reader r(raw);
            Block b;
            b.h = BlockHeader::parse(r);
            uint32_t n = r.u32();
            if (n > MAX_BLOCK_TXS) return std::nullopt;
            b.txs.reserve(n);
            for (uint32_t i = 0; i < n; i++) b.txs.push_back(Tx::parse(r));
            if (r.remaining() != 0) return std::nullopt;
            return b;
        } catch (...) { return std::nullopt; }
    }
};

// ---------- merkle tree (Bitcoin-style: odd level duplicates last node) ----------
inline H256 merkle_parent(const H256& l, const H256& r) {
    uint8_t buf[64];
    memcpy(buf, l.data(), 32);
    memcpy(buf + 32, r.data(), 32);
    return sha256d(buf, 64);
}
inline H256 merkle_root(std::vector<H256> level) {
    if (level.empty()) return H256{};      // empty block => zero root
    while (level.size() > 1) {
        if (level.size() & 1) level.push_back(level.back());
        std::vector<H256> up;
        up.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2)
            up.push_back(merkle_parent(level[i], level[i + 1]));
        level = std::move(up);
    }
    return level[0];
}
struct MerkleStep { H256 h; uint8_t left; };  // left=1: sibling is on the left
inline std::vector<MerkleStep> merkle_proof(std::vector<H256> level, size_t idx) {
    std::vector<MerkleStep> steps;
    while (level.size() > 1) {
        if (level.size() & 1) level.push_back(level.back());
        size_t sib = idx ^ 1;
        steps.push_back({ level[sib], (uint8_t)((idx & 1) ? 1 : 0) });
        std::vector<H256> up;
        up.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2)
            up.push_back(merkle_parent(level[i], level[i + 1]));
        level = std::move(up);
        idx >>= 1;
    }
    return steps;
}
inline H256 merkle_apply(H256 leaf, const std::vector<MerkleStep>& steps) {
    for (auto& s : steps)
        leaf = s.left ? merkle_parent(s.h, leaf) : merkle_parent(leaf, s.h);
    return leaf;
}

// ---------- account state ----------
struct Account { uint64_t balance = 0; uint64_t nonce = 0; };
using State = std::map<Addr20, Account>;

// Validate + apply one tx to `st`. Returns "" on success, error string otherwise.
inline std::string apply_tx(State& st, const Tx& t, const Params& p, uint64_t height, bool is_first) {
    if (t.net_id != p.net_id) return "wrong network id";
    if (t.type == TX_COINBASE) {
        if (!is_first) return "coinbase must be first tx";
        if (!is_zero(t.from) || !is_zero(t.sig)) return "coinbase must have zero from/sig";
        if (!t.payload.empty()) return "coinbase payload not allowed";
        if (t.amount != p.reward) return "bad coinbase amount";
        if (t.nonce != height) return "coinbase nonce must equal height";
        st[t.to].balance += t.amount;
        return "";
    }
    if (is_first) return "first tx must be coinbase";
    if (is_zero(t.from)) return "missing sender";
    if (!sig_verify(t.from, t.sign_hash(), t.sig)) return "bad signature";
    Addr20 a = addr_of(t.from);
    Account& acct = st[a];
    if (t.nonce != acct.nonce) return strf("bad nonce (want %llu got %llu)",
                                          (unsigned long long)acct.nonce, (unsigned long long)t.nonce);
    if (t.type == TX_TRANSFER) {
        if (!t.payload.empty()) return "transfer payload not allowed";
        if (acct.balance < t.amount) return "insufficient balance";
        acct.balance -= t.amount;
        st[t.to].balance += t.amount;
    } else if (t.type == TX_RECORD) {
        if (t.amount != 0) return "record amount must be 0";
        if (t.payload.empty() || t.payload.size() > MAX_PAYLOAD) return "bad payload size";
    } else return "unknown tx type";
    acct.nonce++;
    return "";
}

// ---------- the chain ----------
class Chain {
public:
    Params params;
    std::vector<Block> blocks;
    std::vector<H256>  hashes;
    State st;
    std::map<H256, std::pair<uint32_t, uint32_t>> txidx;  // txid -> (height, index)
    uint64_t work = 0;
    sq::Db* db = nullptr;
    bool persisting = true;

    static Block make_genesis(const Params& p) {
        Block g;
        g.h.version = CL_VERSION;
        g.h.net_id  = p.net_id;
        g.h.height  = 0;
        g.h.time    = p.genesis_time;
        g.h.bits    = 0;
        g.h.nonce   = 0;
        g.h.merkle  = H256{};
        return g;
    }

    uint64_t height() const { return blocks.empty() ? 0 : blocks.back().h.height; }
    const Block& tip() const { return blocks.back(); }
    const H256& tip_hash() const { return hashes.back(); }
    bool has_block(const H256& h) const {
        for (auto& x : hashes) if (x == h) return true;
        return false;
    }

    // Validate `b` as the next block and append it. "" on success.
    std::string connect_block(const Block& b) {
        if (blocks.empty()) {
            // only the exact deterministic genesis may start the chain
            Block g = make_genesis(params);
            if (b.h.hash() != g.h.hash() || !b.txs.empty()) return "invalid genesis";
            append(b, 1);
            return "";
        }
        const BlockHeader& prev = tip().h;
        if (b.h.version != CL_VERSION) return "bad version";
        if (b.h.net_id != params.net_id) return "wrong network";
        if (b.h.height != prev.height + 1) return "bad height";
        if (b.h.prev != tip_hash()) return "prev hash mismatch";
        if (b.h.bits != params.bits) return "bad difficulty";
        H256 bh = b.h.hash();
        if (!pow_ok(bh, b.h.bits)) return "insufficient proof of work";
        if (b.h.time > now_s() + MAX_TIME_SKEW_S) return "timestamp too far in future";
        if (b.txs.empty() || b.txs.size() > MAX_BLOCK_TXS) return "bad tx count";
        std::vector<H256> ids;
        ids.reserve(b.txs.size());
        for (auto& t : b.txs) ids.push_back(t.txid());
        if (merkle_root(ids) != b.h.merkle) return "merkle mismatch";
        State tmp = st;
        for (size_t i = 0; i < b.txs.size(); i++) {
            std::string err = apply_tx(tmp, b.txs[i], params, b.h.height, i == 0);
            if (!err.empty()) return strf("tx %zu: %s", i, err.c_str());
        }
        st = std::move(tmp);
        append(b, work_of(b.h.bits));
        return "";
    }

    // Adopt `cand` (a full chain from genesis) if valid and strictly more work.
    // On success returns the fork height via *fork_out.
    std::string try_replace(const std::vector<Block>& cand, uint64_t* fork_out) {
        if (cand.empty()) return "empty candidate";
        Chain tmp;
        tmp.params = params;
        tmp.persisting = false;
        for (auto& b : cand) {
            std::string err = tmp.connect_block(b);
            if (!err.empty()) return strf("candidate height %llu: %s",
                                          (unsigned long long)b.h.height, err.c_str());
        }
        if (tmp.work <= work) return "candidate has no more work than current chain";
        uint64_t fork = 0;
        while (fork < hashes.size() && fork < tmp.hashes.size() && hashes[fork] == tmp.hashes[fork]) fork++;
        blocks = std::move(tmp.blocks);
        hashes = std::move(tmp.hashes);
        st     = std::move(tmp.st);
        txidx  = std::move(tmp.txidx);
        work   = tmp.work;
        if (db && persisting) {
            db->exec("BEGIN IMMEDIATE");
            db_truncate_from(fork);
            for (uint64_t h = fork; h < blocks.size(); h++) db_insert(blocks[h]);
            db->exec("COMMIT");
        }
        if (fork_out) *fork_out = fork;
        return "";
    }

    // Load from db (creating genesis if empty). Returns "" or error.
    std::string init(sq::Db* database) {
        db = database;
        if (db) {
            if (!db->exec("PRAGMA journal_mode=WAL") ||
                !db->exec("PRAGMA synchronous=NORMAL") ||
                !db->exec("CREATE TABLE IF NOT EXISTS blocks("
                          "height INTEGER PRIMARY KEY, hash TEXT, prev TEXT, time INTEGER,"
                          "ntx INTEGER, raw BLOB)") ||
                !db->exec("CREATE TABLE IF NOT EXISTS txs("
                          "txid TEXT, height INTEGER, idx INTEGER, type INTEGER,"
                          "from_addr TEXT, to_addr TEXT, amount INTEGER, nonce INTEGER, payload BLOB)"))
                return "schema: " + db->errmsg();
            std::vector<bytes> raws;
            {
                sq::Db::St q(*db, "SELECT raw FROM blocks ORDER BY height");
                if (!q.ok()) return "load query failed";
                while (q.step() == CL_SQLITE_ROW) raws.push_back(q.col_blob(0));
            }
            persisting = false;
            uint64_t good = 0;
            for (auto& raw : raws) {
                auto b = Block::parse(raw);
                if (!b) break;
                if (!connect_block(*b).empty()) break;
                good++;
            }
            persisting = true;
            if (good < raws.size()) {
                logl("chain", strf("database corrupt beyond height %llu; truncating (peers will re-sync us)",
                                   (unsigned long long)(good ? good - 1 : 0)));
                db->exec("BEGIN IMMEDIATE");
                db_truncate_from(good);
                db->exec("COMMIT");
            }
        }
        if (blocks.empty()) {
            std::string err = connect_block(make_genesis(params));
            if (!err.empty()) return "genesis: " + err;
        }
        return "";
    }

private:
    void append(const Block& b, uint64_t w) {
        H256 bh = b.h.hash();
        for (size_t i = 0; i < b.txs.size(); i++)
            txidx[b.txs[i].txid()] = { (uint32_t)b.h.height, (uint32_t)i };
        blocks.push_back(b);
        hashes.push_back(bh);
        work += w;
        if (db && persisting) db_insert(b);
    }
    void db_insert(const Block& b) {
        sq::Db::St s(*db, "INSERT OR REPLACE INTO blocks(height,hash,prev,time,ntx,raw) VALUES(?,?,?,?,?,?)");
        if (s.ok()) {
            s.bind_i64(1, (long long)b.h.height);
            s.bind_text(2, hexs(b.h.hash()));
            s.bind_text(3, hexs(b.h.prev));
            s.bind_i64(4, (long long)b.h.time);
            s.bind_i64(5, (long long)b.txs.size());
            s.bind_blob(6, b.serialize());
            s.step();
        }
        for (size_t i = 0; i < b.txs.size(); i++) {
            const Tx& t = b.txs[i];
            sq::Db::St ts(*db, "INSERT INTO txs(txid,height,idx,type,from_addr,to_addr,amount,nonce,payload) "
                               "VALUES(?,?,?,?,?,?,?,?,?)");
            if (!ts.ok()) continue;
            ts.bind_text(1, hexs(t.txid()));
            ts.bind_i64(2, (long long)b.h.height);
            ts.bind_i64(3, (long long)i);
            ts.bind_i64(4, t.type);
            ts.bind_text(5, t.type == TX_COINBASE ? std::string("coinbase") : hexs(addr_of(t.from)));
            ts.bind_text(6, hexs(t.to));
            ts.bind_i64(7, (long long)t.amount);
            ts.bind_i64(8, (long long)t.nonce);
            ts.bind_blob(9, t.payload);
            ts.step();
        }
    }
    void db_truncate_from(uint64_t h) {
        {
            sq::Db::St s(*db, "DELETE FROM blocks WHERE height>=?");
            if (s.ok()) { s.bind_i64(1, (long long)h); s.step(); }
        }
        {
            sq::Db::St s(*db, "DELETE FROM txs WHERE height>=?");
            if (s.ok()) { s.bind_i64(1, (long long)h); s.step(); }
        }
    }
};

// ---------- mempool ----------
class Mempool {
public:
    // keyed by (sender address, nonce) so conflicting double-spends can't coexist
    std::map<std::pair<Addr20, uint64_t>, Tx> m;
    std::set<H256> ids;

    std::string add(const Tx& t, const State& st, const Params& p) {
        if (t.type == TX_COINBASE) return "coinbase not allowed in mempool";
        if (t.net_id != p.net_id) return "wrong network id";
        if (m.size() >= 10000) return "mempool full";
        H256 id = t.txid();
        if (ids.count(id)) return "already in mempool";
        if (is_zero(t.from)) return "missing sender";
        if (!sig_verify(t.from, t.sign_hash(), t.sig)) return "bad signature";
        Addr20 a = addr_of(t.from);
        auto it = st.find(a);
        uint64_t cur = (it == st.end()) ? 0 : it->second.nonce;
        if (t.nonce < cur) return "nonce already used";
        if (t.nonce > cur + 16) return "nonce too far ahead";
        if (t.type == TX_TRANSFER) {
            uint64_t bal = (it == st.end()) ? 0 : it->second.balance;
            if (t.nonce == cur && bal < t.amount) return "insufficient balance";
            if (!t.payload.empty()) return "transfer payload not allowed";
        } else if (t.type == TX_RECORD) {
            if (t.amount != 0) return "record amount must be 0";
            if (t.payload.empty() || t.payload.size() > MAX_PAYLOAD) return "bad payload size";
        } else return "unknown tx type";
        auto key = std::make_pair(a, t.nonce);
        if (m.count(key)) return "conflicting tx (same sender+nonce) already pending";
        m[key] = t;
        ids.insert(id);
        return "";
    }

    // Pick includable txs in valid nonce order (validated against a state copy).
    std::vector<Tx> collect(const State& base, const Params& p, uint64_t height, size_t maxn = 1000) {
        std::vector<Tx> out;
        State tmp = base;
        bool progress = true;
        while (progress && out.size() < maxn) {
            progress = false;
            for (auto& [key, tx] : m) {
                auto it = tmp.find(key.first);
                uint64_t cur = (it == tmp.end()) ? 0 : it->second.nonce;
                if (key.second != cur) continue;
                if (apply_tx(tmp, tx, p, height, false).empty()) {
                    out.push_back(tx);
                    progress = true;
                    if (out.size() >= maxn) break;
                }
            }
        }
        return out;
    }

    // Drop txs whose nonce the chain has already consumed.
    void purge(const State& st) {
        for (auto it = m.begin(); it != m.end();) {
            auto sit = st.find(it->first.first);
            uint64_t cur = (sit == st.end()) ? 0 : sit->second.nonce;
            if (it->first.second < cur) {
                ids.erase(it->second.txid());
                it = m.erase(it);
            } else ++it;
        }
    }
    size_t size() const { return m.size(); }
    bool has(const H256& id) const { return ids.count(id) > 0; }
    std::optional<Tx> find(const H256& id) const {
        for (auto& [k, t] : m) if (t.txid() == id) return t;
        return std::nullopt;
    }
};
