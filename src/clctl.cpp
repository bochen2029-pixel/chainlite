// clctl — chainlite wallet + query CLI. Talks to any node's local RPC.
//
//   clctl keygen [--out wallet.key]
//   clctl addr    --key wallet.key
//   clctl status | mempool | tail [--n 10]          [--rpc 8501]
//   clctl balance (--addr <hex40> | --key FILE)
//   clctl send    --key FILE --to <hex40> --amount N
//   clctl record  --key FILE (--text "..." | --file PATH [--hash-only])
//   clctl block   (--height N | --hash <hex64>)
//   clctl tx      --id <hex64>
//   clctl prove   --txid <hex64> [--out proof.txt]
//   clctl verify  --proof proof.txt [--rpc-all 8501,8502,8503]
#include "common.h"
#include "core.h"
#include "http_client.h"

static std::string g_host = "127.0.0.1";
static uint16_t g_port = 8501;

static void set_rpc(const std::string& spec) {
    if (spec.empty()) return;
    size_t c = spec.rfind(':');
    if (c == std::string::npos) { g_port = (uint16_t)atoi(spec.c_str()); }
    else { g_host = spec.substr(0, c); g_port = (uint16_t)atoi(spec.c_str() + c + 1); }
}
static int rpc_get(const std::string& path, std::string& out) {
    return http_req(g_host, g_port, "GET", path, "", out);
}
static int rpc_post(const std::string& path, const std::string& body, std::string& out) {
    return http_req(g_host, g_port, "POST", path, body, out);
}
static bool die(const std::string& msg) { fprintf(stderr, "error: %s\n", msg.c_str()); return false; }

static std::optional<KeyPair> need_key(const Args& a) {
    std::string kf = a.get("key", "wallet.key");
    auto kp = kp_load(kf);
    if (!kp) fprintf(stderr, "error: could not load key file '%s' (create one with: clctl keygen --out %s)\n",
                     kf.c_str(), kf.c_str());
    return kp;
}

// Fetch the node's net id + our current account nonce, build, sign, submit.
static bool build_and_submit(const KeyPair& kp, uint8_t type, const Addr20& to,
                             uint64_t amount, const bytes& payload) {
    std::string st;
    if (rpc_get("/status", st) != 200) return die("node not reachable at " + g_host + strf(":%u", g_port));
    uint32_t net_id = (uint32_t)extract_json_int(st, "net_id", 0);
    Addr20 me = addr_of(kp.pub);
    std::string bal;
    if (rpc_get("/balance?addr=" + hexs(me), bal) != 200) return die("balance query failed");
    uint64_t nonce = (uint64_t)extract_json_int(bal, "nonce", 0);

    Tx t;
    t.type = type;
    t.net_id = net_id;
    t.from = kp.pub;
    t.to = to;
    t.amount = amount;
    t.nonce = nonce;
    t.payload = payload;
    auto sig = kp_sign(kp, t.sign_hash());
    if (!sig) return die("signing failed");
    t.sig = *sig;

    std::string resp;
    int code = rpc_post("/submit", hexs(t.serialize()), resp);
    printf("%s\n", resp.c_str());
    if (code != 200) return false;
    printf("submitted. check with: clctl tx --id %s\n", hexs(t.txid()).c_str());
    return true;
}

static int cmd_verify(const Args& a) {
    std::string pf = a.get("proof", "proof.txt");
    FILE* f = nullptr;
    if (fopen_s(&f, pf.c_str(), "rb") || !f) { die("cannot open proof file " + pf); return 1; }
    std::string content;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) content.append(buf, n);
    fclose(f);

    H256 txid{}, blockhash{};
    uint64_t height = ~0ull;
    bytes header_raw;
    std::vector<MerkleStep> steps;
    bool ok_hdr = false, ok_txid = false, ok_bh = false;
    size_t pos = 0;
    while (pos < content.size()) {
        size_t e = content.find('\n', pos);
        if (e == std::string::npos) e = content.size();
        std::string line = content.substr(pos, e - pos);
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        pos = e + 1;
        if (line.rfind("txid ", 0) == 0) { auto v = unhex_n<32>(line.substr(5)); if (v) { txid = *v; ok_txid = true; } }
        else if (line.rfind("height ", 0) == 0) height = strtoull(line.c_str() + 7, nullptr, 10);
        else if (line.rfind("blockhash ", 0) == 0) { auto v = unhex_n<32>(line.substr(10)); if (v) { blockhash = *v; ok_bh = true; } }
        else if (line.rfind("header ", 0) == 0) { auto v = unhex(line.substr(7)); if (v && v->size() == HEADER_SIZE) { header_raw = *v; ok_hdr = true; } }
        else if (line.rfind("sibling ", 0) == 0 && line.size() > 10) {
            uint8_t left = line[8] == 'L' ? 1 : 0;
            auto v = unhex_n<32>(line.substr(10));
            if (v) steps.push_back({ *v, left });
        }
    }
    if (!ok_txid || !ok_bh || !ok_hdr || height == ~0ull) { die("malformed proof file"); return 1; }

    BlockHeader h;
    try { Reader r(header_raw); h = BlockHeader::parse(r); }
    catch (...) { die("bad header in proof"); return 1; }

    bool pass = true;
    H256 hh = sha256d(header_raw);
    if (hh != blockhash) { printf("FAIL: header does not hash to blockhash\n"); pass = false; }
    if (h.height != height) { printf("FAIL: header height mismatch\n"); pass = false; }
    H256 root = merkle_apply(txid, steps);
    if (root != h.merkle) { printf("FAIL: merkle path does not reach the header's merkle root\n"); pass = false; }
    if (height > 0 && !pow_ok(blockhash, h.bits)) { printf("FAIL: block hash does not meet its proof-of-work target\n"); pass = false; }
    if (pass) {
        printf("proof OK: tx %s...\n  is committed at height %llu by block %s...\n"
               "  (merkle path -> root OK, header hash OK, PoW OK at %u bits)\n",
               hexs(txid).substr(0, 16).c_str(), (unsigned long long)height,
               hexs(blockhash).substr(0, 16).c_str(), h.bits);
    }

    // Cross-check that independent nodes agree this block is on their best chain.
    std::string all = a.get("rpc-all", "");
    if (!all.empty()) {
        printf("cross-checking %s against nodes: %s\n", "block hash", all.c_str());
        size_t p2 = 0;
        int agree = 0, total = 0;
        while (p2 < all.size()) {
            size_t c = all.find(',', p2);
            if (c == std::string::npos) c = all.size();
            std::string spec = all.substr(p2, c - p2);
            p2 = c + 1;
            if (spec.empty()) continue;
            std::string host = "127.0.0.1";
            uint16_t port;
            size_t cl = spec.rfind(':');
            if (cl == std::string::npos) port = (uint16_t)atoi(spec.c_str());
            else { host = spec.substr(0, cl); port = (uint16_t)atoi(spec.c_str() + cl + 1); }
            total++;
            std::string body;
            if (http_req(host, port, "GET", strf("/block?height=%llu", (unsigned long long)height), "", body) != 200) {
                printf("  %s:%u  UNREACHABLE\n", host.c_str(), port);
                continue;
            }
            std::string bh = extract_json_str(body, "hash");
            if (bh == hexs(blockhash)) { printf("  %s:%u  CONSENSUS OK (same block at height %llu)\n", host.c_str(), port, (unsigned long long)height); agree++; }
            else { printf("  %s:%u  MISMATCH: has %s\n", host.c_str(), port, bh.substr(0, 16).c_str()); pass = false; }
        }
        printf("%d/%d reachable nodes agree\n", agree, total);
    }
    printf(pass ? "VERDICT: VALID\n" : "VERDICT: INVALID\n");
    return pass ? 0 : 1;
}

int main(int argc, char** argv) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    Args a;
    a.parse(argc, argv);
    set_rpc(a.get("rpc", ""));
    std::string cmd = a.pos.empty() ? "help" : a.pos[0];
    std::string out;

    if (cmd == "keygen") {
        std::string of = a.get("out", "wallet.key");
        auto kp = kp_generate();
        if (!kp) { die("key generation failed"); return 1; }
        if (!kp_save(*kp, of)) { die("could not write " + of); return 1; }
        printf("wrote %s (plaintext ECDSA P-256 key -- toy wallet, do not reuse elsewhere)\n", of.c_str());
        printf("address: %s\n", hexs(addr_of(kp->pub)).c_str());
        return 0;
    }
    if (cmd == "addr") {
        auto kp = need_key(a);
        if (!kp) return 1;
        printf("%s\n", hexs(addr_of(kp->pub)).c_str());
        return 0;
    }
    if (cmd == "status" || cmd == "mempool") {
        if (rpc_get("/" + cmd, out) < 0) { die("node not reachable"); return 1; }
        printf("%s\n", out.c_str());
        return 0;
    }
    if (cmd == "tail") {
        if (rpc_get("/tail?n=" + a.get("n", "10"), out) < 0) { die("node not reachable"); return 1; }
        printf("%s\n", out.c_str());
        return 0;
    }
    if (cmd == "balance") {
        std::string addr = a.get("addr", "");
        if (addr.empty()) {
            auto kp = need_key(a);
            if (!kp) return 1;
            addr = hexs(addr_of(kp->pub));
        }
        if (rpc_get("/balance?addr=" + addr, out) < 0) { die("node not reachable"); return 1; }
        printf("%s\n", out.c_str());
        return 0;
    }
    if (cmd == "block") {
        std::string q = a.has("height") ? "height=" + a.get("height") : "hash=" + a.get("hash");
        if (rpc_get("/block?" + q, out) < 0) { die("node not reachable"); return 1; }
        printf("%s\n", out.c_str());
        return 0;
    }
    if (cmd == "tx") {
        if (rpc_get("/tx?id=" + a.get("id"), out) < 0) { die("node not reachable"); return 1; }
        printf("%s\n", out.c_str());
        return 0;
    }
    if (cmd == "send") {
        auto kp = need_key(a);
        if (!kp) return 1;
        auto to = unhex_n<20>(a.get("to", ""));
        if (!to) { die("need --to <hex40 address>"); return 1; }
        uint64_t amount = strtoull(a.get("amount", "0").c_str(), nullptr, 10);
        if (!amount) { die("need --amount N"); return 1; }
        return build_and_submit(*kp, TX_TRANSFER, *to, amount, {}) ? 0 : 1;
    }
    if (cmd == "record") {
        auto kp = need_key(a);
        if (!kp) return 1;
        bytes payload;
        if (a.has("text")) {
            std::string t = a.get("text");
            payload.assign(t.begin(), t.end());
        } else if (a.has("file")) {
            FILE* f = nullptr;
            if (fopen_s(&f, a.get("file").c_str(), "rb") || !f) { die("cannot open " + a.get("file")); return 1; }
            bytes content;
            char buf[65536];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), f)) > 0) content.insert(content.end(), buf, buf + n);
            fclose(f);
            if (a.has("hash-only")) {
                H256 h = sha256(content);
                payload.assign(h.begin(), h.end());
                printf("recording sha256(%s) = %s\n", a.get("file").c_str(), hexs(h).c_str());
            } else if (content.size() <= MAX_PAYLOAD) payload = content;
            else { die(strf("file is %zu bytes (max %zu). use --hash-only to record its sha256 instead", content.size(), MAX_PAYLOAD)); return 1; }
        } else { die("need --text \"...\" or --file PATH"); return 1; }
        if (payload.empty()) { die("empty payload"); return 1; }
        return build_and_submit(*kp, TX_RECORD, Addr20{}, 0, payload) ? 0 : 1;
    }
    if (cmd == "prove") {
        std::string id = a.get("txid", "");
        if (id.empty()) { die("need --txid <hex64>"); return 1; }
        int code = rpc_get("/prove?txid=" + id, out);
        if (code != 200) { fprintf(stderr, "%s\n", out.c_str()); return 1; }
        if (a.has("out")) {
            FILE* f = nullptr;
            if (fopen_s(&f, a.get("out").c_str(), "wb") || !f) { die("cannot write " + a.get("out")); return 1; }
            fwrite(out.data(), 1, out.size(), f);
            fclose(f);
            printf("proof written to %s (verify with: clctl verify --proof %s --rpc-all 8501,8502,8503)\n",
                   a.get("out").c_str(), a.get("out").c_str());
        } else printf("%s", out.c_str());
        return 0;
    }
    if (cmd == "verify") return cmd_verify(a);

    printf("chainlite ctl -- commands:\n"
           "  keygen [--out wallet.key]\n"
           "  addr --key wallet.key\n"
           "  status | mempool | tail [--n 10]        (--rpc 8501 or host:port)\n"
           "  balance (--addr HEX40 | --key FILE)\n"
           "  send --key FILE --to HEX40 --amount N\n"
           "  record --key FILE (--text \"...\" | --file PATH [--hash-only])\n"
           "  block (--height N | --hash HEX64)\n"
           "  tx --id HEX64\n"
           "  prove --txid HEX64 [--out proof.txt]\n"
           "  verify --proof proof.txt [--rpc-all 8501,8502,8503]\n");
    return cmd == "help" ? 0 : 1;
}
