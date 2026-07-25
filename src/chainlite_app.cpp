// chainlite.exe — the all-in-one portable app.
//
// Double-click it and it bootstraps an entire private blockchain: it picks free
// ports, spawns three real validating node processes (children of itself), waits
// for them to come up, and opens the notes/explorer UI in your browser. The web UI
// is compiled into this binary, so a single .exe with no folder alongside it is a
// complete, working chain. Close the window (or Ctrl+C) and every node it started
// dies with it — the children live in a job object with KILL_ON_JOB_CLOSE, so
// nothing is ever orphaned, even if this process is killed outright.
//
//   chainlite.exe                       launch everything + open the browser
//   chainlite.exe --no-browser          same, without opening a browser
//   chainlite.exe --datadir D:\chain    keep the chain somewhere specific
//   chainlite.exe --bits 20 --heartbeat 30
//   chainlite.exe --reset               wipe the stored chain first
//   chainlite.exe --node ...            (internal) be a single node
#include "node_impl.h"
#include "http_client.h"
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")

static std::atomic<bool> g_sup_running{ true };
static BOOL WINAPI sup_ctrl(DWORD) { g_sup_running = false; return TRUE; }

static std::string exe_path() {
    char buf[MAX_PATH] = { 0 };
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return buf;
}
static std::string dir_of(const std::string& p) {
    size_t s = p.find_last_of("\\/");
    return s == std::string::npos ? "." : p.substr(0, s);
}

// A port is "free" if we can bind it right now (no SO_REUSEADDR, so a live
// listener is correctly detected as taken).
static bool port_free(uint16_t p) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(p);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    int rc = bind(s, (sockaddr*)&a, sizeof(a));
    closesocket(s);
    return rc == 0;
}

struct Child {
    PROCESS_INFORMATION pi{};
    HANDLE log = INVALID_HANDLE_VALUE;
    uint16_t rpc = 0;
};

static bool spawn_node(const std::string& exe, std::string cmdline,
                       const std::string& logpath, HANDLE job, Child& out) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE h = CreateFileA(logpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    if (h != INVALID_HANDLE_VALUE) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = h;
        si.hStdError = h;
    }
    PROCESS_INFORMATION pi{};
    // CREATE_SUSPENDED so the child is in the job before it can run (and before it
    // could spawn anything of its own that would escape the job).
    BOOL ok = CreateProcessA(exe.c_str(), cmdline.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
    if (!ok) {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        return false;
    }
    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    out.pi = pi;
    out.log = h;
    return true;
}

static bool rpc_up(uint16_t port, long long* height = nullptr) {
    std::string body;
    if (http_req("127.0.0.1", port, "GET", "/status", "", body) != 200) return false;
    if (height) *height = extract_json_int(body, "height", -1);
    return true;
}
static int count_notes(uint16_t port) {
    std::string body;
    if (http_req("127.0.0.1", port, "GET", "/records?limit=500", "", body) != 200) return -1;
    int n = 0;
    for (size_t p = body.find("\"txid\""); p != std::string::npos; p = body.find("\"txid\"", p + 1)) n++;
    return n;
}

static void banner(const std::string& datadir, int nodes, uint16_t p2p0, uint16_t rpc0,
                   const std::string& bits, const std::string& hb) {
    printf("\n");
    printf("   chainlite  -  a private blockchain in one window\n");
    printf("   ---------------------------------------------------------\n");
    printf("   data        %s\n", datadir.c_str());
    printf("   network     %d nodes  |  p2p %u-%u  |  rpc %u-%u\n",
           nodes, p2p0, (unsigned)(p2p0 + nodes - 1), rpc0, (unsigned)(rpc0 + nodes - 1));
    printf("   consensus   proof-of-work, %s leading zero bits  |  heartbeat %ss\n",
           bits.c_str(), hb.c_str());
    printf("\n");
    fflush(stdout);
}

static int supervise(const Args& args) {
    const int NODES = 3;
    std::string exe = exe_path();
    std::string root = args.get("datadir", dir_of(exe) + "\\chainlite-data");
    std::string bits = args.get("bits", "18");
    std::string hb   = args.get("heartbeat", "12");

    std::error_code ec;
    std::filesystem::create_directories(root, ec);

    if (args.has("reset")) {
        for (int i = 1; i <= NODES; i++) {
            std::string d = strf("%s\\node%d", root.c_str(), i);
            for (const char* f : { "chain.db", "chain.db-wal", "chain.db-shm" })
                std::filesystem::remove(d + "\\" + f, ec);
        }
        printf("   [reset] stored chain wiped (keys kept)\n");
    }

    // Find a run of free ports so a second instance (or an existing run-network.bat
    // network) doesn't collide; each attempt shifts both ranges by 10.
    uint16_t p2p0 = 0, rpc0 = 0;
    for (int attempt = 0; attempt < 20 && !p2p0; attempt++) {
        uint16_t p = (uint16_t)(7501 + attempt * 10), r = (uint16_t)(8501 + attempt * 10);
        bool ok = true;
        for (int i = 0; i < NODES; i++)
            if (!port_free((uint16_t)(p + i)) || !port_free((uint16_t)(r + i))) { ok = false; break; }
        if (ok) { p2p0 = p; rpc0 = r; }
    }
    if (!p2p0) {
        printf("   [!] could not find %d free port pairs starting at 7501/8501.\n", NODES);
        printf("       Something else is using them; stop it and try again.\n");
        return 1;
    }

    banner(root, NODES, p2p0, rpc0, bits, hb);

    std::string rpc_list;
    for (int i = 0; i < NODES; i++) rpc_list += (i ? "," : "") + std::to_string(rpc0 + i);

    HANDLE job = CreateJobObjectA(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    printf("   starting nodes");
    fflush(stdout);
    std::vector<Child> kids;
    for (int i = 0; i < NODES; i++) {
        std::string datadir = strf("%s\\node%d", root.c_str(), i + 1);
        std::filesystem::create_directories(datadir, ec);
        std::string peers;
        for (int j = 0; j < NODES; j++)
            if (j != i) peers += (peers.empty() ? "" : ",") + strf("127.0.0.1:%u", (unsigned)(p2p0 + j));
        std::string cmd = strf("\"%s\" --node --datadir \"%s\" --p2p-port %u --rpc-port %u "
                               "--peers %s --rpc-peers %s --bits %s --heartbeat %s",
                               exe.c_str(), datadir.c_str(), (unsigned)(p2p0 + i), (unsigned)(rpc0 + i),
                               peers.c_str(), rpc_list.c_str(), bits.c_str(), hb.c_str());
        Child c;
        c.rpc = (uint16_t)(rpc0 + i);
        if (!spawn_node(exe, cmd, datadir + "\\node.log", job, c)) {
            printf("\n   [!] failed to start node %d (error %lu)\n", i + 1, GetLastError());
            if (job) CloseHandle(job);
            return 1;
        }
        kids.push_back(c);
        printf(".");
        fflush(stdout);
    }

    // Wait for every node's RPC to answer before pointing a browser at it.
    bool all_up = false;
    for (int t = 0; t < 100 && !all_up; t++) {
        all_up = true;
        for (auto& k : kids) if (!rpc_up(k.rpc)) { all_up = false; break; }
        if (!all_up) std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    if (!all_up) {
        printf(" failed\n   [!] nodes did not come up; see %s\\node1\\node.log\n", root.c_str());
        if (job) CloseHandle(job);
        return 1;
    }
    printf(" ok\n");

    std::string url = strf("http://127.0.0.1:%u/", (unsigned)rpc0);
    if (!args.has("no-browser")) {
        printf("   opening     %s\n", url.c_str());
        ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    } else {
        printf("   viewer      %s\n", url.c_str());
    }
    printf("\n   Write notes in the browser; they are signed there and stored on this chain.\n");
    printf("   Keep this window open. Ctrl+C (or closing it) stops every node.\n\n");
    fflush(stdout);

    SetConsoleCtrlHandler(sup_ctrl, TRUE);
    long long last_h = -1;
    int last_n = -1;
    while (g_sup_running) {
        // Report only when something actually changed, so the window stays readable.
        long long h = -1;
        int live = 0;
        for (auto& k : kids) {
            long long kh = -1;
            if (rpc_up(k.rpc, &kh)) { live++; if (kh > h) h = kh; }
        }
        int n = count_notes(kids[0].rpc);
        if (h != last_h || n != last_n) {
            time_t tt = time(nullptr);
            struct tm tmv;
            localtime_s(&tmv, &tt);
            printf("   %02d:%02d:%02d  height %-6lld  %d/%d nodes up  %d note%s on chain\n",
                   tmv.tm_hour, tmv.tm_min, tmv.tm_sec, h, live, (int)kids.size(),
                   n < 0 ? 0 : n, (n == 1 ? "" : "s"));
            fflush(stdout);
            last_h = h;
            last_n = n;
        }
        for (int i = 0; i < 20 && g_sup_running; i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    printf("\n   stopping nodes...\n");
    if (job) CloseHandle(job);      // KILL_ON_JOB_CLOSE takes every child down with us
    for (auto& k : kids) {
        WaitForSingleObject(k.pi.hProcess, 3000);
        TerminateProcess(k.pi.hProcess, 0);
        CloseHandle(k.pi.hThread);
        CloseHandle(k.pi.hProcess);
        if (k.log != INVALID_HANDLE_VALUE) CloseHandle(k.log);
    }
    printf("   stopped. Your chain is saved in %s\n\n", root.c_str());
    return 0;
}

int main(int argc, char** argv) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    Args args;
    args.parse(argc, argv);
    SetConsoleOutputCP(CP_UTF8);
    if (args.has("node")) return node_run(args);   // child: be a single validating node
    return supervise(args);                        // default: bootstrap the whole thing
}
