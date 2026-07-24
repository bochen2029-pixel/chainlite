// chainlite — SQLite via the copy Windows ships in System32 (winsqlite3.dll),
// loaded dynamically. Each node's chain lives in its own .db file, so the
// ledger is crash-safe and queryable with any SQLite client.
#pragma once
#include "common.h"

#define CL_SQLITE_OK    0
#define CL_SQLITE_ROW   100
#define CL_SQLITE_DONE  101
#define CL_SQLITE_OPEN_READWRITE 0x02
#define CL_SQLITE_OPEN_CREATE    0x04

namespace sq {

typedef int   (__cdecl* fn_open_v2)(const char*, void**, int, const char*);
typedef int   (__cdecl* fn_close)(void*);
typedef int   (__cdecl* fn_exec)(void*, const char*, void*, void*, char**);
typedef int   (__cdecl* fn_prepare_v2)(void*, const char*, int, void**, const char**);
typedef int   (__cdecl* fn_step)(void*);
typedef int   (__cdecl* fn_finalize)(void*);
typedef int   (__cdecl* fn_bind_int64)(void*, int, long long);
typedef int   (__cdecl* fn_bind_text)(void*, int, const char*, int, void*);
typedef int   (__cdecl* fn_bind_blob)(void*, int, const void*, int, void*);
typedef long long (__cdecl* fn_column_int64)(void*, int);
typedef const unsigned char* (__cdecl* fn_column_text)(void*, int);
typedef const void* (__cdecl* fn_column_blob)(void*, int);
typedef int   (__cdecl* fn_column_bytes)(void*, int);
typedef const char* (__cdecl* fn_errmsg)(void*);
typedef int   (__cdecl* fn_busy_timeout)(void*, int);

struct Api {
    HMODULE mod = nullptr;
    fn_open_v2 open_v2{}; fn_close close{}; fn_exec exec{}; fn_prepare_v2 prepare_v2{};
    fn_step step{}; fn_finalize finalize{}; fn_bind_int64 bind_int64{}; fn_bind_text bind_text{};
    fn_bind_blob bind_blob{}; fn_column_int64 column_int64{}; fn_column_text column_text{};
    fn_column_blob column_blob{}; fn_column_bytes column_bytes{}; fn_errmsg errmsg{};
    fn_busy_timeout busy_timeout{};
    bool ok = false;
};
inline Api& api() { static Api a; return a; }

inline bool load() {
    static std::once_flag once;
    std::call_once(once, [] {
        Api& a = api();
        a.mod = LoadLibraryW(L"winsqlite3.dll");
        if (!a.mod) return;
        auto gp = [&](const char* n) { return GetProcAddress(a.mod, n); };
        a.open_v2      = (fn_open_v2)gp("sqlite3_open_v2");
        a.close        = (fn_close)gp("sqlite3_close");
        a.exec         = (fn_exec)gp("sqlite3_exec");
        a.prepare_v2   = (fn_prepare_v2)gp("sqlite3_prepare_v2");
        a.step         = (fn_step)gp("sqlite3_step");
        a.finalize     = (fn_finalize)gp("sqlite3_finalize");
        a.bind_int64   = (fn_bind_int64)gp("sqlite3_bind_int64");
        a.bind_text    = (fn_bind_text)gp("sqlite3_bind_text");
        a.bind_blob    = (fn_bind_blob)gp("sqlite3_bind_blob");
        a.column_int64 = (fn_column_int64)gp("sqlite3_column_int64");
        a.column_text  = (fn_column_text)gp("sqlite3_column_text");
        a.column_blob  = (fn_column_blob)gp("sqlite3_column_blob");
        a.column_bytes = (fn_column_bytes)gp("sqlite3_column_bytes");
        a.errmsg       = (fn_errmsg)gp("sqlite3_errmsg");
        a.busy_timeout = (fn_busy_timeout)gp("sqlite3_busy_timeout");
        a.ok = a.open_v2 && a.close && a.exec && a.prepare_v2 && a.step && a.finalize &&
               a.bind_int64 && a.bind_text && a.bind_blob && a.column_int64 &&
               a.column_text && a.column_blob && a.column_bytes && a.errmsg;
    });
    return api().ok;
}

#define CL_SQLITE_TRANSIENT ((void*)-1)

struct Db {
    void* h = nullptr;
    bool open(const std::string& path) {
        if (!load()) return false;
        if (api().open_v2(path.c_str(), &h, CL_SQLITE_OPEN_READWRITE | CL_SQLITE_OPEN_CREATE, nullptr) != CL_SQLITE_OK)
            return false;
        if (api().busy_timeout) api().busy_timeout(h, 3000);
        return true;
    }
    bool exec(const std::string& sql) {
        char* err = nullptr;
        int rc = api().exec(h, sql.c_str(), nullptr, nullptr, &err);
        return rc == CL_SQLITE_OK;
    }
    std::string errmsg() { return h ? (const char*)api().errmsg(h) : "no db"; }
    void close() { if (h) { api().close(h); h = nullptr; } }
    ~Db() { close(); }

    struct St {
        void* s = nullptr;
        St(Db& db, const std::string& sql) { api().prepare_v2(db.h, sql.c_str(), -1, &s, nullptr); }
        ~St() { if (s) api().finalize(s); }
        bool ok() const { return s != nullptr; }
        void bind_i64(int i, long long v)         { api().bind_int64(s, i, v); }
        void bind_text(int i, const std::string& v) { api().bind_text(s, i, v.c_str(), (int)v.size(), CL_SQLITE_TRANSIENT); }
        void bind_blob(int i, const bytes& v)     { api().bind_blob(s, i, v.data(), (int)v.size(), CL_SQLITE_TRANSIENT); }
        int  step()                                { return api().step(s); }
        long long col_i64(int i)                   { return api().column_int64(s, i); }
        std::string col_text(int i)                { const unsigned char* t = api().column_text(s, i); return t ? (const char*)t : ""; }
        bytes col_blob(int i) {
            const void* p = api().column_blob(s, i);
            int n = api().column_bytes(s, i);
            return (p && n > 0) ? bytes((const uint8_t*)p, (const uint8_t*)p + n) : bytes{};
        }
    };
};

} // namespace sq
