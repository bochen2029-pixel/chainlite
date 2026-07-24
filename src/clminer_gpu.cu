// clminer_gpu — CUDA proof-of-work miner for chainlite. Pulls a work header
// from a node's RPC, grinds double-SHA256 over nonce ranges on the GPU until a
// hash meets the difficulty target, then submits the solved header back.
//
//   clminer_gpu --rpc 8501 [--addr <hex40>] [--device 0]
//
// This is the "point the GPU at one node and watch it out-mine the others"
// tool: run it against a single node with a higher --bits network and you can
// stage a 51%-style takeover of your own local chain.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cuda_runtime.h>

// host-side helpers reused from the project
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#include "common.h"
#include "http_client.h"

// ---------------- device SHA-256 ----------------
__constant__ uint32_t dK[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
__device__ __forceinline__ uint32_t rr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

__device__ void sha256_block(const uint8_t* blk, uint32_t st[8]) {
    uint32_t w[64];
#pragma unroll
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|((uint32_t)blk[i*4+2]<<8)|blk[i*4+3];
#pragma unroll
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rr(w[i-15],7) ^ rr(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = rr(w[i-2],17) ^ rr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
#pragma unroll
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rr(e,6)^rr(e,11)^rr(e,25);
        uint32_t ch = (e&f)^(~e&g);
        uint32_t t1 = h + S1 + ch + dK[i] + w[i];
        uint32_t S0 = rr(a,2)^rr(a,13)^rr(a,22);
        uint32_t mj = (a&b)^(a&c)^(b&c);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

// The 100-byte header hashed twice. Message = 100 bytes => two blocks with
// padding for the first hash; the 32-byte digest => one block for the second.
__device__ void sha256d_100(const uint8_t* msg, uint8_t out[32]) {
    uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[64];
#pragma unroll
    for (int i = 0; i < 64; i++) blk[i] = msg[i];
    sha256_block(blk, st);
    // second block: remaining 36 bytes + 0x80 + zero pad + 64-bit length (800 bits)
    for (int i = 0; i < 36; i++) blk[i] = msg[64 + i];
    blk[36] = 0x80;
    for (int i = 37; i < 56; i++) blk[i] = 0;
    uint64_t bits = 100 * 8;
    for (int i = 0; i < 8; i++) blk[56 + i] = (uint8_t)(bits >> (56 - 8*i));
    sha256_block(blk, st);
    uint8_t dig[32];
    for (int i = 0; i < 8; i++) { dig[i*4]=st[i]>>24; dig[i*4+1]=st[i]>>16; dig[i*4+2]=st[i]>>8; dig[i*4+3]=st[i]; }
    // second hash of the 32-byte digest
    uint32_t st2[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk2[64];
    for (int i = 0; i < 32; i++) blk2[i] = dig[i];
    blk2[32] = 0x80;
    for (int i = 33; i < 56; i++) blk2[i] = 0;
    uint64_t bits2 = 32 * 8;
    for (int i = 0; i < 8; i++) blk2[56 + i] = (uint8_t)(bits2 >> (56 - 8*i));
    sha256_block(blk2, st2);
    for (int i = 0; i < 8; i++) { out[i*4]=st2[i]>>24; out[i*4+1]=st2[i]>>16; out[i*4+2]=st2[i]>>8; out[i*4+3]=st2[i]; }
}

__device__ __forceinline__ int lead_zeros(const uint8_t* h) {
    int n = 0;
    for (int i = 0; i < 32; i++) {
        if (h[i] == 0) { n += 8; continue; }
        uint8_t b = h[i];
        while (!(b & 0x80)) { n++; b <<= 1; }
        return n;
    }
    return 256;
}

// Each thread tries nonces base + tid + k*stride. Header nonce is the LE u64 at
// offset 92. First thread to meet `bits` writes its nonce to *found.
__global__ void mine_kernel(const uint8_t* __restrict__ hdr, uint32_t bits,
                            uint64_t base, uint32_t per_thread,
                            unsigned long long* found, int* flag) {
    uint64_t tid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
    uint8_t local[100];
#pragma unroll
    for (int i = 0; i < 100; i++) local[i] = hdr[i];
    for (uint32_t k = 0; k < per_thread; k++) {
        if (*flag) return;
        uint64_t nonce = base + tid + (uint64_t)k * stride;
        for (int b = 0; b < 8; b++) local[92 + b] = (uint8_t)(nonce >> (8*b));
        uint8_t out[32];
        sha256d_100(local, out);
        if (lead_zeros(out) >= (int)bits) {
            if (atomicExch(flag, 1) == 0) *found = nonce;
            return;
        }
    }
}

static bool json_get_str(const std::string& b, const char* k, std::string& out) {
    out = extract_json_str(b, k);
    return !out.empty();
}

int main(int argc, char** argv) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    Args args; args.parse(argc, argv);
    std::string rpc = args.get("rpc", "8501");
    std::string host = "127.0.0.1"; uint16_t port;
    { size_t c = rpc.rfind(':'); if (c==std::string::npos) port=(uint16_t)atoi(rpc.c_str());
      else { host=rpc.substr(0,c); port=(uint16_t)atoi(rpc.c_str()+c+1); } }
    std::string addr = args.get("addr", "");
    int device = atoi(args.get("device", "0").c_str());

    cudaSetDevice(device);
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device) != cudaSuccess) {
        printf("no CUDA device %d\n", device); return 1;
    }
    printf("chainlite GPU miner on %s (%d SMs), node http://%s:%u\n", prop.name, prop.multiProcessorCount, host.c_str(), port);

    const int threads = 256;
    const int blocks = prop.multiProcessorCount * 32;
    const uint32_t per_thread = 256;
    uint8_t* d_hdr; unsigned long long* d_found; int* d_flag;
    cudaMalloc(&d_hdr, 100);
    cudaMalloc(&d_found, sizeof(unsigned long long));
    cudaMalloc(&d_flag, sizeof(int));

    std::string last_tip;
    uint64_t total_hashes = 0;
    auto t_report = std::chrono::steady_clock::now();

    while (true) {
        std::string body;
        std::string path = "/work" + (addr.empty() ? "" : ("?addr=" + addr));
        if (http_req(host, port, "GET", path, "", body) != 200) {
            printf("waiting for node...\n");
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            continue;
        }
        std::string hdr_hex, tip; long long bits = extract_json_int(body, "bits", 0);
        long long height = extract_json_int(body, "height", 0);
        long long ntx = extract_json_int(body, "ntx", 0);
        json_get_str(body, "header", hdr_hex);
        json_get_str(body, "tip", tip);
        auto hdr = unhex(hdr_hex);
        if (!hdr || hdr->size() != 100 || bits <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }
        // Nothing to do if only the coinbase would be in the block and tip is unchanged?
        // We still mine (heartbeat-style) so the GPU race is visible; comment out to idle.

        cudaMemcpy(d_hdr, hdr->data(), 100, cudaMemcpyHostToDevice);
        int zero = 0; cudaMemcpy(d_flag, &zero, sizeof(int), cudaMemcpyHostToDevice);
        unsigned long long fnonce = 0; cudaMemcpy(d_found, &fnonce, sizeof(fnonce), cudaMemcpyHostToDevice);

        uint64_t base = ((uint64_t)rand() << 32) ^ (uint64_t)rand() ^ (uint64_t)GetTickCount64();
        bool solved = false;
        for (int round = 0; round < 64 && !solved; round++) {
            mine_kernel<<<blocks, threads>>>(d_hdr, (uint32_t)bits, base, per_thread, d_found, d_flag);
            cudaDeviceSynchronize();
            total_hashes += (uint64_t)blocks * threads * per_thread;
            base += (uint64_t)blocks * threads * per_thread;
            int flag = 0; cudaMemcpy(&flag, d_flag, sizeof(int), cudaMemcpyDeviceToHost);
            if (flag) {
                cudaMemcpy(&fnonce, d_found, sizeof(fnonce), cudaMemcpyDeviceToHost);
                solved = true;
            }
            auto now = std::chrono::steady_clock::now();
            double el = std::chrono::duration<double>(now - t_report).count();
            if (el > 2.0) {
                printf("  height %lld bits %lld ntx %lld  %.1f Mhash/s\n",
                       height, bits, ntx, total_hashes / el / 1e6);
                total_hashes = 0; t_report = now;
            }
            // bail out early if the tip moved under us (another node won)
            std::string chk;
            if (round % 8 == 7 && http_req(host, port, "GET", "/status", "", chk) == 200) {
                std::string cur = extract_json_str(chk, "tip");
                if (!cur.empty() && !tip.empty() && cur != tip) break;
            }
        }
        if (!solved) continue;

        // patch nonce into the header and submit
        for (int b = 0; b < 8; b++) (*hdr)[92 + b] = (uint8_t)(fnonce >> (8*b));
        std::string resp;
        int code = http_req(host, port, "POST", "/submitwork", hexs(*hdr), resp);
        printf("SOLVED height %lld nonce %llu -> node says: %s%s\n",
               height, (unsigned long long)fnonce, resp.c_str(), code==200?"":" (rejected)");
    }
    return 0;
}
