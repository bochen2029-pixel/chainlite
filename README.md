# chainlite

A **real but minimal blockchain** you run entirely on your own machine — three
independent processes gossiping over TCP loopback, reaching Nakamoto (proof-of-work)
consensus, with a queryable SQLite ledger and exportable cryptographic proofs.

It is to a "real" blockchain what SQLite is to Postgres: not a toy, not a demo — a
genuinely usable *embedded ledger* with zero moving parts you don't control. The
networking is real TCP that merely happens to use `127.0.0.1`; change the peer list
to LAN IPs and the exact same binary is a real multi-machine chain. "Local" is
configuration, not architecture.

Built with basic primitives on Windows: MSVC + Winsock, SHA-256 written from the
FIPS 180-4 spec, ECDSA P-256 signatures from the OS (CNG/bcrypt), SQLite from the
copy Windows already ships (`winsqlite3.dll`), and an optional CUDA miner.

---

## What's real about it

- **Hash-linked blocks + Merkle roots.** Every block commits to its transactions
  via a Merkle root and to all history via the previous block's hash. Any
  retroactive edit to any block is detectable and breaks the chain from that point.
- **Independent validation.** Each node verifies every block and transaction
  itself — signatures, proof-of-work, Merkle roots, balances, nonces. Nodes never
  trust each other's claims.
- **Proof-of-work consensus with real fork choice.** Heaviest-cumulative-work wins.
  Nodes fork, detect it, download competing chains, and **reorg** — all exercised
  and logged.
- **Real P2P gossip.** A small message set (`HELLO/TIP/GET_BLOCKS/BLOCKS/TX/BLOCK`)
  over TCP. Separate OS processes, separate data directories — they can *only*
  communicate through the socket.
- **Digital signatures.** Every transaction is signed; tampering with a signed
  field changes its id and invalidates it.
- **Crash-safe, queryable storage.** Each node's chain is a SQLite database
  (`data/nodeN/chain.db`). Open it with any SQLite client and
  `SELECT * FROM blocks`.

Deliberately cut (no conceptual loss): peer discovery (peers are hardcoded), smart
contracts, fee markets, wire encryption, HD wallets. Byzantine fault tolerance
needs 3f+1 nodes for f faults; three nodes give you crash-fault tolerance (any one
can die) — bump the peer list to 4+ for f=1 BFT.

---

## The one-file app

**`chainlite.exe` is a complete blockchain in a single portable binary.** Copy that
one file anywhere — a USB stick, a fresh machine — double-click it, and it:

1. claims a free range of ports (a named mutex reserves the range before the
   probe, so two instances started at the same moment cannot pick the same one),
2. spawns **three real validating node processes**,
3. waits for them to come up and opens the notes UI in your browser,
4. keeps the chain in `chainlite-data\` next to the exe.

The web UI is compiled into the binary, so there is no `web\` folder to ship. Close
the window (or Ctrl+C) and every node it started dies with it — the children live in
a Windows job object with `KILL_ON_JOB_CLOSE`, so nothing is ever orphaned, even if
the launcher is killed outright. Restart it and your chain (and notes) are still there.

```bat
chainlite.exe                     :: launch everything + open the browser
chainlite.exe --no-browser        :: same, headless
chainlite.exe --datadir D:\chain  :: keep the chain somewhere specific
chainlite.exe --bits 20 --heartbeat 30
chainlite.exe --reset             :: wipe the stored chain (keys kept)
```

It prints a live status line as blocks arrive:

```
   chainlite  -  a private blockchain in one window
   ---------------------------------------------------------
   data        C:\portable\chainlite-data
   network     3 nodes  |  p2p 7501-7503  |  rpc 8501-8503
   consensus   proof-of-work, 18 leading zero bits  |  heartbeat 12s

   starting nodes... ok
   opening     http://127.0.0.1:8501/

   13:14:34  height 12     3/3 nodes up  4 notes on chain
```

`clnode.exe` (one node per process, driven by `run-network.bat`) is still there for
the classic workflow — both binaries share the exact same node code (`src/node_impl.h`).

## Build

Requires Visual Studio 2022 with the C++ toolset. CUDA is optional.

```bat
build.bat            :: builds chainlite.exe, clnode.exe, clctl.exe, cl_selftest.exe
build.bat gpu        :: also builds the CUDA miner (needs nvcc)
build-gpu.bat        :: builds ONLY the CUDA miner (safe while nodes are running)
```

`build.bat` runs `tools\embed.ps1` first, which turns `web\viewer.html` into
`src\viewer_html.h` so the UI can be compiled in. When a node finds a real
`web\viewer.html` next to it, it serves that instead — so editing the page during
development hot-reloads with a browser refresh, no rebuild needed.

`build.bat` also runs `tools\test_viewer.js` (skipped if `node` isn't installed),
which checks the viewer's HTML escaping against the real `web\viewer.html`.

Run the self-test first — it checks SHA-256 against the official NIST vectors,
signatures, Merkle proofs, serialization, chain validation, the mempool, a full
reorg, and the network/RPC layers: P2P framing and the `M_BLOCKS` byte budget,
the RPC's Host/CORS/CSRF rules, and the `/records` notes feed:

```bat
bin\cl_selftest.exe
```

## Run the network

```bat
run-network.bat            :: 3 nodes, each in its own window (difficulty bits=18)
run-network.bat 20         :: harder difficulty
stop-network.bat           :: stop them all
```

Nodes listen on p2p `7501/7502/7503` and RPC `8501/8502/8503`. With `--heartbeat`
set they mint an empty block on an interval so the chain keeps ticking even with
no traffic; otherwise the chain only grows when there are transactions.

## Web viewer (explorer + wallet)

Each node serves a self-contained HTML client at its RPC port — just open:

```
http://127.0.0.1:8501/
```

No build step, no separate server: the node reads `web/viewer.html` and serves it
(`--webroot` overrides the location). It talks to the node over the same HTTP RPC.

What it does:

- **Notes** *(the default tab)* — a write-and-read feed for the chain. Type a note,
  hit **Sign & post**, and it's signed in your browser, committed on-chain, and appears
  in the feed below **immediately** (as `pending`, then `block N · k conf` once mined).
  Every note ever written is listed newest-first, decoded and readable, with a `you`
  badge on yours, an "only mine" filter, and a **prove it** link that jumps to a
  client-side Merkle verification. Ctrl+Enter posts; the counter enforces the 1 KB
  payload cap. Notes are plain `RECORD` transactions, so `clctl record` and the web UI
  write to the same feed.
- **Explorer** — live status and a **convergence banner** across all three nodes,
  auto-refreshing recent blocks, click-through to block/transaction detail, address
  balances, mempool, and a universal search (height / txid / address).
- **Wallet** — generate a keypair (kept in this browser's localStorage) or import a
  chainlite key file (a `wallet.key`, or a node's `node.key` to spend its mined
  coin). **Signing happens locally in the browser** via the Web Crypto API (ECDSA
  P-256) — the private key never leaves the page. Send LITE, or notarize text / a
  file's hash.
- **Verify** — paste a proof and it is checked **entirely client-side** (recomputing
  the Merkle path, header hash, and proof-of-work), then cross-checked against every
  reachable node.

The browser signs with Web Crypto and the node verifies with Windows CNG — the
formats line up (raw `r‖s` signatures, `X‖Y` public keys, ECDSA over
double-SHA256), so a browser-generated wallet and a `clctl`/node key are
interchangeable. Because it's one static file, it can also be wrapped in
Tauri/Electron unchanged.

## Use it (clctl)

```bat
bin\clctl.exe status --rpc 8501
bin\clctl.exe keygen --out wallet.key
bin\clctl.exe addr   --key wallet.key

:: money: spend a node's mined coin into your wallet, then check any node
bin\clctl.exe send    --key data\node3\node.key --to <wallet-addr> --amount 100 --rpc 8501
bin\clctl.exe balance --addr <wallet-addr> --rpc 8503
bin\clctl.exe tx      --id <txid> --rpc 8502

:: notarization: commit a file's hash, then prove + verify it later
bin\clctl.exe record  --key wallet.key --file contract.pdf --hash-only --rpc 8502
bin\clctl.exe prove   --txid <txid> --out proof.txt --rpc 8501
bin\clctl.exe verify  --proof proof.txt --rpc-all 8501,8502,8503
```

A **proof** is a self-contained Merkle inclusion proof: it shows a given
transaction (e.g. `sha256(your file)`) is committed at a specific block, verifiable
against the block header's Merkle root and proof-of-work, and `--rpc-all` confirms
the independent nodes agree that block is on their chain. Proofs stay valid forever
as the chain grows.

## Two transaction types

- `TRANSFER(to, amount)` — move coin. Accounts model: balance + monotonic nonce
  per address; the nonce prevents replay/double-spend.
- `RECORD(payload)` — commit an arbitrary signed blob (≤ 1 KB), or a file's
  `sha256` via `--hash-only`. This is the notarization / tamper-evident-log
  primitive.

---

## The lab (things you can't do to a real chain)

You own all three nodes, so you're allowed to attack them:

- **Kill and heal.** Stop a node, delete its `chain.db`, restart it — it rebuilds
  the entire ledger from its peers and reconverges, keeping its `node.key` identity.
- **Corrupt the ledger.** Damage a block in one node's DB; on reload the node
  detects the broken hash-link, truncates to the last good height, and re-syncs the
  rest from consensus. The two honest nodes outvote the tampered one.
- **Forge a proof.** Flip any byte in a `proof.txt` and `verify` rejects it — the
  Merkle path no longer reaches the committed root.
- **51%-attack yourself with the GPU.** Point `clminer_gpu.exe` at a single node
  and it out-mines the CPU nodes, driving nearly every block. Raise `--bits` so a
  block takes real time and you can watch the hashrate and the takeover.

```bat
bin\clminer_gpu.exe --rpc 8501 [--addr <hex40>] [--device 0]
```

The GPU grinds double-SHA256 over nonce ranges (embarrassingly parallel). At low
`--bits` it will flood thousands of blocks a second; for meaningful per-block time
use a high-difficulty network (e.g. `run-network.bat 30`).

---

## Architecture (≈2,000 lines, `src/`)

| file | role |
|------|------|
| `common.h` | types, hex, little-endian serialization, args, logging |
| `sha256.h` | SHA-256 from FIPS 180-4; proof-of-work helpers |
| `crypto_cng.h` | ECDSA P-256 keygen/sign/verify via Windows CNG |
| `sqlite_shim.h` | dynamic binding to `winsqlite3.dll` |
| `core.h` | tx, block, Merkle tree/proofs, account state, chain + reorg, mempool |
| `net.h` | non-blocking TCP gossip, one dedup'd link per peer pair |
| `rpc.h` | tiny HTTP/1.1 server (127.0.0.1) for the node RPC |
| `http_client.h` | blocking HTTP client for clctl / the GPU miner |
| `node_impl.h` | the node: wires storage + net + miner + RPC together |
| `clnode.cpp` | one node per process (thin `main` over `node_impl.h`) |
| `chainlite_app.cpp` | the all-in-one launcher: spawns 3 nodes, opens the UI |
| `clctl.cpp` | wallet + query CLI |
| `clminer_gpu.cu` | CUDA proof-of-work miner |
| `selftest.cpp` | the test suite |
| `web/viewer.html` | the browser explorer + wallet (served by the node at `/`) |

**Consensus params** (`Params` in `core.h`): 32-byte hashes, 100-byte headers, PoW
= N leading zero bits, one writer per block via the mempool, heaviest-work fork
choice. Difficulty is fixed per network via `--bits` (no retargeting — a
deliberate simplification for a controlled local chain).

### Node RPC (JSON over HTTP, 127.0.0.1 only)

`GET /status /balance /block /tx /mempool /records /tail /prove /work` ·
`POST /submit /submitwork`. Any language that can do an HTTP GET can read the
ledger; `curl http://127.0.0.1:8501/status`.

**Binding to loopback is not by itself protection from the web.** Every page you
visit can issue requests to `127.0.0.1`, so the RPC enforces three rules:

- **`Host:` must be loopback.** Blocks DNS rebinding, where an attacker's domain
  re-resolves to `127.0.0.1` so their page counts as same-origin and skips CORS.
- **CORS is allow-listed, never `*`.** `Access-Control-Allow-Origin` is echoed
  only for this network's own node ports (so the viewer on `:8501` can still poll
  `:8502`/`:8503`). Any other site gets no CORS header and cannot read a response.
- **Writes need an `X-Chainlite` header.** CORS does *not* stop a cross-origin
  `POST` from being delivered — a `text/plain` body is a "simple request" that
  needs no preflight. Requiring a custom header does, because setting one forces
  a preflight, which is answered only for allow-listed origins.

Reading from a script is unaffected (`curl` sends no `Origin`). Posting from one
needs the header — `clctl` and the GPU miner send it automatically:

```bat
curl -H "X-Chainlite: 1" --data-binary "<hex tx>" http://127.0.0.1:8501/submit
```

The viewer is also served with a Content-Security-Policy that pins network access
to loopback, so a future markup bug can't ship your wallet key off the machine.

`GET /records?limit=N[&addr=<hex40>]` is the notes feed: every `RECORD` transaction
newest-first, with pending (mempool) ones listed ahead of confirmed. Payloads come back
as hex, so arbitrary note text needs no escaping —
`curl "http://127.0.0.1:8501/records?limit=5"`.

---

## Notes & honest limitations

- Keys are stored in plaintext (`node.key`, `wallet.key`) — this is a local toy
  wallet, not key management. Don't reuse these keys anywhere real. The browser
  wallet keeps an *extractable* key in `localStorage` for the same reason.
- No difficulty retargeting, no transaction fees, no mempool eviction policy beyond
  a size cap, no wire encryption (loopback).
- **Addresses have no checksum.** They are `sha256(pubkey)[:20]`, so a mistyped
  `--to` is a valid-looking address nobody holds the key for, and the coin is
  gone. Copy/paste, don't retype.
- **Block timestamps are only checked against future skew** (2 h), not for
  monotonicity. A miner can backdate a block, which scrambles the notes feed's
  ordering. The obvious fix — requiring `time >= prev.time` — is deliberately
  *not* applied: with no median-time-past rule, a single backwards clock step
  (NTP correction) would make a node mine blocks its peers reject and stall the
  chain. Doing it properly means Bitcoin-style median-time-past over the last 11
  blocks.
- **ECDSA signatures are malleable**, so txids are too: re-signing a pending tx
  with `s -> n-s` yields a different txid for the same transfer. The mempool's
  (sender, nonce) key stops it becoming a double-spend, but a `proof.txt` saved
  for the original txid is orphaned if the malleated twin gets mined instead.
  Enforcing low-`s` would reject any already-confirmed high-`s` transaction, so
  it needs a planned migration rather than a flag flip.
- **No coinbase maturity.** A miner can spend a reward immediately. If a reorg
  erases that reward, the spending tx stays in the mempool (its nonce is still
  unused) and can never be mined — it lingers until it is pushed out by the
  10,000-tx cap.
- Three nodes = crash-fault tolerant, not Byzantine. All three share one admin
  (you), so "decentralization" here is a lab property, not a trust model.
- What it *is* genuinely good for locally: a tamper-evident, self-healing,
  queryable audit log with portable inclusion proofs — a tiny Certificate-
  Transparency-style log you fully own.
