// clnode — one chainlite node per process (the classic workflow: run three of
// these, e.g. via run-network.bat). All the actual node logic lives in
// node_impl.h, which chainlite.exe reuses verbatim.
//
//   clnode --datadir data\node1 --p2p-port 7501 --rpc-port 8501
//          --peers 127.0.0.1:7502,127.0.0.1:7503 --mine on [--bits 20]
//          [--heartbeat 60] [--netid N] [--webroot DIR]
#include "node_impl.h"

int main(int argc, char** argv) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    Args args;
    args.parse(argc, argv);
    return node_run(args);
}
