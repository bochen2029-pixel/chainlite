@echo off
REM Launch a 3-node chainlite network, each node in its own console window.
REM Nodes gossip over loopback:  p2p 7501/7502/7503, rpc 8501/8502/8503.
REM Low difficulty (bits 18) so blocks mine in well under a second on CPU.
REM Heartbeat 30s => each node makes an empty block if idle, so the chain
REM keeps ticking even with no transactions (comment out --heartbeat to stop).
setlocal
set ROOT=%~dp0
set BIN=%ROOT%bin
if not exist "%BIN%\clnode.exe" (echo [!] build first: build.bat & exit /b 1)
set BITS=%1
if "%BITS%"=="" set BITS=18

start "chainlite node1" cmd /k ""%BIN%\clnode.exe" --datadir "%ROOT%data\node1" --p2p-port 7501 --rpc-port 8501 --peers 127.0.0.1:7502,127.0.0.1:7503 --bits %BITS% --heartbeat 30"
start "chainlite node2" cmd /k ""%BIN%\clnode.exe" --datadir "%ROOT%data\node2" --p2p-port 7502 --rpc-port 8502 --peers 127.0.0.1:7501,127.0.0.1:7503 --bits %BITS% --heartbeat 30"
start "chainlite node3" cmd /k ""%BIN%\clnode.exe" --datadir "%ROOT%data\node3" --p2p-port 7503 --rpc-port 8503 --peers 127.0.0.1:7501,127.0.0.1:7502 --bits %BITS% --heartbeat 30"

echo Launched 3 nodes. RPC on 8501, 8502, 8503.
echo   bin\clctl.exe status --rpc 8501
echo   bin\clctl.exe status --rpc 8502
echo   bin\clctl.exe status --rpc 8503
echo Stop them with: stop-network.bat  (or just close the windows)
endlocal
