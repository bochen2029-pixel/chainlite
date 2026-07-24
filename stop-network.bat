@echo off
REM Stop all chainlite nodes (and any GPU miner) started by run-network.bat.
taskkill /IM clnode.exe /F >nul 2>nul
taskkill /IM clminer_gpu.exe /F >nul 2>nul
echo stopped chainlite nodes.
