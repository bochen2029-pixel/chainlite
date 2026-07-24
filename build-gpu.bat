@echo off
REM Build ONLY the CUDA miner (clminer_gpu.exe) without touching the node binaries,
REM so it can be built while a node network is running. Needs nvcc + MSVC host compiler.
setlocal
set ROOT=%~dp0
set SRC=%ROOT%src
set BIN=%ROOT%bin
if not exist "%BIN%" mkdir "%BIN%"

where cl.exe >nul 2>nul && goto have_cl
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (echo [!] vswhere not found & exit /b 1)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (echo [!] Visual Studio with C++ tools not found & exit /b 1)
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
:have_cl

where nvcc >nul 2>nul
if %errorlevel% neq 0 (echo [!] nvcc not found on PATH & exit /b 1)
echo === building clminer_gpu.exe ===
nvcc -O3 -std=c++17 -I"%SRC%" "%SRC%\clminer_gpu.cu" -o "%BIN%\clminer_gpu.exe" -lws2_32
if %errorlevel% neq 0 (echo [!] GPU miner build failed & exit /b 1)
echo === done -> %BIN%\clminer_gpu.exe ===
endlocal
