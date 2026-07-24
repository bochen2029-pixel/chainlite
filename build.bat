@echo off
REM chainlite build — MSVC for the node/CLI/selftest, NVCC for the optional GPU miner.
REM Usage:  build.bat          (build node + ctl + selftest)
REM         build.bat gpu      (also build the CUDA miner)
setlocal
set ROOT=%~dp0
set SRC=%ROOT%src
set BIN=%ROOT%bin
if not exist "%BIN%" mkdir "%BIN%"

REM --- locate and enter the MSVC x64 developer environment ---
where cl.exe >nul 2>nul && goto have_cl
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (echo [!] vswhere not found & exit /b 1)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (echo [!] Visual Studio with C++ tools not found & exit /b 1)
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
:have_cl

echo === building clnode.exe ===
cl /nologo /std:c++17 /O2 /EHsc /DNDEBUG /I"%SRC%" "%SRC%\clnode.cpp" /Fe"%BIN%\clnode.exe" /Fo"%BIN%\\" /link ws2_32.lib bcrypt.lib
if %errorlevel% neq 0 (echo [!] clnode build failed & exit /b 1)

echo === building clctl.exe ===
cl /nologo /std:c++17 /O2 /EHsc /DNDEBUG /I"%SRC%" "%SRC%\clctl.cpp" /Fe"%BIN%\clctl.exe" /Fo"%BIN%\\" /link ws2_32.lib bcrypt.lib
if %errorlevel% neq 0 (echo [!] clctl build failed & exit /b 1)

echo === building cl_selftest.exe ===
cl /nologo /std:c++17 /O2 /EHsc /DNDEBUG /I"%SRC%" "%SRC%\selftest.cpp" /Fe"%BIN%\cl_selftest.exe" /Fo"%BIN%\\" /link ws2_32.lib bcrypt.lib
if %errorlevel% neq 0 (echo [!] selftest build failed & exit /b 1)

if "%~1"=="gpu" (
    echo === building clminer_gpu.exe ===
    where nvcc >nul 2>nul
    if %errorlevel% neq 0 (echo [!] nvcc not found on PATH, skipping GPU miner & goto done)
    nvcc -O3 -std=c++17 -I"%SRC%" "%SRC%\clminer_gpu.cu" -o "%BIN%\clminer_gpu.exe" -lws2_32
    if %errorlevel% neq 0 (echo [!] GPU miner build failed & exit /b 1)
)
:done
echo.
echo === build complete -> %BIN% ===
dir /b "%BIN%\*.exe"
endlocal
