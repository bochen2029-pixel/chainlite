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

REM /utf-8 is required, not cosmetic: viewer_html.h is UTF-8 and without it MSVC
REM transcodes string literals to the system code page (1252), silently replacing
REM every non-Latin-1 character in the embedded web UI (warning C4566). The copy
REM compiled into chainlite.exe would then differ from web\viewer.html.

REM --- embed the web viewer into a header so binaries are self-contained ---
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%tools\embed.ps1"
if %errorlevel% neq 0 (echo [!] embedding viewer.html failed & exit /b 1)

REM --- viewer escaping regressions (needs node; skipped when it isn't installed) ---
where node >nul 2>nul
if %errorlevel% equ 0 (
    node "%ROOT%tools\test_viewer.js"
    if errorlevel 1 (echo [!] viewer tests failed & exit /b 1)
) else (
    echo [i] node not found - skipping viewer JS tests
)

echo === building chainlite.exe (all-in-one portable app) ===
cl /nologo /std:c++17 /O2 /EHsc /DNDEBUG /utf-8 /I"%SRC%" "%SRC%\chainlite_app.cpp" /Fe"%BIN%\chainlite.exe" /Fo"%BIN%\\" /link ws2_32.lib bcrypt.lib shell32.lib
if %errorlevel% neq 0 (echo [!] chainlite build failed & exit /b 1)

echo === building clnode.exe ===
cl /nologo /std:c++17 /O2 /EHsc /DNDEBUG /utf-8 /I"%SRC%" "%SRC%\clnode.cpp" /Fe"%BIN%\clnode.exe" /Fo"%BIN%\\" /link ws2_32.lib bcrypt.lib
if %errorlevel% neq 0 (echo [!] clnode build failed & exit /b 1)

echo === building clctl.exe ===
cl /nologo /std:c++17 /O2 /EHsc /DNDEBUG /utf-8 /I"%SRC%" "%SRC%\clctl.cpp" /Fe"%BIN%\clctl.exe" /Fo"%BIN%\\" /link ws2_32.lib bcrypt.lib
if %errorlevel% neq 0 (echo [!] clctl build failed & exit /b 1)

echo === building cl_selftest.exe ===
cl /nologo /std:c++17 /O2 /EHsc /DNDEBUG /utf-8 /I"%SRC%" "%SRC%\selftest.cpp" /Fe"%BIN%\cl_selftest.exe" /Fo"%BIN%\\" /link ws2_32.lib bcrypt.lib
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
REM ^> is escaped: a bare > here is parsed as a redirect, which tried to write to
REM the bin directory and ended a successful build with "Access is denied."
echo === build complete -^> %BIN% ===
dir /b "%BIN%\*.exe"
endlocal
