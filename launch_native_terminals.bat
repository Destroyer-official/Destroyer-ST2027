@echo off
title ST2027 Native Rust Dual Tactical Terminal Launcher
cd /d "%~dp0"
echo ===============================================================================
echo   SPAWNING 2 STANDALONE NATIVE RUST TACTICAL TERMINALS (ST2027 DEFCON-1)
echo   Post-Quantum ML-KEM-1024 + 50ms Constant-Rate Traffic Pacing (Song et al.)
echo   Zero Python Runtime ^| Zero Web Server ^| NIST SP 800-88 Deterministic Zeroize
echo ===============================================================================
echo.
echo Terminal 1: NORAD Base Alpha    (Responder on 127.0.0.1:9060)
echo Terminal 2: Pentagon Base Bravo (Initiator on 127.0.0.1:9061)
echo.

set BIN=rust_data_plane\target\release\secure-transmit.exe
if not exist "%BIN%" set BIN=rust_data_plane\target\debug\secure-transmit.exe
if not exist "%BIN%" (
    echo [BUILD] Native binary not found. Compiling release binary...
    cargo build --release --manifest-path rust_data_plane\Cargo.toml --bin secure-transmit
    set BIN=rust_data_plane\target\release\secure-transmit.exe
)

if not exist "keys" mkdir keys
if not exist "keys\native_session.key" (
    echo [INIT] Generating fresh 256-bit post-quantum session key...
    "%BIN%" keygen --out keys\native_session.key
)

start "TERMINAL 1: NORAD ALPHA (NATIVE RUST)" cmd /k "cd /d "%~dp0" && start_native_terminal_alpha.bat"
timeout /t 2 /nobreak >nul
start "TERMINAL 2: PENTAGON BRAVO (NATIVE RUST)" cmd /k "cd /d "%~dp0" && start_native_terminal_bravo.bat"
echo Terminals launched successfully in two separate native console windows.
pause
