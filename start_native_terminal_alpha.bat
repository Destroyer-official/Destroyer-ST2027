@echo off
cd /d "%~dp0"
title ST2027 NATIVE RUST TACTICAL TERMINAL (BASE ALPHA - NORAD)
color 0B
echo ===============================================================================
echo   ST2027 STANDALONE NATIVE RUST TACTICAL TERMINAL (BASE ALPHA - NORAD)
echo   Post-Quantum CNSA 2.0 / FIPS 203 ML-KEM-1024 / FIPS 204 ML-DSA-87 / AES-256-GCM
echo   Traffic Invariance: 50ms Constant-Rate Wire Pacing ^| 1232B Fixed Quantized Cells
echo   Zero Python ^| Zero Web Runtime ^| NIST SP 800-88 Deterministic In-RAM Sanitization
echo ===============================================================================
echo.

set BIN=rust_data_plane\target\release\secure-transmit.exe
if not exist "%BIN%" set BIN=rust_data_plane\target\debug\secure-transmit.exe
if not exist "%BIN%" (
    echo [ERROR] Native binary not found. Compiling release binary...
    cargo build --release --manifest-path rust_data_plane\Cargo.toml --bin secure-transmit
    set BIN=rust_data_plane\target\release\secure-transmit.exe
)

if not exist "keys" mkdir keys
if not exist "keys\native_session.key" (
    echo [INIT] Generating fresh 256-bit post-quantum session key...
    "%BIN%" keygen --out keys\native_session.key
)

echo Starting Base Alpha (Responder) on 127.0.0.1:9060 ^<--^> Peer 127.0.0.1:9061...
echo.
"%BIN%" terminal --key-file keys\native_session.key --state keys\alpha_term.state --bind 127.0.0.1:9060 --to 127.0.0.1:9061 --role responder --interval-ms 50 --quantum 1232 --callsign NORAD-ALPHA %*
pause
