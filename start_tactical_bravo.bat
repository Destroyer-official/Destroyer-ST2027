@echo off
cd /d "%~dp0"
title ST2027 OPERATOR CONSOLE (NODE BRAVO - PENTAGON)
color 0A
set P2P_DATA_PLANE=rust
set SECURE_P2P_PRODUCTION=1
set P2P_PRODUCTION=1

set BIN=rust_data_plane\target\release\secure-transmit.exe
if not exist "%BIN%" set BIN=rust_data_plane\target\debug\secure-transmit.exe
if not exist "%BIN%" (
    echo [ERROR] Native binary not found. Compiling release binary...
    cargo build --release --offline --no-default-features --manifest-path rust_data_plane\Cargo.toml --bin secure-transmit
    set BIN=rust_data_plane\target\release\secure-transmit.exe
)

if not exist "keys" mkdir keys
if not exist "keys\tactical_shared.psk" (
    echo [INIT] Generating authentic CNSA 2.0 PSK...
    "%BIN%" keygen --out keys\tactical_shared.psk
)
if not exist "keys\alpha.sk" "%BIN%" auth-keygen --out-sk keys\alpha.sk --out-pk keys\alpha.pk
if not exist "keys\bravo.sk" "%BIN%" auth-keygen --out-sk keys\bravo.sk --out-pk keys\bravo.pk

echo ===============================================================================
echo   ST2027 PRODUCTION POST-QUANTUM C2 CONSOLE (NODE BRAVO - INITIATOR)
echo   Post-Quantum KEX: ML-KEM-1024 + ECDH P-384 / Auth: ML-DSA-87 / Ratchet: SPQR
echo ===============================================================================
echo.
"%BIN%" node --role initiator --bind 127.0.0.1:9061 --to 127.0.0.1:9060 --psk-file keys\tactical_shared.psk --auth-sk-file keys\bravo.sk --peer-auth-pk-file keys\alpha.pk --require-mutual-auth --state keys\bravo_tactical.state --interval-ms 50 --quantum 1232 --callsign PENTAGON-BRAVO %*
pause
