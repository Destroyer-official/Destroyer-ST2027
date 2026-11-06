@echo off
cd /d "%~dp0"
title ST2027 TACTICAL WEB OPERATOR CONSOLE (mTLS 1.3 + FIDO2 L3)
echo ===============================================================================
echo   LAUNCHING ST2027 TACTICAL WEB OPERATOR CONSOLE
echo   Security: DoD CAC / PIV mTLS 1.3 + WebAuthn FIDO2 Level 3 Hardware Key
echo   CSP: Level 3 Strict (default-src 'self'; object-src 'none'; Zero CDNs)
echo   PQC: Post-Quantum ML-KEM-1024 + ML-DSA-87 + 20ms Continuous Wire Camouflage
echo   URL: https://127.0.0.1:8443
echo ===============================================================================
echo.
python tactical_web_console.py --host 127.0.0.1 --port 8443
pause
