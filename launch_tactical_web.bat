@echo off
cd /d "%~dp0"
title ST2027 WEB OPERATOR CONSOLE
echo ===============================================================================
echo   LAUNCHING ST2027 WEB OPERATOR CONSOLE
echo   Post-Quantum ML-KEM-1024 + 20ms Continuous Wire Pacing
echo   URL: http://127.0.0.1:8443
echo ===============================================================================
echo.
python secure_p2p.py web --lab --host 127.0.0.1 --port 8443
pause
