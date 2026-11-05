@echo off
title Secure P2P Dual Terminal Launcher (Direct Real IPv6)
cd /d "%~dp0"
echo ===============================================================================
echo   SPAWNING 2 SOVEREIGN MILITARY P2P TERMINALS (DIRECT REAL IPV6 DEFCON-1)
echo   Post-Quantum ML-KEM-1024 + Continuous 20ms Paced Wire Camouflage
echo   Transport: Real Global IPv6 Direct Peer-to-Peer
echo ===============================================================================
echo.
echo Terminal 1: NORAD Base Alpha    (Direct IPv6 Responder)
echo Terminal 2: Pentagon Base Bravo (Direct IPv6 Initiator)
echo.
start "TERMINAL 1: NORAD ALPHA (IPV6)" cmd /k "cd /d "%~dp0" && start_tactical_alpha_ipv6.bat"
timeout /t 2 /nobreak >nul
start "TERMINAL 2: PENTAGON BRAVO (IPV6)" cmd /k "cd /d "%~dp0" && start_tactical_bravo_ipv6.bat"
echo Terminals launched successfully in two separate windows over Direct IPv6.
pause

