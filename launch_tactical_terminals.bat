@echo off
REM Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
REM NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
cd /d "%~dp0"
echo ===============================================================================
echo   SPAWNING 2 TACTICAL MILITARY P2P TERMINALS (ST2027 DEFCON-1)
echo   Post-Quantum ML-KEM-1024 + Continuous 20ms Paced Wire Camouflage
echo ===============================================================================
echo.
echo Terminal 1: NORAD Base Alpha    (Responder)
echo Terminal 2: Pentagon Base Bravo (Initiator)
echo.
start "TERMINAL 1: NORAD ALPHA" cmd /k "cd /d "%~dp0" && start_tactical_alpha.bat"
timeout /t 2 /nobreak >nul
start "TERMINAL 2: PENTAGON BRAVO" cmd /k "cd /d "%~dp0" && start_tactical_bravo.bat"
echo Terminals launched successfully in two separate windows.
