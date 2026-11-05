@echo off
cd /d "%~dp0"
echo ===============================================================================
echo   SPAWNING 2 ST2027 OPERATOR TERMINALS (CNSA 2.0 / POST-QUANTUM)
echo   Post-Quantum ML-KEM-1024 + Continuous 20ms Paced Wire Transmission
echo ===============================================================================
echo.
echo Terminal 1: Node Alpha (Responder)
echo Terminal 2: Node Bravo (Initiator)
echo.
start "TERMINAL 1: NODE ALPHA" cmd /k "cd /d "%~dp0" && start_tactical_alpha.bat"
timeout /t 2 /nobreak >nul
start "TERMINAL 2: NODE BRAVO" cmd /k "cd /d "%~dp0" && start_tactical_bravo.bat"
echo Terminals launched successfully in two separate windows.
