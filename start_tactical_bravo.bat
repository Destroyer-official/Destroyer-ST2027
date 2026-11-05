@echo off
cd /d "%~dp0"
title ST2027 OPERATOR CONSOLE (NODE BRAVO)
color 0A
set P2P_DATA_PLANE=rust
set SECURE_P2P_PRODUCTION=1
set P2P_PRODUCTION=1
python secure_p2p.py bravo %*
pause
