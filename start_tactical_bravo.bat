@echo off
cd /d "%~dp0"
title PENTAGON JOINT OPERATIONS CENTER (BASE BRAVO)
set P2P_DATA_PLANE=rust
python secure_p2p.py bravo
pause
