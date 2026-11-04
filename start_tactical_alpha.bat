@echo off
cd /d "%~dp0"
title NORAD STRATEGIC DEFENSE COMMAND (BASE ALPHA)
set P2P_DATA_PLANE=rust
python secure_p2p.py alpha
pause
