@echo off
cd /d "%~dp0"
title NORAD STRATEGIC DEFENSE COMMAND (BASE ALPHA)
color 0B
set P2P_DATA_PLANE=rust
set SECURE_P2P_PRODUCTION=1
set P2P_PRODUCTION=1
python secure_p2p.py alpha %*
pause
