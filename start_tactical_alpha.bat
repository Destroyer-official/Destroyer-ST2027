@echo off
REM Destroyer-ST2027 Military Production Hardening Release (2026-10-26)
REM NSA Commercial National Security Algorithm (CNSA) Suite 2.0 / FIPS 203 / FIPS 204
cd /d "%~dp0"
title NORAD STRATEGIC DEFENSE COMMAND (BASE ALPHA)
set P2P_DATA_PLANE=rust
python destroyer_tactical_p2p.py node --role responder --bind 127.0.0.1 --peer 127.0.0.1 --name NORAD_ALPHA
pause
