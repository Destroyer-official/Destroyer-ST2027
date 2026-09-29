@echo off
cd /d "%~dp0"
title PENTAGON JOINT OPERATIONS CENTER (BASE BRAVO)
python destroyer_tactical_p2p.py node --role initiator --bind 127.0.0.1 --peer 127.0.0.1 --name PENTAGON_BRAVO
pause
