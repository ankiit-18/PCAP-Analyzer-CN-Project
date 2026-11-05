@echo off
REM One-command launcher for Windows. Requires Python 3, Node.js and tshark (Wireshark) on PATH.
cd /d "%~dp0"
if exist backend\.venv ( backend\.venv\Scripts\python -m pip --version >nul 2>&1 || rmdir /s /q backend\.venv )
if not exist backend\.venv python -m venv backend\.venv
backend\.venv\Scripts\python -m pip install -q -r backend\requirements.txt
cd frontend
call npm install --no-audit --no-fund --silent
call npm run build --silent
cd ..\backend
echo PCAP Analyzer running at http://127.0.0.1:8000  (Ctrl+C to stop)
.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 8000
