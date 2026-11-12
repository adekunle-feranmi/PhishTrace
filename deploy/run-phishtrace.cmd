@echo off
setlocal
cd /d C:\Users\Administrator\PhishTrace
if not exist data mkdir data
.venv\Scripts\phishtrace.exe serve >> data\serve.log 2>&1
