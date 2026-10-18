@echo off
setlocal
cd /d "%~dp0"
where node.exe >nul 2>nul
if errorlevel 1 (
  echo Node.js 22.22 or later is required. See the Cannabis worker console guide.
  echo https://cannabis-coin.online/docs/worker-console.html
  pause
  exit /b 1
)
echo Cannabis worker console - local observation and admission readiness
echo Keep this window open. Ctrl+C stops the console.
node.exe operator\server.mjs --open
if errorlevel 1 pause
endlocal
