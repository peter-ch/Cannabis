@echo off
setlocal
cd /d "%~dp0"
where node.exe >nul 2>nul
if errorlevel 1 (
  echo Use the pinned Node.js 24.22.0 or 22.23.3 tools. See the Cannabis worker console guide.
  echo https://cannabis-coin.online/docs/worker-console.html
  pause
  exit /b 1
)
echo Cannabis worker console - local observation and admission readiness
echo Keep this window open. Ctrl+C stops the console.
node.exe operator\server.mjs --open
if errorlevel 1 pause
endlocal
