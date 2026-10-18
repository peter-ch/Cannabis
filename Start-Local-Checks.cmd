@echo off
setlocal
cd /d "%~dp0"
echo Cannabis - local operator workflow checks
echo Uses labeled fixture identities on a temporary loopback chain. No public activity.
choice /c YN /n /m "Prepare tools and run local checks? [Y/N] "
if errorlevel 2 exit /b 0
powershell.exe -NoProfile -File "%~dp0scripts\windows-setup.ps1" -CheckActivity
if errorlevel 1 echo Checks did not complete. See the local output and documentation.
pause
endlocal
