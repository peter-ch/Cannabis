@echo off
setlocal
cd /d "%~dp0"
echo Cannabis - guided Windows participant setup
echo This installs verified portable tools for your Windows account, then opens the guide.
echo It does not move funds or enroll anyone automatically.
echo.
choice /c YN /n /m "Prepare and open Cannabis? [Y/N] "
if errorlevel 2 exit /b 0
powershell.exe -NoProfile -File "%~dp0scripts\windows-setup.ps1"
if errorlevel 1 (
  echo.
  echo Setup did not finish. See docs\windows-setup.md for recovery and policy guidance.
  pause
  exit /b 1
)
endlocal
