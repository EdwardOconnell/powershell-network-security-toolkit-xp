@echo off
rem NetSecToolkitXP menu, same as NetSecToolkitXP.exe. Use this if an
rem antivirus blocks the .exe. Keep it next to the NetSecToolkitXP folder.
set "NSTXP_PS=%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%NSTXP_PS%" (
  echo Windows PowerShell 2.0 is not installed. Install the Windows Management
  echo Framework Core for Windows XP ^(KB968930^), then run this again.
  pause
  exit /b 1
)
if not exist "%~dp0NetSecToolkitXP\NetSecToolkitXP.psd1" (
  echo The NetSecToolkitXP folder must be next to this file.
  pause
  exit /b 1
)
cd /d "%~dp0"
"%NSTXP_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "& { Import-Module .\NetSecToolkitXP\NetSecToolkitXP.psd1 -Force; Start-NetSecToolkitXP }"
