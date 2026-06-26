@echo off
REM ============================================================================
REM  MCP Switchboard - stop the running gateway (Windows)
REM
REM  Frees whatever is listening on the configured dashboard port. Use this if
REM  you closed the launcher window without Ctrl+C and the port is still busy.
REM
REM  It kills the whole process tree (the gateway plus any upstream MCP servers
REM  it spawned), and falls back to PowerShell if taskkill can't do the job.
REM ============================================================================
setlocal enableextensions
cd /d "%~dp0"

REM --- Resolve the port from the config (falls back to the 8088 default) ------
set "PORT=8088"
for /f "usebackq delims=" %%p in (`node -e "const fs=require('fs');try{const m=String(fs.readFileSync('switchboard.config.yaml','utf8')).match(/port:\s*(\d+)/);process.stdout.write(m?m[1]:'8088')}catch(e){process.stdout.write('8088')}" 2^>nul`) do set "PORT=%%p"

echo   [MCP Switchboard] Stopping anything listening on port %PORT% ...

set "FOUND="
set "KILLED="
for /f "tokens=5" %%a in ('netstat -ano ^| findstr /C:":%PORT% " ^| findstr /C:"LISTENING"') do (
  set "FOUND=1"
  call :kill_pid %%a
)

if not defined FOUND (
  echo   [MCP Switchboard] nothing was listening on port %PORT% - already stopped.
) else if defined KILLED (
  echo   [MCP Switchboard] done.
) else (
  echo   [MCP Switchboard] found a process on port %PORT% but could not stop it.
  echo   [MCP Switchboard] try again from an Administrator command prompt.
)
exit /b 0

REM --- kill one PID (tree first via taskkill; PowerShell Stop-Process backup) --
:kill_pid
set "_PID=%~1"
taskkill /PID %_PID% /T /F >nul 2>nul
if not errorlevel 1 (
  echo   [MCP Switchboard] stopped PID %_PID%.
  set "KILLED=1"
  goto :eof
)
REM taskkill failed (process held by a parent, elevated, etc.) - fall back.
powershell -NoProfile -Command "try { Stop-Process -Id %_PID% -Force -ErrorAction Stop; exit 0 } catch { exit 1 }" >nul 2>nul
if not errorlevel 1 (
  echo   [MCP Switchboard] stopped PID %_PID% ^(via PowerShell^).
  set "KILLED=1"
)
goto :eof
