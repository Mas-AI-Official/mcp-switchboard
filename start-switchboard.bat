@echo off
REM ============================================================================
REM  MCP Switchboard - one-click launcher (Windows)
REM
REM  One governed MCP endpoint in front of all your MCP servers. Double-click
REM  this file (or pin it to your taskbar / Start menu) to start the gateway
REM  plus its web dashboard; your browser opens automatically when it's ready.
REM
REM  First run: installs dependencies, builds, and writes a starter config.
REM  Stop it any time with Ctrl+C in this window, or run stop-switchboard.bat.
REM ============================================================================
setlocal enableextensions
title MCP Switchboard
cd /d "%~dp0"

REM --- 1. Node.js present? ----------------------------------------------------
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo   [MCP Switchboard] Node.js was not found on your PATH.
  echo   Install Node 18.18 or newer from https://nodejs.org and run this again.
  echo.
  pause
  exit /b 1
)

REM --- 2. Dependencies (first run only) ---------------------------------------
if not exist "node_modules\" (
  echo   [MCP Switchboard] Installing dependencies ^(first run, ~1 minute^)...
  call npm install
  if errorlevel 1 (
    echo   [MCP Switchboard] npm install failed - see the messages above.
    pause
    exit /b 1
  )
)

REM --- 3. Build (first run / after a git pull) --------------------------------
if not exist "dist\cli.js" (
  echo   [MCP Switchboard] Building...
  call npm run build
  if errorlevel 1 (
    echo   [MCP Switchboard] build failed - see the messages above.
    pause
    exit /b 1
  )
)

REM --- 4. Config (created once, then it's yours to edit) ----------------------
if not exist "switchboard.config.yaml" (
  echo   [MCP Switchboard] Creating a starter switchboard.config.yaml...
  node "dist\cli.js" init
)

REM --- 5. Resolve the dashboard port (falls back to the 8088 default) ---------
set "PORT=8088"
for /f "usebackq delims=" %%p in (`node -e "const fs=require('fs');try{const m=String(fs.readFileSync('switchboard.config.yaml','utf8')).match(/port:\s*(\d+)/);process.stdout.write(m?m[1]:'8088')}catch(e){process.stdout.write('8088')}" 2^>nul`) do set "PORT=%%p"

REM --- 6. Open the dashboard once the port is actually listening --------------
REM     (detached; polls the socket so the browser never opens too early - the
REM      first run may download the bundled test server before it binds)
start "" powershell -NoProfile -WindowStyle Hidden -Command "$p=%PORT%; for($i=0;$i -lt 240;$i++){ try{ $c=New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1',$p); $c.Close(); Start-Process ('http://127.0.0.1:'+$p); break } catch { Start-Sleep -Milliseconds 500 } }"

REM --- 7. Run the gateway + dashboard (this window streams the logs) ----------
echo.
echo   MCP Switchboard is starting on http://127.0.0.1:%PORT%
echo   The dashboard will open in your browser automatically.
echo   Keep this window open. Press Ctrl+C to stop.
echo.
node "dist\cli.js" dashboard

REM --- when the server exits --------------------------------------------------
echo.
echo   [MCP Switchboard] stopped.
pause
