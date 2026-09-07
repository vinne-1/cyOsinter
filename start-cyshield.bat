@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Cyshield Pro - startup

REM ============================================================================
REM  Cyshield Pro - clean start
REM
REM  Brings up the database, waits for it to be genuinely healthy, frees the
REM  app port, then launches the dev server in its own window.
REM
REM  Deliberately starts ONLY the `db` service. A bare `docker-compose up -d`
REM  would also start the `app` container, which is the same product listening
REM  on the same port - it would fight the dev server for it.
REM
REM  This script does NOT run `drizzle-kit push`. That command can prompt for
REM  confirmation on destructive schema changes, which would hang an unattended
REM  script, and forcing it past that prompt risks the local data. Run
REM  `npm run db:push` by hand after a schema change.
REM ============================================================================

cd /d "%~dp0"

set "APP_PORT=5050"
if exist ".env" (
  for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    if /i "%%A"=="PORT" set "APP_PORT=%%B"
  )
)
REM Strip stray whitespace a hand-edited .env can leave behind.
for /f "tokens=* delims= " %%A in ("!APP_PORT!") do set "APP_PORT=%%A"

echo.
echo  ============================================
echo   Cyshield Pro - starting
echo  ============================================
echo.

REM --- 1. Docker present and running -----------------------------------------
where docker >nul 2>&1
if errorlevel 1 (
  echo  [X] Docker is not on PATH. Install Docker Desktop, then re-run.
  goto :fail
)

docker info >nul 2>&1
if errorlevel 1 (
  echo  [X] Docker is installed but not running.
  echo      Start Docker Desktop, wait for it to report "Engine running", then re-run.
  goto :fail
)
echo  [1/5] Docker engine is running.

REM --- 2. Pick the compose CLI that actually exists ---------------------------
REM  Docker v29 on this machine has no `docker compose` subcommand, only the
REM  standalone `docker-compose` binary. Detect rather than assume.
set "COMPOSE="
docker compose version >nul 2>&1
if not errorlevel 1 set "COMPOSE=docker compose"
if not defined COMPOSE (
  docker-compose version >nul 2>&1
  if not errorlevel 1 set "COMPOSE=docker-compose"
)
if not defined COMPOSE (
  echo  [X] Neither "docker compose" nor "docker-compose" is available.
  goto :fail
)

REM --- 3. Database ------------------------------------------------------------
echo  [2/5] Starting database (service: db)...
REM  Merge stderr into stdout: compose writes its progress lines to stderr,
REM  which some shells surface as errors even on a clean start. errorlevel
REM  is unaffected by the redirect, so a real failure is still caught below.
%COMPOSE% up -d db 2>&1
if errorlevel 1 (
  echo  [X] Could not start the database container.
  goto :fail
)

echo  [3/5] Waiting for Postgres to report healthy...
set "DB_READY="
for /l %%i in (1,1,60) do (
  if not defined DB_READY (
    for /f "usebackq tokens=*" %%H in (`docker inspect --format="{{.State.Health.Status}}" cyshield-db 2^>nul`) do (
      if "%%H"=="healthy" set "DB_READY=1"
    )
    if not defined DB_READY (
      ping -n 2 127.0.0.1 >nul
    )
  )
)
if not defined DB_READY (
  echo  [X] Database did not become healthy within ~60s.
  echo      Check: docker logs cyshield-db
  goto :fail
)
echo        Database healthy.

REM --- 3b. Tor (optional) -----------------------------------------------------
REM  Dark-web monitoring needs a SOCKS5 proxy to reach .onion services. Without
REM  it those sources are SKIPPED and the panel reports the check as incomplete
REM  rather than clean -- which is correct, but it means the feature does not
REM  actually run. Start it with:  start-cyshield.bat /darkweb
REM
REM  It is opt-in because it starts a Tor client on this machine, which is an
REM  operator's decision to make rather than a side effect of starting the app.
if /i "%~1"=="/darkweb" (
  echo  [3b/5] Starting Tor proxy for dark-web monitoring...
  %COMPOSE% --profile darkweb up -d tor 2>&1
  if errorlevel 1 (
    echo  [!] Tor container did not start -- dark-web .onion sources will be skipped.
  ) else (
    echo        Waiting for a Tor circuit ^(~30s from cold^)...
    set "TOR_READY="
    for /l %%i in (1,1,45) do (
      if not defined TOR_READY (
        for /f "usebackq tokens=*" %%T in (`docker inspect --format="{{.State.Health.Status}}" cyshield-tor 2^>nul`) do (
          if "%%T"=="healthy" set "TOR_READY=1"
        )
        if not defined TOR_READY ping -n 2 127.0.0.1 >nul
      )
    )
    if defined TOR_READY (
      echo        Tor circuit ready -- .onion sources enabled.
    ) else (
      echo  [!] Tor did not build a circuit in time. Dark-web .onion sources
      echo      will be skipped and reported as an incomplete check.
    )
  )
)

REM --- 4. Free the app port ---------------------------------------------------
REM  A leftover server from a previous run holds the port AND serves stale code,
REM  which is the documented way to get a convincing but wrong result.
echo  [4/5] Ensuring port !APP_PORT! is free...
set "KILLED="
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /c:"LISTENING" ^| findstr /c:":!APP_PORT! "') do (
  if not "%%P"=="0" (
    taskkill /F /PID %%P >nul 2>&1
    if not errorlevel 1 set "KILLED=1"
  )
)
if defined KILLED (
  echo        Stopped a process that was holding port !APP_PORT!.
) else (
  echo        Port !APP_PORT! was already free.
)

REM --- 5. Dev server ----------------------------------------------------------
echo  [5/5] Launching dev server in a new window...
start "Cyshield Dev Server (port !APP_PORT!)" cmd /k "cd /d "%~dp0" && npm run dev"

echo.
echo  Waiting for the server to answer...
set "APP_READY="
for /l %%i in (1,1,60) do (
  if not defined APP_READY (
    curl -s -o nul -m 2 "http://localhost:!APP_PORT!/readyz" >nul 2>&1
    if not errorlevel 1 set "APP_READY=1"
    if not defined APP_READY ping -n 2 127.0.0.1 >nul
  )
)

echo.
if defined APP_READY (
  echo  ============================================
  echo   Cyshield Pro is up
  echo  ============================================
  echo    App        http://localhost:!APP_PORT!
  echo    Health     http://localhost:!APP_PORT!/readyz
  echo    Database   cyshield-db  ^(container^)
  echo.
  echo    Server logs are in the "Cyshield Dev Server" window.
  echo    Run stop-cyshield.bat to shut everything down.
) else (
  echo  [!] The server did not answer /readyz in ~60s.
  echo      It may still be compiling - check the "Cyshield Dev Server" window
  echo      for the actual error before assuming it failed.
)
echo.
endlocal
exit /b 0

:fail
echo.
echo  Startup aborted.
echo.
endlocal
exit /b 1
