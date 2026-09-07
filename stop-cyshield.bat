@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Cyshield Pro - shutdown

REM ============================================================================
REM  Cyshield Pro - clean stop and cache clear
REM
REM  Stops the dev server and the containers, then deletes build output and
REM  test/tool caches.
REM
REM  What it deliberately does NOT touch:
REM    .env               - your API keys and DATABASE_URL
REM    node_modules       - reinstalling is slow and is not a cache clear
REM    docker volumes     - your scan data, workspaces and findings survive
REM    docs/screenshots   - captured evidence, not a build artefact
REM
REM  Containers are STOPPED, not removed, so the database keeps its data.
REM  To destroy the data as well:  docker-compose down -v
REM ============================================================================

cd /d "%~dp0"

set "APP_PORT=5050"
if exist ".env" (
  for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    if /i "%%A"=="PORT" set "APP_PORT=%%B"
  )
)
for /f "tokens=* delims= " %%A in ("!APP_PORT!") do set "APP_PORT=%%A"

echo.
echo  ============================================
echo   Cyshield Pro - stopping
echo  ============================================
echo.

REM --- 1. Dev server ----------------------------------------------------------
echo  [1/4] Stopping anything on port !APP_PORT!...
set "KILLED="
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /c:"LISTENING" ^| findstr /c:":!APP_PORT! "') do (
  if not "%%P"=="0" (
    taskkill /F /PID %%P >nul 2>&1
    if not errorlevel 1 (
      echo        Stopped PID %%P.
      set "KILLED=1"
    )
  )
)
if not defined KILLED echo        Nothing was listening on !APP_PORT!.

REM  A `tsx` run leaves a child node process that can outlive the port holder.
REM  Killing only the wrapper is how a stale server keeps serving old code.
for /f "usebackq tokens=2 delims=," %%P in (`tasklist /fi "imagename eq node.exe" /fo csv /nh 2^>nul`) do (
  set "NPID=%%~P"
  wmic process where "ProcessId=!NPID!" get CommandLine /value 2>nul | findstr /i "server[/\\]index.ts" >nul 2>&1
  if not errorlevel 1 (
    taskkill /F /PID !NPID! >nul 2>&1
    echo        Stopped orphaned dev-server process !NPID!.
  )
)

REM --- 2. Containers ----------------------------------------------------------
set "COMPOSE="
docker compose version >nul 2>&1
if not errorlevel 1 set "COMPOSE=docker compose"
if not defined COMPOSE (
  docker-compose version >nul 2>&1
  if not errorlevel 1 set "COMPOSE=docker-compose"
)

echo  [2/4] Stopping containers...
docker info >nul 2>&1
if errorlevel 1 (
  echo        Docker is not running - nothing to stop.
) else (
  if defined COMPOSE (
    REM  --profile darkweb so `stop` also reaches the Tor container; a profiled
    REM  service is invisible to a bare `compose stop` and would be left running.
    %COMPOSE% --profile darkweb stop >nul 2>&1
  )
  REM  Belt and braces: catch a container started outside compose.
  docker stop cyshield-db  >nul 2>&1
  docker stop cyshield-app >nul 2>&1
  docker stop cyshield-ollama >nul 2>&1
  echo        Containers stopped ^(data volumes preserved^).
)

REM --- 3. Build output and caches ---------------------------------------------
echo  [3/4] Clearing build output and caches...
call :wipe_dir  "dist"                      "production build output"
call :wipe_dir  "node_modules\.vite"        "Vite dependency cache"
call :wipe_dir  ".vite"                     "Vite cache"
call :wipe_dir  "test-results"              "Playwright test results"
call :wipe_dir  "playwright-report"         "Playwright HTML report"
call :wipe_dir  "coverage"                  "coverage output"
call :wipe_dir  "node_modules\.cache"       "tooling cache"

REM  The cached Playwright auth state is a 23h token. A stale one makes the
REM  logout test fail with "auth_token is null", which reads like a product bug
REM  rather than a stale fixture - so clearing it is part of a clean stop.
call :wipe_file "tests\e2e\.auth-state.json" "cached E2E auth state"

REM  Scratch files a scan or QA run can leave in the project root.
for %%F in ("*.tmp" "*-tmp.mts" "npm-debug.log*" "*.log") do (
  if exist "%%~F" (
    del /q "%%~F" >nul 2>&1
    echo        removed %%~F
  )
)

REM --- 4. Summary -------------------------------------------------------------
echo  [4/4] Done.
echo.
echo  ============================================
echo   Cyshield Pro is stopped
echo  ============================================
echo    Preserved:  .env, node_modules, database volume, docs/screenshots
echo.
echo    Next start:   start-cyshield.bat
echo    Wipe DB too:  %COMPOSE% down -v      ^(destroys scan data^)
echo.
endlocal
exit /b 0

REM ---------------------------------------------------------------------------
:wipe_dir
if exist %~1\ (
  rd /s /q %~1 >nul 2>&1
  if exist %~1\ (
    echo        [!] could not remove %~2 - a file may be open
  ) else (
    echo        removed %~2
  )
)
exit /b 0

:wipe_file
if exist %~1 (
  del /q %~1 >nul 2>&1
  if exist %~1 (
    echo        [!] could not remove %~2
  ) else (
    echo        removed %~2
  )
)
exit /b 0
