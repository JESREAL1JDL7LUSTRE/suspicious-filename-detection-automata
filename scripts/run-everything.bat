@echo off
REM RUN EVERYTHING — CLONE / INSTALL / RUN SERVERS / OPEN UI
REM Works from ANY directory for ANY user

setlocal EnableDelayedExpansion

REM --------------------------
REM CONFIG
REM --------------------------
set REPO_URL=https://github.com/JESREAL1JDL7LUSTRE/suspicious-filename-detection-automata.git
set REPO_FOLDER=suspicious-filename-detection-automata

REM --------------------------
REM DETECT SCRIPT LOCATION
REM --------------------------
set "SCRIPT_DIR=%~dp0"
if not "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR%\"

echo ===============================
echo Script running from: %SCRIPT_DIR%
echo ===============================

REM --------------------------
REM CHECK PREREQUISITES
REM --------------------------
echo Checking prerequisites...

where git >nul 2>nul || (
    echo ERROR: Git NOT FOUND. Install Git and try again.
    echo Download from: https://git-scm.com/download/win
    pause
    exit /b 1
)
echo [OK] Git found

where node >nul 2>nul || (
    echo ERROR: Node.js NOT FOUND. Install Node.js and try again.
    echo Download from: https://nodejs.org/
    pause
    exit /b 1
)
echo [OK] Node.js found

where npm >nul 2>nul || (
    echo ERROR: NPM NOT FOUND. Install Node.js and try again.
    pause
    exit /b 1
)
echo [OK] NPM found

where python >nul 2>nul || (
    echo WARNING: Python NOT FOUND. Mock file generation will be skipped.
    echo Download from: https://www.python.org/downloads/
    set PYTHON_AVAILABLE=0
) || (
    echo [OK] Python found
    set PYTHON_AVAILABLE=1
)

echo.

REM --------------------------
REM DETERMINE BASE DIRECTORY
REM --------------------------
REM Compute parent directory and detect if this script is inside a `scripts\` folder
for %%I in ("%SCRIPT_DIR:~0,-1%") do set "SCRIPT_FOLDER_NAME=%%~nI"
for %%I in ("%SCRIPT_DIR%..") do set "PARENT_DIR=%%~fI\"

if /I "%SCRIPT_FOLDER_NAME%"=="scripts" (
    set "BASE_DIR=%PARENT_DIR%"
    echo Detected script in 'scripts' folder
    echo Using parent directory as base: %BASE_DIR%
) else (
    set "BASE_DIR=%SCRIPT_DIR%"
    echo Using script directory as base: %BASE_DIR%
)

echo.

REM If no special flag, jump to runner creation which opens a single PowerShell window
if not "%1"=="--inline" goto :create_runner

REM --------------------------
REM INLINE MODE (deprecated, use default mode)
REM --------------------------
if not exist "%BASE_DIR%%REPO_FOLDER%\" (
    if exist "%SCRIPT_DIR%%REPO_FOLDER%\" (
        echo Found nested clone in "%SCRIPT_DIR%" — moving it to parent "%BASE_DIR%"
        move "%SCRIPT_DIR%%REPO_FOLDER%" "%BASE_DIR%"
        if errorlevel 1 (
            echo ERROR: Failed to move nested repository. Please move it manually and re-run.
            pause
            exit /b 1
        )
    ) else (
        echo Repository NOT found. Cloning into:
        echo   "%BASE_DIR%%REPO_FOLDER%\"
        git clone %REPO_URL% "%BASE_DIR%%REPO_FOLDER%"
        if errorlevel 1 (
            echo ERROR: Failed cloning repository.
            pause
            exit /b 1
        )
    )
) else (
    echo Repository FOUND at "%BASE_DIR%%REPO_FOLDER%\" — skipping clone.
)

set WORKDIR=%BASE_DIR%%REPO_FOLDER%\
echo ### DEBUG: Clone step complete. WORKDIR=%WORKDIR%

REM --------------------------
REM INSTALL FRONTEND DEPENDENCIES
REM --------------------------
if exist "%WORKDIR%\display\package.json" (
    echo Installing dependencies (npm install)...
    pushd "%WORKDIR%\display"
    npm install
    if errorlevel 1 (
        echo ERROR: npm install FAILED.
        popd
        pause
        exit /b 1
    )
    popd
) else (
    echo ERROR: package.json NOT FOUND — something is wrong.
    pause
    exit /b 1
)

REM --------------------------
REM BUILD NATIVE SIMULATOR (in new window) and wait for completion
REM --------------------------
echo Running native build (will open a new PowerShell window and wait)...
start "Build Simulator" /wait powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%WORKDIR%'; if (Test-Path '.scripts\build.ps1') { & '.scripts\build.ps1' } else { Write-Host '.scripts\build.ps1 not found'; exit 1 }"

REM After build completes, launch simulator.exe in its own window
if exist "%WORKDIR%\simulator.exe" (
    echo Starting simulator.exe in new window...
    start "Simulator" powershell -NoExit -NoProfile -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%WORKDIR%'; & '.\\simulator.exe'"
) else (
    echo WARNING: simulator.exe not found at "%WORKDIR%\simulator.exe" — build may have failed.
)

REM --------------------------
REM START BOTH SERVERS (backend & frontend) in separate windows
REM --------------------------
echo Starting backend and frontend in new windows...
start "Backend Server" powershell -NoExit -NoProfile -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%WORKDIR%\display'; npm run dev:server"
start "Frontend (Vite)" powershell -NoExit -NoProfile -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%WORKDIR%\display'; npm run dev"

REM Give servers a moment then open browser
timeout /t 4 >nul
start "" http://localhost:5173

echo ===============================
echo All DONE, SYSTEM IS RUNNING!
echo FRONTEND UI: http://localhost:5173
echo Keep the opened windows visible to monitor output.
echo ===============================
pause
endlocal
exit /b 0

REM --------------------------
REM CREATE POWERSHELL RUNNER (DEFAULT MODE)
REM --------------------------
:create_runner
set "RUNNER=%SCRIPT_DIR%run-and-log.ps1"
if exist "%RUNNER%" del /f /q "%RUNNER%" >nul 2>&1

echo Creating PowerShell runner script...

echo # ============================================= > "%RUNNER%"
echo # Auto-generated PowerShell Runner Script >> "%RUNNER%"
echo # Generated on: %DATE% %TIME% >> "%RUNNER%"
echo # ============================================= >> "%RUNNER%"
echo. >> "%RUNNER%"
echo Write-Host "===============================================" -ForegroundColor Cyan >> "%RUNNER%"
echo Write-Host "  Suspicious Filename Detection Automata" -ForegroundColor Cyan >> "%RUNNER%"
echo Write-Host "  Automated Setup and Launch Script" -ForegroundColor Cyan >> "%RUNNER%"
echo Write-Host "===============================================" -ForegroundColor Cyan >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo $ErrorActionPreference = 'Continue' >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Configuration (dynamically set) --- >> "%RUNNER%"
echo $RepoUrl = '%REPO_URL%' >> "%RUNNER%"
echo $BaseDir = '%BASE_DIR%'.TrimEnd('\') >> "%RUNNER%"
echo $RepoFolder = '%REPO_FOLDER%' >> "%RUNNER%"
echo $TargetPath = Join-Path $BaseDir $RepoFolder >> "%RUNNER%"
echo $PythonAvailable = $true >> "%RUNNER%"
echo try { python --version ^| Out-Null; $PythonAvailable = $true } catch { $PythonAvailable = $false } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo Write-Host "Base Directory: $BaseDir" -ForegroundColor Yellow >> "%RUNNER%"
echo Write-Host "Repository will be cloned to: $TargetPath" -ForegroundColor Yellow >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Clone repository if needed --- >> "%RUNNER%"
echo if (-not (Test-Path -LiteralPath $TargetPath)) { >> "%RUNNER%"
echo     Write-Host "[CLONE] Repository not found. Cloning..." -ForegroundColor Yellow >> "%RUNNER%"
echo     Write-Host "  From: $RepoUrl" -ForegroundColor Gray >> "%RUNNER%"
echo     Write-Host "  To: $TargetPath" -ForegroundColor Gray >> "%RUNNER%"
echo     git clone $RepoUrl $TargetPath >> "%RUNNER%"
echo     if ($LASTEXITCODE -ne 0) { >> "%RUNNER%"
echo         Write-Host "[ERROR] Git clone failed!" -ForegroundColor Red >> "%RUNNER%"
echo         Read-Host "Press Enter to exit" >> "%RUNNER%"
echo         exit 1 >> "%RUNNER%"
echo     } >> "%RUNNER%"
echo     Write-Host "[OK] Clone successful!" -ForegroundColor Green >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Host "[OK] Repository already exists at $TargetPath" -ForegroundColor Green >> "%RUNNER%"
echo } >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Verify directory structure --- >> "%RUNNER%"
echo $display = Join-Path $TargetPath 'display' >> "%RUNNER%"
echo if (-not (Test-Path -LiteralPath $display)) { >> "%RUNNER%"
echo     Write-Host "[ERROR] Expected frontend directory not found: $display" -ForegroundColor Red >> "%RUNNER%"
echo     Read-Host "Press Enter to exit" >> "%RUNNER%"
echo     exit 1 >> "%RUNNER%"
echo } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Build native simulator if build script exists --- >> "%RUNNER%"
echo $scriptsFolder = Join-Path $TargetPath '.scripts' >> "%RUNNER%"
echo $buildScript = Join-Path $scriptsFolder 'build.ps1' >> "%RUNNER%"
echo Write-Host "[BUILD] Looking for build script..." -ForegroundColor Cyan >> "%RUNNER%"
echo Write-Host "  Path: $buildScript" -ForegroundColor Gray >> "%RUNNER%"
echo if (Test-Path -LiteralPath $buildScript) { >> "%RUNNER%"
echo     Write-Host "[BUILD] Found! Running build..." -ForegroundColor Yellow >> "%RUNNER%"
echo     Push-Location -LiteralPath $TargetPath >> "%RUNNER%"
echo     try { >> "%RUNNER%"
echo         ^& $buildScript >> "%RUNNER%"
echo         if ($LASTEXITCODE -eq 0) { >> "%RUNNER%"
echo             Write-Host "[OK] Build completed successfully!" -ForegroundColor Green >> "%RUNNER%"
echo         } else { >> "%RUNNER%"
echo             Write-Host "[WARNING] Build script returned exit code: $LASTEXITCODE" -ForegroundColor Yellow >> "%RUNNER%"
echo         } >> "%RUNNER%"
echo     } catch { >> "%RUNNER%"
echo         Write-Host "[ERROR] Build failed: $_" -ForegroundColor Red >> "%RUNNER%"
echo     } finally { >> "%RUNNER%"
echo         Pop-Location >> "%RUNNER%"
echo     } >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Host "[WARNING] Build script not found - skipping native build." -ForegroundColor Yellow >> "%RUNNER%"
echo } >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Wait for build artifacts --- >> "%RUNNER%"
echo Start-Sleep -Seconds 2 >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Generate mock test files --- >> "%RUNNER%"
echo if ($PythonAvailable) { >> "%RUNNER%"
echo     $mockScript = Join-Path $TargetPath 's.py' >> "%RUNNER%"
echo     if (Test-Path -LiteralPath $mockScript) { >> "%RUNNER%"
echo         Write-Host "[MOCK FILES] Generating test files (2 per pattern)..." -ForegroundColor Cyan >> "%RUNNER%"
echo         try { >> "%RUNNER%"
echo             Push-Location -LiteralPath $TargetPath >> "%RUNNER%"
echo             echo "2" ^| python s.py ^| Out-Host >> "%RUNNER%"
echo             if ($LASTEXITCODE -eq 0) { >> "%RUNNER%"
echo                 Write-Host "[OK] Mock files generated!" -ForegroundColor Green >> "%RUNNER%"
echo             } else { >> "%RUNNER%"
echo                 Write-Host "[WARNING] Mock file generation returned code: $LASTEXITCODE" -ForegroundColor Yellow >> "%RUNNER%"
echo             } >> "%RUNNER%"
echo         } catch { >> "%RUNNER%"
echo             Write-Host "[WARNING] Could not generate mock files: $_" -ForegroundColor Yellow >> "%RUNNER%"
echo         } finally { >> "%RUNNER%"
echo             Pop-Location >> "%RUNNER%"
echo         } >> "%RUNNER%"
echo     } else { >> "%RUNNER%"
echo         Write-Host "[INFO] s.py not found - skipping mock file generation" -ForegroundColor Gray >> "%RUNNER%"
echo     } >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Host "[SKIP] Python not available - skipping mock file generation" -ForegroundColor Gray >> "%RUNNER%"
echo } >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Start simulator executable if present --- >> "%RUNNER%"
echo $simExe = Join-Path $TargetPath 'simulator.exe' >> "%RUNNER%"
echo if (Test-Path -LiteralPath $simExe) { >> "%RUNNER%"
echo     Write-Host "[SIMULATOR] Starting in new window..." -ForegroundColor Green >> "%RUNNER%"
echo     $simCmd = "Set-Location -LiteralPath '$TargetPath'; Write-Host '=== SIMULATOR STARTING ===' -ForegroundColor Cyan; ^& '.\simulator.exe'; Write-Host '=== SIMULATOR EXITED ===' -ForegroundColor Yellow; pause" >> "%RUNNER%"
echo     Start-Process -FilePath "powershell" -ArgumentList "-NoExit","-NoProfile","-ExecutionPolicy","Bypass","-Command",$simCmd >> "%RUNNER%"
echo     Start-Sleep -Seconds 1 >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Host "[WARNING] Simulator not found at: $simExe" -ForegroundColor Yellow >> "%RUNNER%"
echo     Write-Host "  Build may have failed. Check build output above." -ForegroundColor Gray >> "%RUNNER%"
echo } >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Install npm dependencies --- >> "%RUNNER%"
echo Set-Location -LiteralPath $display >> "%RUNNER%"
echo Write-Host "[NPM] Installing dependencies..." -ForegroundColor Cyan >> "%RUNNER%"
echo npm install >> "%RUNNER%"
echo if ($LASTEXITCODE -ne 0) { >> "%RUNNER%"
echo     Write-Host "[ERROR] npm install failed!" -ForegroundColor Red >> "%RUNNER%"
echo     Read-Host "Press Enter to exit" >> "%RUNNER%"
echo     exit 1 >> "%RUNNER%"
echo } >> "%RUNNER%"
echo Write-Host "[OK] Dependencies installed!" -ForegroundColor Green >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Check if ports are already in use --- >> "%RUNNER%"
echo Write-Host "[PORT CHECK] Checking if servers are already running..." -ForegroundColor Cyan >> "%RUNNER%"
echo $port3001 = Get-NetTCPConnection -LocalPort 3001 -ErrorAction SilentlyContinue >> "%RUNNER%"
echo $port5173 = Get-NetTCPConnection -LocalPort 5173 -ErrorAction SilentlyContinue >> "%RUNNER%"
echo if ($port3001 -or $port5173) { >> "%RUNNER%"
echo     Write-Host "" >> "%RUNNER%"
echo     Write-Host "===============================================" -ForegroundColor Yellow >> "%RUNNER%"
echo     Write-Host "  WARNING: Ports already in use!" -ForegroundColor Yellow >> "%RUNNER%"
echo     Write-Host "===============================================" -ForegroundColor Yellow >> "%RUNNER%"
echo     if ($port3001) { Write-Host "  Backend port 3001 is in use" -ForegroundColor Yellow } >> "%RUNNER%"
echo     if ($port5173) { Write-Host "  Frontend port 5173 is in use" -ForegroundColor Yellow } >> "%RUNNER%"
echo     Write-Host "" >> "%RUNNER%"
echo     Write-Host "The servers may already be running from a previous instance." -ForegroundColor White >> "%RUNNER%"
echo     Write-Host "Options:" -ForegroundColor Cyan >> "%RUNNER%"
echo     Write-Host "  1. Close the other PowerShell windows running the servers" -ForegroundColor Gray >> "%RUNNER%"
echo     Write-Host "  2. Or visit http://localhost:5173 in your browser now" -ForegroundColor Gray >> "%RUNNER%"
echo     Write-Host "" >> "%RUNNER%"
echo     $response = Read-Host "Continue anyway? (y/N)" >> "%RUNNER%"
echo     if ($response -ne 'y' -and $response -ne 'Y') { >> "%RUNNER%"
echo         Write-Host "Exiting. You can access the running servers at http://localhost:5173" -ForegroundColor Green >> "%RUNNER%"
echo         exit 0 >> "%RUNNER%"
echo     } >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Host "[OK] Ports are available" -ForegroundColor Green >> "%RUNNER%"
echo } >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Start dev servers --- >> "%RUNNER%"
echo Write-Host "[SERVERS] Starting development servers..." -ForegroundColor Yellow >> "%RUNNER%"
echo Write-Host "  This will start both backend and frontend servers" -ForegroundColor Gray >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo Start-Sleep -Seconds 2 >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Open browser --- >> "%RUNNER%"
echo try { >> "%RUNNER%"
echo     Start-Sleep -Seconds 1 >> "%RUNNER%"
echo     Start-Process "http://localhost:5173" >> "%RUNNER%"
echo     Write-Host "[OK] Browser opened to http://localhost:5173" -ForegroundColor Green >> "%RUNNER%"
echo } catch { >> "%RUNNER%"
echo     Write-Host "[INFO] Could not open browser automatically" -ForegroundColor Yellow >> "%RUNNER%"
echo     Write-Host "  Please navigate to: http://localhost:5173" -ForegroundColor Cyan >> "%RUNNER%"
echo } >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo Write-Host "===============================================" -ForegroundColor Cyan >> "%RUNNER%"
echo Write-Host "  Starting servers now..." -ForegroundColor Cyan >> "%RUNNER%"
echo Write-Host "  Keep this window open!" -ForegroundColor Yellow >> "%RUNNER%"
echo Write-Host "===============================================" -ForegroundColor Cyan >> "%RUNNER%"
echo Write-Host "" >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Run dev servers (this will block) --- >> "%RUNNER%"
echo npm run dev:all >> "%RUNNER%"

echo.
echo ===============================
echo [OK] PowerShell runner created!
echo ===============================
echo Starting setup in new window...
echo.
start "Suspicious Filename Detection Automata - Setup & Run" powershell -NoExit -NoProfile -ExecutionPolicy Bypass -File "%RUNNER%"
echo.
echo The setup is running in a separate PowerShell window.
echo Watch that window for progress and any errors.
echo.
echo This window can be closed.
echo ===============================
pause
exit /b 0