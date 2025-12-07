@echo off
REM RUN EVERYTHING — CLONE / INSTALL / RUN SERVERS / OPEN UI

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

echo Script running from: %SCRIPT_DIR%

REM --------------------------
REM CHECK GIT
REM --------------------------
where git >nul 2>nul || (
    echo ERROR: Git NOT FOUND. Install Git and try again.
    pause
    exit /b
)

REM --------------------------
REM CHECK NODE and NPM
REM --------------------------
where node >nul 2>nul || (
    echo ERROR: Node.js NOT FOUND. Install Node.js and try again.
    pause
    exit /b
)

where npm >nul 2>nul || (
    echo ERROR: NPM NOT FOUND. Install Node.js and try again.
    pause
    exit /b
)

REM --------------------------
REM CLONE IF DO NOT EXIST
REM --------------------------
REM Compute parent directory and detect if this script is inside a `scripts\` folder
for %%I in ("%SCRIPT_DIR:~0,-1%") do set "SCRIPT_FOLDER_NAME=%%~nI"
for %%I in ("%SCRIPT_DIR%..") do set "PARENT_DIR=%%~fI\"

if /I "%SCRIPT_FOLDER_NAME%"=="scripts" (
    set "BASE_DIR=%PARENT_DIR%"
) else (
    set "BASE_DIR=%SCRIPT_DIR%"
)

echo Script folder: %SCRIPT_FOLDER_NAME%
echo Using base directory: %BASE_DIR%

REM If no special flag, jump to runner creation which opens a single PowerShell window
if not "%1"=="--inline" goto :create_runner

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
            exit /b
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
        exit /b
    )
    popd
) else (
    echo ERROR: package.json NOT FOUND — something is wrong.
    pause
    exit /b
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

:create_runner
set "RUNNER=%SCRIPT_DIR%run-and-log.ps1"
if exist "%RUNNER%" del /f /q "%RUNNER%" >nul 2>&1


echo Write-Host "Runner starting..." -ForegroundColor Cyan > "%RUNNER%"
echo $ErrorActionPreference = 'Stop' >> "%RUNNER%"
echo $RepoUrl = '%REPO_URL%' >> "%RUNNER%"
echo $BaseDir = '%BASE_DIR%' >> "%RUNNER%"
echo $RepoFolder = '%REPO_FOLDER%' >> "%RUNNER%"
echo $TargetPath = Join-Path $BaseDir $RepoFolder >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Clone repository if needed --- >> "%RUNNER%"
echo if (-not (Test-Path -LiteralPath $TargetPath)) { >> "%RUNNER%"
echo     Write-Host "Cloning $RepoUrl into $TargetPath" -ForegroundColor Yellow >> "%RUNNER%"
echo     git clone $RepoUrl $TargetPath >> "%RUNNER%"
echo     if ($LASTEXITCODE -ne 0) { >> "%RUNNER%"
echo         Write-Error "Git clone failed!" >> "%RUNNER%"
echo         exit 1 >> "%RUNNER%"
echo     } >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Host "Repository already exists at $TargetPath" -ForegroundColor Green >> "%RUNNER%"
echo } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo $display = Join-Path $TargetPath 'display' >> "%RUNNER%"
echo if (-not (Test-Path -LiteralPath $display)) { >> "%RUNNER%"
echo     Write-Error "Expected frontend directory not found: $display" >> "%RUNNER%"
echo     exit 1 >> "%RUNNER%"
echo } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Build native simulator if build script exists --- >> "%RUNNER%"
echo $scriptsFolder = Join-Path $TargetPath '.scripts' >> "%RUNNER%"
echo $buildScript = Join-Path $scriptsFolder 'build.ps1' >> "%RUNNER%"
echo Write-Host "Looking for build script at: $buildScript" -ForegroundColor Cyan >> "%RUNNER%"
echo if (Test-Path -LiteralPath $buildScript) { >> "%RUNNER%"
echo     Write-Host "Found build script -- running build..." -ForegroundColor Yellow >> "%RUNNER%"
echo     Push-Location -LiteralPath $TargetPath >> "%RUNNER%"
echo     try { >> "%RUNNER%"
echo         ^& $buildScript >> "%RUNNER%"
echo         if ($LASTEXITCODE -ne 0) { >> "%RUNNER%"
echo             Write-Warning "Build script returned non-zero exit code: $LASTEXITCODE" >> "%RUNNER%"
echo         } else { >> "%RUNNER%"
echo             Write-Host "Build completed successfully!" -ForegroundColor Green >> "%RUNNER%"
echo         } >> "%RUNNER%"
echo     } catch { >> "%RUNNER%"
echo         Write-Error "Build failed with error: $_" >> "%RUNNER%"
echo     } finally { >> "%RUNNER%"
echo         Pop-Location >> "%RUNNER%"
echo     } >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Warning "No build script found at $buildScript -- skipping native build." >> "%RUNNER%"
echo     Write-Host "Expected path: $buildScript" -ForegroundColor Red >> "%RUNNER%"
echo } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Wait a moment for build to complete --- >> "%RUNNER%"
echo Start-Sleep -Seconds 2 >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Generate mock test files --- >> "%RUNNER%"
echo $mockScript = Join-Path $TargetPath 's.py' >> "%RUNNER%"
echo if (Test-Path -LiteralPath $mockScript) { >> "%RUNNER%"
echo     Write-Host "Found s.py - Generating mock test files..." -ForegroundColor Cyan >> "%RUNNER%"
echo     try { >> "%RUNNER%"
echo         Push-Location -LiteralPath $TargetPath >> "%RUNNER%"
echo         $mockOutput = "2" ^| python s.py 2^>^&1 >> "%RUNNER%"
echo         Write-Host $mockOutput >> "%RUNNER%"
echo         Write-Host "Mock files generated successfully!" -ForegroundColor Green >> "%RUNNER%"
echo     } catch { >> "%RUNNER%"
echo         Write-Warning "Could not generate mock files: $_" >> "%RUNNER%"
echo     } finally { >> "%RUNNER%"
echo         Pop-Location >> "%RUNNER%"
echo     } >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Host "s.py not found - skipping mock file generation" -ForegroundColor Yellow >> "%RUNNER%"
echo } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Start simulator executable if present --- >> "%RUNNER%"
echo $simExe = Join-Path $TargetPath 'simulator.exe' >> "%RUNNER%"
echo Write-Host "Looking for simulator at: $simExe" -ForegroundColor Cyan >> "%RUNNER%"
echo if (Test-Path -LiteralPath $simExe) { >> "%RUNNER%"
echo     Write-Host "Starting simulator executable in new window..." -ForegroundColor Green >> "%RUNNER%"
echo     $simCmd = "Set-Location -LiteralPath '$TargetPath'; Write-Host 'Starting simulator...' -ForegroundColor Green; ^& '.\simulator.exe'; Write-Host 'Simulator exited.' -ForegroundColor Yellow; pause" >> "%RUNNER%"
echo     Start-Process -FilePath "powershell" -ArgumentList "-NoExit","-NoProfile","-ExecutionPolicy","Bypass","-Command",$simCmd >> "%RUNNER%"
echo } else { >> "%RUNNER%"
echo     Write-Warning "Simulator executable not found at $simExe" >> "%RUNNER%"
echo     Write-Host "Build may have failed. Check the build output above." -ForegroundColor Red >> "%RUNNER%"
echo } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Install npm dependencies --- >> "%RUNNER%"
echo Set-Location -LiteralPath $display >> "%RUNNER%"
echo Write-Host "Running npm install in display folder..." -ForegroundColor Cyan >> "%RUNNER%"
echo npm install >> "%RUNNER%"
echo if ($LASTEXITCODE -ne 0) { >> "%RUNNER%"
echo     Write-Error "npm install failed!" >> "%RUNNER%"
echo     exit 1 >> "%RUNNER%"
echo } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo # --- Start dev servers --- >> "%RUNNER%"
echo Write-Host "Starting dev servers (npm run dev:all)" -ForegroundColor Yellow >> "%RUNNER%"
echo Start-Sleep -Seconds 3 >> "%RUNNER%"
echo try { >> "%RUNNER%"
echo     Start-Process "http://localhost:5173" >> "%RUNNER%"
echo     Write-Host "Browser should open to http://localhost:5173" -ForegroundColor Green >> "%RUNNER%"
echo } catch { >> "%RUNNER%"
echo     Write-Warning "Could not open browser automatically. Please navigate to http://localhost:5173" >> "%RUNNER%"
echo } >> "%RUNNER%"
echo. >> "%RUNNER%"
echo Write-Host "Starting development servers..." -ForegroundColor Cyan >> "%RUNNER%"
echo npm run dev:all >> "%RUNNER%"

echo.
echo ===============================
echo Creating PowerShell runner...
echo ===============================
echo Starting the runner PowerShell window...
start "Setup & Run" powershell -NoExit -NoProfile -ExecutionPolicy Bypass -File "%RUNNER%"
echo.
echo The setup is running in a new PowerShell window.
echo Watch that window for build progress and any errors.
echo ===============================
pause
exit /b 0