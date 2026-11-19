@echo off
setlocal EnableDelayedExpansion

REM ====================================================================
REM run.bat - Windows launcher for VulnFlow AI Engine & Control Plane
REM ====================================================================

REM Resolve script and repo directories
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "ORIGINAL_CD=%CD%"
set "VULNFLOW_ROOT=%SCRIPT_DIR%"

if exist "%VULNFLOW_ROOT%\vulnflow" (
  set "VULNFLOW_ROOT=%VULNFLOW_ROOT%\vulnflow"
)

REM Detect python executable (prefer python, fallback to py -3, py, or python3)
set "PYTHON_CMD="
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
  set "PYTHON_CMD=python"
) else (
  where py >nul 2>&1
  if %ERRORLEVEL% EQU 0 (
    set "PYTHON_CMD=py -3"
  ) else (
    where python3 >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
      set "PYTHON_CMD=python3"
    ) else (
      echo [ERROR] Python 3.11+ was not found in PATH.
      echo Please install Python from https://www.python.org/downloads/
      exit /b 1
    )
  )
)

REM Configure PYTHONPATH
set "PYTHONPATH=%VULNFLOW_ROOT%\src;%VULNFLOW_ROOT%;%PYTHONPATH%"

set "ACTION=%~1"
if "%ACTION%"=="" (
  cd /d "%ORIGINAL_CD%"
  %PYTHON_CMD% "%VULNFLOW_ROOT%\src\vulnflow\cli.py"
  exit /b %ERRORLEVEL%
)

if /I "%ACTION%"=="help" goto do_help
if /I "%ACTION%"=="-h" goto do_help
if /I "%ACTION%"=="--help" goto do_help
if /I "%ACTION%"=="install" goto do_install
if /I "%ACTION%"=="serve" goto do_serve
if /I "%ACTION%"=="dev" goto do_dev
if /I "%ACTION%"=="build" goto do_build
if /I "%ACTION%"=="docker" goto do_docker
if /I "%ACTION%"=="docker-compose" goto do_compose
if /I "%ACTION%"=="compose" goto do_compose

REM Default / CLI command (scan, report, fix, verify, approve, audit, etc.)
cd /d "%ORIGINAL_CD%"
%PYTHON_CMD% "%VULNFLOW_ROOT%\src\vulnflow\cli.py" %*
exit /b %ERRORLEVEL%

:do_serve
echo ====================================================================
echo  VulnFlow AI - Autonomous Security Remediation Platform
echo ====================================================================
cd /d "%VULNFLOW_ROOT%"
if not exist "%VULNFLOW_ROOT%\ui\dist\index.html" (
  echo [*] First-time run: Building frontend Web Dashboard...
  cd /d "%VULNFLOW_ROOT%\ui"
  call npm run build
  echo [OK] Frontend built successfully.
  cd /d "%VULNFLOW_ROOT%"
)
shift
%PYTHON_CMD% "%VULNFLOW_ROOT%\src\vulnflow\cli.py" serve --open %*
exit /b %ERRORLEVEL%

:do_dev
echo ====================================================================
echo  VulnFlow AI - Development Mode (Vite HMR on :5173 + API on :8000)
echo ====================================================================
cd /d "%VULNFLOW_ROOT%"
shift
%PYTHON_CMD% "%VULNFLOW_ROOT%\src\vulnflow\cli.py" serve --dev %*
exit /b %ERRORLEVEL%

:do_build
echo ====================================================================
echo  Building frontend UI bundle (Vite + React)...
echo ====================================================================
cd /d "%VULNFLOW_ROOT%\ui"
call npm run build
echo [OK] Frontend build complete in ui\dist\
exit /b %ERRORLEVEL%

:do_docker
echo ====================================================================
echo  Building and running VulnFlow Docker container...
echo ====================================================================
cd /d "%VULNFLOW_ROOT%"
docker build -t vulnflow:latest "%VULNFLOW_ROOT%"
docker run --rm -it -p 8000:8000 -v "%VULNFLOW_ROOT%\.vulnflow:/app/.vulnflow" vulnflow:latest
exit /b %ERRORLEVEL%

:do_compose
cd /d "%VULNFLOW_ROOT%"
docker compose -f "%VULNFLOW_ROOT%\docker-compose.yml" up --build
exit /b %ERRORLEVEL%

:do_install
echo ====================================================================
echo  Installing VulnFlow CLI for Windows...
echo ====================================================================
set "INSTALL_DIR=%USERPROFILE%\.local\bin"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
(
  echo @echo off
  echo call "%SCRIPT_DIR%\run.bat" %%*
) > "%INSTALL_DIR%\vulnflow.cmd"
echo [OK] Created %INSTALL_DIR%\vulnflow.cmd
echo.
REM Check if USERPROFILE\.local\bin is in PATH
echo %PATH% | findstr /I /C:"%INSTALL_DIR%" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo [NOTICE] %INSTALL_DIR% is not yet in your PATH.
  echo To add it permanently, run this in PowerShell:
  echo   [Environment]::SetEnvironmentVariable^('Path', $env:Path + ';%INSTALL_DIR%', 'User'^)
  echo.
)
echo You can now run 'vulnflow' from any directory in CMD or PowerShell!
echo Examples:
echo   vulnflow scan --repo fake-vuln-repo --mode report
echo   vulnflow serve
echo   vulnflow --help
echo.
exit /b 0

:do_help
cd /d "%ORIGINAL_CD%"
%PYTHON_CMD% "%VULNFLOW_ROOT%\src\vulnflow\cli.py" --help
exit /b %ERRORLEVEL%
