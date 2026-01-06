@echo off
REM Build script for Windows
REM Builds both the .NET backend and React frontend projects,
REM then combines them into a single unified output directory.

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "REPO_ROOT=%SCRIPT_DIR%.."

set "OUTPUT_PATH=publish"
set "SKIP_FRONTEND=0"
set "SKIP_BACKEND=0"
set "CLEAN=0"

REM Parse arguments
:parse_args
if "%~1"=="" goto :end_parse
if /i "%~1"=="-o" (
    set "OUTPUT_PATH=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--output" (
    set "OUTPUT_PATH=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--skip-frontend" (
    set "SKIP_FRONTEND=1"
    shift
    goto :parse_args
)
if /i "%~1"=="--skip-backend" (
    set "SKIP_BACKEND=1"
    shift
    goto :parse_args
)
if /i "%~1"=="-c" (
    set "CLEAN=1"
    shift
    goto :parse_args
)
if /i "%~1"=="--clean" (
    set "CLEAN=1"
    shift
    goto :parse_args
)
if /i "%~1"=="-h" goto :show_help
if /i "%~1"=="--help" goto :show_help
echo Unknown option: %~1
exit /b 1
:end_parse

set "BACKEND_DIR=%REPO_ROOT%\backend"
set "FRONTEND_DIR=%REPO_ROOT%\frontend"
set "OUTPUT_DIR=%REPO_ROOT%\%OUTPUT_PATH%"

echo ========================================
echo OneBigHead Release Build
echo ========================================
echo.
echo Repository Root: %REPO_ROOT%
echo Output Directory: %OUTPUT_DIR%
echo.

REM Clean if requested
if "%CLEAN%"=="1" (
    echo Cleaning output directories...
    
    if exist "%OUTPUT_DIR%" (
        rmdir /s /q "%OUTPUT_DIR%"
    )
    
    if exist "%FRONTEND_DIR%\dist" (
        rmdir /s /q "%FRONTEND_DIR%\dist"
    )
    
    echo Clean complete.
    echo.
)

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM Build Frontend
if "%SKIP_FRONTEND%"=="0" (
    echo ----------------------------------------
    echo Building Frontend...
    echo ----------------------------------------
    
    pushd "%FRONTEND_DIR%"
    
    echo Installing npm dependencies...
    call npm ci
    if errorlevel 1 (
        echo npm ci failed
        popd
        exit /b 1
    )
    
    echo Building production bundle...
    call npm run build
    if errorlevel 1 (
        echo npm run build failed
        popd
        exit /b 1
    )
    
    echo Frontend build complete.
    echo.
    
    popd
)

REM Build Backend
if "%SKIP_BACKEND%"=="0" (
    echo ----------------------------------------
    echo Building Backend...
    echo ----------------------------------------
    
    pushd "%BACKEND_DIR%"
    
    echo Publishing .NET application...
    dotnet publish -c Release -o "%OUTPUT_DIR%"
    if errorlevel 1 (
        echo dotnet publish failed
        popd
        exit /b 1
    )
    
    echo Backend build complete.
    echo.
    
    popd
)

REM Copy frontend assets to backend wwwroot
if "%SKIP_FRONTEND%"=="0" (
    echo ----------------------------------------
    echo Copying Frontend Assets...
    echo ----------------------------------------
    
    set "FRONTEND_DIST=%FRONTEND_DIR%\dist"
    set "WWWROOT_COLLECTIONS=%OUTPUT_DIR%\wwwroot\collections"
    
    if not exist "!WWWROOT_COLLECTIONS!" mkdir "!WWWROOT_COLLECTIONS!"
    
    echo Copying frontend build to !WWWROOT_COLLECTIONS!...
    xcopy /s /e /y "!FRONTEND_DIST!\*" "!WWWROOT_COLLECTIONS!\"
    
    echo Frontend assets copied.
    echo.
)

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Output directory: %OUTPUT_DIR%
echo.
echo To run the application:
echo   cd %OUTPUT_DIR%
echo   backend.exe
echo.

exit /b 0

:show_help
echo Usage: %~nx0 [options]
echo.
echo Options:
echo   -o, --output PATH    Output directory (default: publish)
echo   --skip-frontend      Skip building the frontend
echo   --skip-backend       Skip building the backend
echo   -c, --clean          Clean output directories before building
echo   -h, --help           Show this help message
exit /b 0

