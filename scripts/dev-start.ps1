#!/usr/bin/env pwsh
# dev-start.ps1
# Development startup script for Windows
# Starts PostgreSQL, builds and tests, then launches backend and frontend

param(
    [switch]$ResetDatabase,
    [switch]$SkipTests,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
dev-start.ps1 - Development startup script

Usage: ./dev-start.ps1 [options]

Options:
    -ResetDatabase    Reset the database before starting
    -SkipTests        Skip running tests (faster startup)
    -Help             Show this help message

This script will:
    1. Start the PostgreSQL Docker container if not running
    2. Restore tools, run tests, and build backend (produces efbundle)
    3. Apply migrations (or reset database if requested)
    4. Start the backend (displays PID)
    5. Build and start the frontend dev server
"@
    exit 0
}

$ErrorActionPreference = "Stop"
$containerName = "onebighead-postgres"
$rootDir = Split-Path -Parent $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  OneBigHead Development Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check/Start PostgreSQL container
Write-Host "[1/5] Checking PostgreSQL container..." -ForegroundColor Yellow
$container = docker ps --filter "name=$containerName" --format "{{.Names}}" 2>$null
if ($container -ne $containerName) {
    Write-Host "      PostgreSQL not running. Starting via docker compose..." -ForegroundColor Cyan
    Push-Location $rootDir
    docker compose up -d
    Pop-Location
    
    # Wait for PostgreSQL to be ready
    Write-Host "      Waiting for PostgreSQL to be ready..." -ForegroundColor Cyan
    $retries = 30
    $ready = $false
    while ($retries -gt 0 -and -not $ready) {
        $health = docker inspect --format='{{.State.Health.Status}}' $containerName 2>$null
        if ($health -eq "healthy") {
            $ready = $true
        } else {
            Start-Sleep -Seconds 2
            $retries--
            Write-Host "      Waiting... ($retries retries left)" -ForegroundColor Gray
        }
    }
    
    if (-not $ready) {
        Write-Host "      Error: PostgreSQL did not become ready in time" -ForegroundColor Red
        exit 1
    }
    Write-Host "      PostgreSQL is ready!" -ForegroundColor Green
} else {
    Write-Host "      PostgreSQL is already running." -ForegroundColor Green
}

# Step 2: Restore tools, run tests, and build backend
Write-Host ""
Write-Host "[2/5] Building and testing backend..." -ForegroundColor Yellow

Write-Host "      Restoring tools..." -ForegroundColor Cyan
Push-Location $rootDir
dotnet tool restore --verbosity minimal
Pop-Location

Write-Host "      Restoring packages..." -ForegroundColor Cyan
Push-Location "$rootDir\backend\src\backend"
dotnet restore --verbosity minimal
if ($LASTEXITCODE -ne 0) {
    Write-Host "      Package restore failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location

if (-not $SkipTests) {
    Write-Host "      Running tests..." -ForegroundColor Cyan
    Push-Location "$rootDir\backend\tests\backend.tests"
    dotnet test --no-restore --verbosity minimal
    if ($LASTEXITCODE -ne 0) {
        Write-Host "      Backend tests failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    Pop-Location
    Write-Host "      Tests passed!" -ForegroundColor Green
} else {
    Write-Host "      Skipping tests (use without -SkipTests to run)" -ForegroundColor Gray
}

Write-Host "      Building backend..." -ForegroundColor Cyan
Push-Location "$rootDir\backend\src\backend"
dotnet build --no-restore --verbosity minimal
if ($LASTEXITCODE -ne 0) {
    Write-Host "      Backend build failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location
Write-Host "      Backend build succeeded!" -ForegroundColor Green

Write-Host "      Creating migration bundle..." -ForegroundColor Cyan
Push-Location "$rootDir\backend\src\backend"
dotnet ef migrations bundle --force --no-build
if ($LASTEXITCODE -ne 0) {
    Write-Host "      Migration bundle creation failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location
Write-Host "      Migration bundle created." -ForegroundColor Green

# Step 3: Apply migrations (or reset database if requested)
Write-Host ""
if ($ResetDatabase) {
    Write-Host "[3/5] Resetting database..." -ForegroundColor Yellow
    & "$rootDir\scripts\reset-database.ps1" -Force
    if ($LASTEXITCODE -ne 0) {
        Write-Host "      Database reset failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "      Database reset complete." -ForegroundColor Green
} else {
    Write-Host "[3/5] Applying pending migrations..." -ForegroundColor Yellow
    $efBundle = Join-Path $rootDir "backend\src\backend\efbundle.exe"
    if (Test-Path $efBundle) {
        & $efBundle --connection "Host=localhost;Port=5432;Database=onebighead;Username=postgres;Password=DevPassword123!"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "      Migration bundle failed!" -ForegroundColor Red
            exit 1
        }
        Write-Host "      Migrations applied." -ForegroundColor Green
    } else {
        Write-Host "      Warning: efbundle.exe not found." -ForegroundColor Yellow
    }
}

# Step 4: Start backend
Write-Host ""
Write-Host "[4/5] Starting backend..." -ForegroundColor Yellow
Push-Location "$rootDir\backend\src\backend"
$backendProcess = Start-Process -FilePath "dotnet" -ArgumentList "run", "--no-build" -PassThru -WindowStyle Normal
Pop-Location

Write-Host ""
Write-Host "      ┌─────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "      │  BACKEND PROCESS ID: $($backendProcess.Id.ToString().PadRight(17)) │" -ForegroundColor Cyan
Write-Host "      │  To stop: Stop-Process -Id $($backendProcess.Id.ToString().PadRight(10)) │" -ForegroundColor Cyan
Write-Host "      └─────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

# Give backend a moment to start
Write-Host "      Waiting for backend to initialize..." -ForegroundColor Gray
Start-Sleep -Seconds 3

# Step 5: Build and start frontend
Write-Host ""
Write-Host "[5/5] Building and starting frontend..." -ForegroundColor Yellow
Push-Location "$rootDir\frontend"

Write-Host "      Installing dependencies..." -ForegroundColor Cyan
npm install --silent
if ($LASTEXITCODE -ne 0) {
    Write-Host "      npm install failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}

Write-Host "      Starting Vite dev server..." -ForegroundColor Cyan
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Development environment ready!" -ForegroundColor Green
Write-Host "  Backend PID: $($backendProcess.Id)" -ForegroundColor Green
Write-Host "  Frontend: Starting below..." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# Run npm dev in the foreground so user can see output and Ctrl+C to stop
npm run dev

# When frontend stops, offer to stop backend
Pop-Location
Write-Host ""
Write-Host "Frontend stopped." -ForegroundColor Yellow
$stopBackend = Read-Host "Stop backend process $($backendProcess.Id)? (Y/n)"
if ($stopBackend -ne 'n' -and $stopBackend -ne 'N') {
    Stop-Process -Id $backendProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Host "Backend stopped." -ForegroundColor Green
} else {
    Write-Host "Backend still running (PID: $($backendProcess.Id))" -ForegroundColor Yellow
}
