#!/usr/bin/env pwsh
# reset-database.ps1
# Resets the local development database by dropping it, applying migrations via efbundle, and seeding.

param(
    [switch]$Force
)

$containerName = "onebighead-sqlserver"
$databaseName = "onebighead"
$saPassword = "DevPassword123!"
$rootDir = Split-Path -Parent $PSScriptRoot

# Check if container is running
$container = docker ps --filter "name=$containerName" --format "{{.Names}}" 2>$null
if ($container -ne $containerName) {
    Write-Host "Error: SQL Server container '$containerName' is not running." -ForegroundColor Red
    Write-Host "Start it with: docker compose up -d" -ForegroundColor Yellow
    exit 1
}

if (-not $Force) {
    $confirmation = Read-Host "This will delete all data in the '$databaseName' database. Continue? (y/N)"
    if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "Dropping database '$databaseName'..." -ForegroundColor Cyan

$dropResult = docker exec $containerName sqlcmd `
    -S localhost -U sa -P $saPassword -C `
    -Q "IF EXISTS (SELECT name FROM sys.databases WHERE name = N'$databaseName') BEGIN ALTER DATABASE [$databaseName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$databaseName]; END" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Could not drop database (it may not exist yet)" -ForegroundColor Yellow
} else {
    Write-Host "Database dropped successfully." -ForegroundColor Green
}

# Build and apply migrations via efbundle
$backendProject = Join-Path $rootDir "backend\src\backend\backend.csproj"
$efBundle = Join-Path $rootDir "backend\src\backend\efbundle.exe"

Write-Host "Building migration bundle..." -ForegroundColor Cyan
dotnet ef migrations bundle --project $backendProject --force --output $efBundle --no-build 2>$null
if ($LASTEXITCODE -ne 0) {
    dotnet ef migrations bundle --project $backendProject --force --output $efBundle
}

if (Test-Path $efBundle) {
    Write-Host "Applying migrations..." -ForegroundColor Cyan
    & $efBundle --connection "Server=localhost,1433;Database=onebighead;User Id=sa;Password=$saPassword;TrustServerCertificate=True"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Migration bundle failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "Migrations applied successfully." -ForegroundColor Green
} else {
    Write-Host "Error: Failed to create migration bundle." -ForegroundColor Red
    exit 1
}

# Seed database
$connectionString = "Server=localhost,1433;Database=onebighead;User Id=sa;Password=$saPassword;TrustServerCertificate=True"
$seedsPath = Join-Path $rootDir "backend\seeds"
$dbseedProject = Join-Path $rootDir "backend\tools\dbseed\dbseed.csproj"
if (Test-Path $dbseedProject) {
    Write-Host "Seeding database..." -ForegroundColor Cyan
    $env:ConnectionStrings__DefaultConnection = $connectionString
    dotnet run --project $dbseedProject -- $seedsPath --force
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Database seeding failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "Database seeded successfully." -ForegroundColor Green
} else {
    Write-Host "Warning: dbseed project not found at $dbseedProject" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Database reset complete." -ForegroundColor Green
