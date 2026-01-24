#!/usr/bin/env pwsh
# reset-database.ps1
# Resets the local development database by dropping and recreating it.
# The database will be recreated automatically when the backend starts.

param(
    [switch]$Force
)

$containerName = "onebighead-sqlserver"
$databaseName = "onebighead"
$saPassword = "DevPassword123!"

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

$dropResult = docker exec $containerName /opt/mssql-tools18/bin/sqlcmd `
    -S localhost -U sa -P $saPassword -C `
    -Q "IF EXISTS (SELECT name FROM sys.databases WHERE name = N'$databaseName') BEGIN ALTER DATABASE [$databaseName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$databaseName]; END" 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Could not drop database (it may not exist yet)" -ForegroundColor Yellow
} else {
    Write-Host "Database dropped successfully." -ForegroundColor Green
}

Write-Host ""
Write-Host "Database reset complete." -ForegroundColor Green
Write-Host "Run 'dotnet run' in the backend folder to recreate the database with fresh migrations." -ForegroundColor Cyan
