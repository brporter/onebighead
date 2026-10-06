#!/usr/bin/env pwsh
#Requires -Version 7.3
param([switch]$ResetDatabase, [switch]$SkipTests, [switch]$Help)
if ($Help) {
    Write-Host 'Usage: ./scripts/dev-start.ps1 [-ResetDatabase] [-SkipTests]'
    Write-Host 'Requires .NET 10, Node 22+, Docker, and PowerShell 7.3+. Ctrl+C stops both servers.'
    exit 0
}
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$repoRoot = Split-Path -Parent $PSScriptRoot
$backendProcess = $null
Push-Location $repoRoot
try {
    docker compose up --wait --wait-timeout 60 postgres
    dotnet tool restore
    if (-not $SkipTests) {
        & "$PSScriptRoot/verify.ps1"
    } else {
        dotnet restore onebighead.slnx
        Push-Location frontend
        try { npm ci } finally { Pop-Location }
    }
    dotnet build backend/src/backend --no-restore --verbosity minimal
    Set-Location backend/src/backend
    if ($ResetDatabase) {
        & "$PSScriptRoot/reset-database.ps1" -Force
    } else {
        $previousEnvironment = $env:ASPNETCORE_ENVIRONMENT
        try {
            $env:ASPNETCORE_ENVIRONMENT = 'Development'
            dotnet ef database update --no-build
        } finally {
            $env:ASPNETCORE_ENVIRONMENT = $previousEnvironment
        }
        dotnet run --no-build -- --seed
    }
    $backendProcess = Start-Process dotnet -ArgumentList 'run', '--no-build' -PassThru -NoNewWindow
    Set-Location "$repoRoot/frontend"
    Write-Host "Backend PID: $($backendProcess.Id). Frontend: http://localhost:5173"
    npm run dev
} finally {
    if ($backendProcess -and -not $backendProcess.HasExited) {
        Stop-Process -Id $backendProcess.Id -ErrorAction SilentlyContinue
    }
    Pop-Location
}
