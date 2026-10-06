#!/usr/bin/env pwsh
# PowerShell 7.3+ propagates native command failures with these preferences.
#Requires -Version 7.3
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    dotnet restore onebighead.slnx
    dotnet test backend/tests/backend.tests/backend.tests.csproj --no-restore --verbosity minimal
    Set-Location frontend
    npm ci
    npm run typecheck
    npm run lint
    npm run test:run
    npm run build
}
finally {
    Pop-Location
}
