#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Builds the OneBigHead application in release mode.

.DESCRIPTION
    This script builds both the .NET backend and React frontend projects,
    then combines them into a single unified output directory ready for deployment.

.PARAMETER OutputPath
    The output directory for the build artifacts. Defaults to './publish'.

.PARAMETER SkipFrontend
    Skip building the frontend project.

.PARAMETER SkipBackend
    Skip building the backend project.

.PARAMETER Clean
    Clean output directories before building.

.EXAMPLE
    ./Build-Release.ps1
    
.EXAMPLE
    ./Build-Release.ps1 -OutputPath ./my-output -Clean
#>

param(
    [string]$OutputPath = "./publish",
    [switch]$SkipFrontend,
    [switch]$SkipBackend,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Get the repository root (parent of the build directory)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)

$BackendDir = Join-Path $RepoRoot "backend" "src" "backend"
$FrontendDir = Join-Path $RepoRoot "frontend"
$OutputDir = Join-Path $RepoRoot $OutputPath

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "OneBigHead Release Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Repository Root: $RepoRoot"
Write-Host "Output Directory: $OutputDir"
Write-Host ""

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning output directories..." -ForegroundColor Yellow
    
    if (Test-Path $OutputDir) {
        Remove-Item -Recurse -Force $OutputDir
    }
    
    $FrontendDist = Join-Path $FrontendDir "dist"
    if (Test-Path $FrontendDist) {
        Remove-Item -Recurse -Force $FrontendDist
    }
    
    Write-Host "Clean complete." -ForegroundColor Green
    Write-Host ""
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Build Frontend
if (-not $SkipFrontend) {
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "Building Frontend..." -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    
    Push-Location $FrontendDir
    try {
        # Install dependencies
        Write-Host "Installing npm dependencies..." -ForegroundColor Yellow
        npm ci
        if ($LASTEXITCODE -ne 0) {
            throw "npm ci failed with exit code $LASTEXITCODE"
        }
        
        # Build production bundle
        Write-Host "Building production bundle..." -ForegroundColor Yellow
        npm run build
        if ($LASTEXITCODE -ne 0) {
            throw "npm run build failed with exit code $LASTEXITCODE"
        }
        
        Write-Host "Frontend build complete." -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
    Write-Host ""
}

# Build Backend
if (-not $SkipBackend) {
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "Building Backend..." -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    
    Push-Location $BackendDir
    try {
        Write-Host "Publishing .NET application..." -ForegroundColor Yellow
        dotnet publish -c Release -o $OutputDir
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet publish failed with exit code $LASTEXITCODE"
        }
        
        Write-Host "Backend build complete." -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
    Write-Host ""
}

# Copy frontend assets to backend wwwroot
if (-not $SkipFrontend) {
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "Copying Frontend Assets..." -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    
    $FrontendDist = Join-Path $FrontendDir "dist"
    $WwwrootCollections = Join-Path $OutputDir "wwwroot" "collections"
    
    if (-not (Test-Path $WwwrootCollections)) {
        New-Item -ItemType Directory -Path $WwwrootCollections | Out-Null
    }
    
    Write-Host "Copying frontend build to $WwwrootCollections..." -ForegroundColor Yellow
    Copy-Item -Path (Join-Path $FrontendDist "*") -Destination $WwwrootCollections -Recurse -Force
    
    Write-Host "Frontend assets copied." -ForegroundColor Green
    Write-Host ""
}

Write-Host "========================================" -ForegroundColor Green
Write-Host "Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output directory: $OutputDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run the application:" -ForegroundColor Yellow
Write-Host "  cd $OutputDir"
Write-Host "  ./backend" -ForegroundColor White
Write-Host ""

