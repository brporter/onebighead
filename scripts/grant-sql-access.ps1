#!/usr/bin/env pwsh
# grant-sql-access.ps1
# Grants the current Azure CLI user db_owner access to the production SQL database.
# Temporarily swaps the SQL AD admin, creates the user, then restores the original admin.
# This is a one-time setup — after running, you can connect to the database without being AD admin.

param(
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$ServerName,
    [Parameter(Mandatory)][string]$DatabaseName
)

$ErrorActionPreference = "Stop"

# Verify Azure CLI is logged in
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "Error: Not logged in to Azure CLI. Run 'az login' first." -ForegroundColor Red
    exit 1
}
Write-Host "Logged in as: $($account.user.name)" -ForegroundColor Cyan

# Step 1: Save current AD admin
Write-Host "Reading current SQL AD admin..." -ForegroundColor Cyan
$currentAdmin = az sql server ad-admin list --resource-group $ResourceGroup --server $ServerName 2>$null | ConvertFrom-Json
if (-not $currentAdmin -or $currentAdmin.Count -eq 0) {
    Write-Host "Error: No AD admin found on server '$ServerName'. Run the deploy script first." -ForegroundColor Red
    exit 1
}

$originalAdminName = $currentAdmin[0].login
$originalAdminObjectId = $currentAdmin[0].sid
Write-Host "Current AD admin: $originalAdminName ($originalAdminObjectId)" -ForegroundColor Gray

# Step 2: Get current user info
Write-Host "Getting current user identity..." -ForegroundColor Cyan
$currentUser = az ad signed-in-user show 2>$null | ConvertFrom-Json
if (-not $currentUser) {
    Write-Host "Error: Could not retrieve signed-in user. Ensure 'az login' was completed." -ForegroundColor Red
    exit 1
}

$myObjectId = $currentUser.id
$myDisplayName = $currentUser.displayName
$myUpn = $currentUser.userPrincipalName
if (-not $myUpn) {
    $myUpn = $currentUser.mail
}
if (-not $myUpn) {
    Write-Host "Error: Could not determine UPN or email for current user." -ForegroundColor Red
    exit 1
}
Write-Host "Your identity: $myDisplayName / $myUpn ($myObjectId)" -ForegroundColor Gray

# Step 3: Temporarily set current user as AD admin
Write-Host "Setting you as temporary SQL AD admin..." -ForegroundColor Cyan
az sql server ad-admin create `
    --resource-group $ResourceGroup `
    --server $ServerName `
    --display-name $myDisplayName `
    --object-id $myObjectId `
    --output none

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to set AD admin." -ForegroundColor Red
    exit 1
}

# Step 4: Create user with db_owner (wrapped in try/finally to ensure admin is restored)
$serverFqdn = "$ServerName.database.windows.net"
try {
    Write-Host "Creating database user and granting db_owner..." -ForegroundColor Cyan

    # Azure SQL requires UPN (email), not display name, for CREATE USER ... FROM EXTERNAL PROVIDER
    $escapedUpn = $myUpn -replace "'", "''"

    sqlcmd -S $serverFqdn `
        -d $DatabaseName `
        --authentication-method=ActiveDirectoryDefault `
        -b `
        -Q "
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N'$escapedUpn')
BEGIN
    CREATE USER [$myUpn] FROM EXTERNAL PROVIDER;
    PRINT 'User created.';
END
ELSE
    PRINT 'User already exists.';
ALTER ROLE db_owner ADD MEMBER [$myUpn];
PRINT 'db_owner role granted.';
"

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to create database user." -ForegroundColor Red
        exit 1
    }

    Write-Host "Database access granted." -ForegroundColor Green
}
finally {
    # Step 5: Restore original AD admin
    Write-Host "Restoring original SQL AD admin ($originalAdminName)..." -ForegroundColor Cyan
    az sql server ad-admin create `
        --resource-group $ResourceGroup `
        --server $ServerName `
        --display-name $originalAdminName `
        --object-id $originalAdminObjectId `
        --output none

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Warning: Failed to restore original AD admin. Restore manually:" -ForegroundColor Red
        Write-Host "  az sql server ad-admin create --resource-group $ResourceGroup --server $ServerName --display-name '$originalAdminName' --object-id $originalAdminObjectId" -ForegroundColor Yellow
    } else {
        Write-Host "Original AD admin restored." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Done. You can now connect to the database without being AD admin:" -ForegroundColor Green
Write-Host "  sqlcmd -S $serverFqdn -d $DatabaseName --authentication-method=ActiveDirectoryDefault" -ForegroundColor Gray
