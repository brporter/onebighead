#Requires -Version 7.0
<#
.SYNOPSIS
    Provision OneBigHead Azure infrastructure via Bicep.

.DESCRIPTION
    This script handles ONLY infrastructure provisioning and SQL identity setup.
    Application deployment (build, push, secrets, revisions) is handled by the
    GitHub Actions workflow (.github/workflows/deploy.yml).

.PARAMETER Name
    Base name for Azure resources (3-16 chars).

.PARAMETER Location
    Azure region (e.g., eastus).

.PARAMETER SkipInfra
    Skip Bicep provisioning (re-read outputs, re-run SQL user).

.PARAMETER GrafanaLocation
    Azure region for Grafana (defaults to Location). Not all regions support Grafana.

.PARAMETER SkipApp
    Skip Container App resource in Bicep (for infra-only re-runs).

.EXAMPLE
    ./deploy.ps1 -Name onebighead -Location northcentralus

.EXAMPLE
    ./deploy.ps1 -Name onebighead -Location northcentralus -GrafanaLocation eastus
#>

param(
    [Parameter(Mandatory)]
    [ValidateLength(3, 16)]
    [string]$Name,

    [Parameter(Mandatory)]
    [string]$Location,

    [string]$GrafanaLocation,

    [switch]$SkipInfra,
    [switch]$SkipApp
)

$ErrorActionPreference = 'Stop'

$ResourceGroup = "$Name-rg"
$DeploymentName = "$Name-infra"
$ScriptDir = $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "OneBigHead Infrastructure Provisioning" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:"
Write-Host "  App Name:        $Name"
Write-Host "  Location:        $Location"
Write-Host "  Resource Group:  $ResourceGroup"
Write-Host ""

# ============================================
# Step 1: Provision Infrastructure (Bicep)
# ============================================
Write-Host "----------------------------------------" -ForegroundColor Cyan
Write-Host "Step 1: Provisioning Infrastructure" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Cyan

if (-not $SkipInfra) {
    Write-Host "Looking up current user's Entra ID..." -ForegroundColor Yellow
    $SqlAdAdminObjectId = az ad signed-in-user show --query id -o tsv
    $SqlAdAdminDisplayName = az ad signed-in-user show --query userPrincipalName -o tsv
    Write-Host "  SQL AD Admin: $SqlAdAdminDisplayName ($SqlAdAdminObjectId)"

    $BicepParams = @(
        "appName=$Name"
        "location=$Location"
        "sqlAdAdminObjectId=$SqlAdAdminObjectId"
        "sqlAdAdminDisplayName=$SqlAdAdminDisplayName"
    )

    if ($GrafanaLocation) {
        $BicepParams += "grafanaLocation=$GrafanaLocation"
    }

    # Skip role assignments on re-runs (they error with RoleAssignmentExists)
    $RgExists = az group exists --name $ResourceGroup
    if ($RgExists -eq 'true') {
        $BicepParams += "skipRoleAssignments=true"
        Write-Host "  Resource group already exists — skipping role assignments." -ForegroundColor Yellow
    }

    if ($SkipApp) {
        $BicepParams += "deployContainerApp=false"
        Write-Host "Container App will be skipped (-SkipApp)." -ForegroundColor Yellow
    }

    Write-Host "Deploying Bicep template..." -ForegroundColor Yellow
    $DeployOutput = az deployment sub create `
        --name $DeploymentName `
        --location $Location `
        --template-file "$ScriptDir/infra/main.bicep" `
        --parameters @BicepParams `
        --output none 2>&1 | Out-String

    if ($LASTEXITCODE -ne 0) {
        # Parse error codes from the deployment output, ignoring wrapper codes
        $WrapperCodes = 'DeploymentFailed', 'ResourceDeploymentFailure'
        $ErrorCodes = [regex]::Matches($DeployOutput, '"code"\s*:\s*"([^"]+)"') |
            ForEach-Object { $_.Groups[1].Value } |
            Where-Object { $_ -notin $WrapperCodes } |
            Select-Object -Unique

        # RoleAssignmentExists is safe to ignore on re-runs (Azure role assignments aren't idempotent)
        if ($ErrorCodes.Count -gt 0 -and ($ErrorCodes | Where-Object { $_ -ne 'RoleAssignmentExists' }).Count -eq 0) {
            Write-Host "  Role assignments already exist (safe to ignore on re-runs)." -ForegroundColor Yellow
        } else {
            Write-Host $DeployOutput -ForegroundColor Red
            throw "Bicep deployment failed"
        }
    }
    Write-Host "Infrastructure provisioned." -ForegroundColor Green
}
else {
    Write-Host "Skipping infrastructure provisioning (-SkipInfra)." -ForegroundColor Yellow
}
Write-Host ""

# ============================================
# Step 2: Read Deployment Outputs
# ============================================
Write-Host "----------------------------------------" -ForegroundColor Cyan
Write-Host "Step 2: Reading Deployment Outputs" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Cyan

$OutputsJson = az deployment sub show `
    --name $DeploymentName `
    --query "properties.outputs" -o json

if ($LASTEXITCODE -ne 0) { throw "Failed to read deployment outputs" }

$Outputs = $OutputsJson | ConvertFrom-Json

$AcrLoginServer = $Outputs.acrLoginServer.value
$AcrName = $Outputs.acrName.value
$SqlServerName = $Outputs.sqlServerName.value
$SqlServerFqdn = $Outputs.sqlServerFqdn.value
$SqlDbName = $Outputs.sqlDatabaseName.value
$IdentityName = $Outputs.identityName.value
$IdentityClientId = $Outputs.identityClientId.value
$IdentityId = $Outputs.identityId.value
$ContainerEnvName = $Outputs.containerEnvName.value
$AppInsightsConnectionString = $Outputs.appInsightsConnectionString.value
$GrafanaEndpoint = $Outputs.grafanaEndpoint.value
$ContainerAppName = $Outputs.containerAppName.value
$ContainerAppFqdn = $Outputs.containerAppFqdn.value

# Validate critical outputs before proceeding to Step 3
if (-not $SqlServerName -or -not $SqlServerFqdn -or -not $IdentityName -or -not $SqlDbName) {
    throw "Deployment outputs are empty — the Bicep deployment may have failed. Check the Azure portal for details."
}

Write-Host "  ACR:             $AcrLoginServer"
Write-Host "  SQL Server:      $SqlServerName"
Write-Host "  Identity:        $IdentityName ($IdentityClientId)"
Write-Host "  Container App:   $(if ($ContainerAppName) { $ContainerAppName } else { 'not deployed' })"
Write-Host ""

# ============================================
# Step 3: Configure SQL Managed Identity User
# ============================================
Write-Host "----------------------------------------" -ForegroundColor Cyan
Write-Host "Step 3: Configuring SQL Managed Identity User" -ForegroundColor Cyan
Write-Host "----------------------------------------" -ForegroundColor Cyan

Write-Host "Adding current IP to SQL Server firewall..." -ForegroundColor Yellow
$CurrentIp = (Invoke-RestMethod -Uri "https://api.ipify.org" -UseBasicParsing).Trim()
$FirewallRuleName = "DeploymentClient-$(Get-Date -Format 'yyyyMMddHHmmss')"
az sql server firewall-rule create `
    --resource-group $ResourceGroup `
    --server $SqlServerName `
    --name $FirewallRuleName `
    --start-ip-address $CurrentIp `
    --end-ip-address $CurrentIp `
    --output none

if ($LASTEXITCODE -ne 0) { throw "Failed to create firewall rule" }

Write-Host "Creating SQL user for managed identity..." -ForegroundColor Yellow
$SqlCmd = @"
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = '$IdentityName')
BEGIN
    CREATE USER [$IdentityName] FROM EXTERNAL PROVIDER;
END
ALTER ROLE db_datareader ADD MEMBER [$IdentityName];
ALTER ROLE db_datawriter ADD MEMBER [$IdentityName];
ALTER ROLE db_ddladmin ADD MEMBER [$IdentityName];
PRINT 'User $IdentityName configured successfully';
"@

sqlcmd -S $SqlServerFqdn `
    -d $SqlDbName `
    --authentication-method=ActiveDirectoryDefault `
    -Q $SqlCmd

if ($LASTEXITCODE -ne 0) { throw "Failed to create SQL user" }

Write-Host "Removing temporary firewall rule..." -ForegroundColor Yellow
az sql server firewall-rule delete `
    --resource-group $ResourceGroup `
    --server $SqlServerName `
    --name $FirewallRuleName `
    --output none 2>$null

Write-Host "SQL access configured." -ForegroundColor Green
Write-Host ""

# ============================================
# Step 4: Summary
# ============================================
Write-Host "========================================" -ForegroundColor Green
Write-Host "Infrastructure Provisioning Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Resources:"
Write-Host "  Resource Group:    $ResourceGroup"
Write-Host "  Container Registry: $AcrName ($AcrLoginServer)"
Write-Host "  SQL Server:        $SqlServerName"
Write-Host "  Database:          $SqlDbName"
Write-Host "  Managed Identity:  $IdentityName"
Write-Host "  Container Env:     $ContainerEnvName"
Write-Host "  App Insights:      $Name-appinsights"
Write-Host "  Grafana:           $Name-grafana ($GrafanaEndpoint)"
if ($ContainerAppName) {
    Write-Host "  Container App:     $ContainerAppName (https://$ContainerAppFqdn)"
}
Write-Host ""

# Try to get tenant and subscription IDs for the guide
$TenantId = az account show --query tenantId -o tsv 2>$null
if (-not $TenantId) { $TenantId = "<your-tenant-id>" }
$SubscriptionId = az account show --query id -o tsv 2>$null
if (-not $SubscriptionId) { $SubscriptionId = "<your-subscription-id>" }

Write-Host "Next: Configure GitHub Actions" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Create a service principal with Contributor access:"
Write-Host ""
Write-Host "   az ad sp create-for-rbac ``"
Write-Host "     --name `"$Name-github-actions`" ``"
Write-Host "     --role Contributor ``"
Write-Host "     --scopes /subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
Write-Host ""
Write-Host "2. Configure the service principal as SQL AD admin:"
Write-Host ""
Write-Host "   `$SpObjectId = az ad sp show --id <clientId-from-step-1> --query id -o tsv"
Write-Host "   az sql server ad-admin create ``"
Write-Host "     --resource-group $ResourceGroup ``"
Write-Host "     --server $SqlServerName ``"
Write-Host "     --display-name `"GitHub Actions`" ``"
Write-Host "     --object-id `$SpObjectId"
Write-Host ""
Write-Host "3. Add these GitHub repository secrets:"
Write-Host ""
Write-Host "   Required:"
Write-Host "     AZURE_CLIENT_ID          = <clientId from step 1>"
Write-Host "     AZURE_TENANT_ID          = $TenantId"
Write-Host "     AZURE_SUBSCRIPTION_ID    = $SubscriptionId"
Write-Host "     AZURE_APP_NAME           = $Name"
Write-Host "     JWT_SIGNING_KEY          = <your-jwt-key-min-32-chars>"
Write-Host ""
Write-Host "   Optional:"
Write-Host "     APP_DOMAIN               = <custom-domain>"
Write-Host "     MICROSOFT_CLIENT_ID      = <microsoft-oauth-client-id>"
Write-Host "     MICROSOFT_CLIENT_SECRET  = <microsoft-oauth-client-secret>"
Write-Host "     GOOGLE_CLIENT_ID         = <google-oauth-client-id>"
Write-Host "     GOOGLE_CLIENT_SECRET     = <google-oauth-client-secret>"
Write-Host "     APPLE_CLIENT_ID          = <apple-oauth-client-id>"
Write-Host "     APPLE_CLIENT_SECRET      = <apple-oauth-client-secret>"
Write-Host "     EMAIL_CONNECTION_STRING  = <azure-communication-services>"
Write-Host "     EMAIL_SENDER_ADDRESS     = <verified-sender-address>"
Write-Host ""
Write-Host "4. Trigger a deployment by merging a PR to main or running the workflow manually."
Write-Host ""
