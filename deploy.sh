#!/bin/bash
#
# Provision OneBigHead Azure infrastructure via Bicep
#
# This script handles ONLY infrastructure provisioning and SQL identity setup.
# Application deployment (build, push, secrets, revisions) is handled by the
# GitHub Actions workflow (.github/workflows/deploy.yml).
#
# Prerequisites:
#   - Azure CLI installed and authenticated (az login)
#   - Azure CLI Bicep extension (az bicep install)
#   - sqlcmd installed (for SQL identity user creation)
#   - jq installed (for parsing deployment outputs)
#
# Usage:
#   ./deploy.sh --name <app-name> --location <region> [options]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Provision Azure infrastructure for OneBigHead."
    echo "Application deployment is handled by GitHub Actions."
    echo ""
    echo "Required Options:"
    echo "  -n, --name NAME           Base name for Azure resources (3-16 chars)"
    echo "  -l, --location LOCATION   Azure region (e.g., eastus)"
    echo ""
    echo "Optional:"
    echo "  --grafana-location LOC    Azure region for Grafana (defaults to LOCATION)"
    echo ""
    echo "Workflow Options:"
    echo "  --skip-infra              Skip Bicep provisioning (re-read outputs, re-run SQL user)"
    echo "  --skip-app                Skip Container App resource in Bicep (for infra-only re-runs)"
    echo "  -h, --help                Show this help message"
}

# Parse command line arguments
SKIP_INFRA=false
SKIP_APP=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            APP_NAME="$2"
            shift 2
            ;;
        -l|--location)
            LOCATION="$2"
            shift 2
            ;;
        --grafana-location)
            GRAFANA_LOCATION="$2"
            shift 2
            ;;
        --skip-infra)
            SKIP_INFRA=true
            shift
            ;;
        --skip-app)
            SKIP_APP=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$APP_NAME" ]]; then
    echo -e "${RED}Error: APP_NAME is required${NC}"
    print_usage
    exit 1
fi

if [[ -z "$LOCATION" ]]; then
    echo -e "${RED}Error: LOCATION is required${NC}"
    print_usage
    exit 1
fi

# Derive resource names
RESOURCE_GROUP="${APP_NAME}-rg"
DEPLOYMENT_NAME="${APP_NAME}-infra"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}OneBigHead Infrastructure Provisioning${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Configuration:"
echo "  App Name:        $APP_NAME"
echo "  Location:        $LOCATION"
echo "  Resource Group:  $RESOURCE_GROUP"
echo ""

# ============================================
# Step 1: Provision Infrastructure (Bicep)
# ============================================
echo -e "${CYAN}----------------------------------------${NC}"
echo -e "${CYAN}Step 1: Provisioning Infrastructure${NC}"
echo -e "${CYAN}----------------------------------------${NC}"

if [[ "$SKIP_INFRA" = false ]]; then
    # Look up current user's Entra ID for SQL admin
    echo -e "${YELLOW}Looking up current user's Entra ID...${NC}"
    SQL_AD_ADMIN_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)
    SQL_AD_ADMIN_DISPLAY_NAME=$(az ad signed-in-user show --query userPrincipalName -o tsv)
    echo "  SQL AD Admin: $SQL_AD_ADMIN_DISPLAY_NAME ($SQL_AD_ADMIN_OBJECT_ID)"

    # Build Bicep parameters
    BICEP_PARAMS=(
        "appName=$APP_NAME"
        "location=$LOCATION"
        "sqlAdAdminObjectId=$SQL_AD_ADMIN_OBJECT_ID"
        "sqlAdAdminDisplayName=$SQL_AD_ADMIN_DISPLAY_NAME"
    )

    if [[ -n "$GRAFANA_LOCATION" ]]; then
        BICEP_PARAMS+=("grafanaLocation=$GRAFANA_LOCATION")
    fi

    if [[ "$SKIP_APP" = true ]]; then
        BICEP_PARAMS+=("deployContainerApp=false")
        echo -e "${YELLOW}Container App will be skipped (--skip-app).${NC}"
    fi

    echo -e "${YELLOW}Deploying Bicep template...${NC}"
    az deployment sub create \
        --name "$DEPLOYMENT_NAME" \
        --location "$LOCATION" \
        --template-file "$SCRIPT_DIR/infra/main.bicep" \
        --parameters "${BICEP_PARAMS[@]}" \
        --output none

    echo -e "${GREEN}Infrastructure provisioned.${NC}"
else
    echo -e "${YELLOW}Skipping infrastructure provisioning (--skip-infra).${NC}"
fi
echo ""

# ============================================
# Step 2: Read Deployment Outputs
# ============================================
echo -e "${CYAN}----------------------------------------${NC}"
echo -e "${CYAN}Step 2: Reading Deployment Outputs${NC}"
echo -e "${CYAN}----------------------------------------${NC}"

DEPLOYMENT_OUTPUTS=$(az deployment sub show \
    --name "$DEPLOYMENT_NAME" \
    --query "properties.outputs" -o json)

ACR_LOGIN_SERVER=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.acrLoginServer.value')
ACR_NAME=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.acrName.value')
SQL_SERVER_NAME=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.sqlServerName.value')
SQL_SERVER_FQDN=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.sqlServerFqdn.value')
SQL_DB_NAME=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.sqlDatabaseName.value')
IDENTITY_NAME=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.identityName.value')
IDENTITY_CLIENT_ID=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.identityClientId.value')
IDENTITY_ID=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.identityId.value')
CONTAINER_ENV_NAME=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.containerEnvName.value')
APP_INSIGHTS_CONNECTION_STRING=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.appInsightsConnectionString.value')
GRAFANA_ENDPOINT=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.grafanaEndpoint.value')
CONTAINER_APP_NAME=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.containerAppName.value // empty')
CONTAINER_APP_FQDN=$(echo "$DEPLOYMENT_OUTPUTS" | jq -r '.containerAppFqdn.value // empty')

echo "  ACR:             $ACR_LOGIN_SERVER"
echo "  SQL Server:      $SQL_SERVER_NAME"
echo "  Identity:        $IDENTITY_NAME ($IDENTITY_CLIENT_ID)"
echo "  Container App:   ${CONTAINER_APP_NAME:-not deployed}"
echo ""

# ============================================
# Step 3: Configure SQL Managed Identity User
# ============================================
echo -e "${CYAN}----------------------------------------${NC}"
echo -e "${CYAN}Step 3: Configuring SQL Managed Identity User${NC}"
echo -e "${CYAN}----------------------------------------${NC}"

echo -e "${YELLOW}Adding current IP to SQL Server firewall...${NC}"
CURRENT_IP=$(curl -s https://api.ipify.org)
FIREWALL_RULE_NAME="DeploymentClient-$(date +%s)"
az sql server firewall-rule create \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SQL_SERVER_NAME" \
    --name "$FIREWALL_RULE_NAME" \
    --start-ip-address "$CURRENT_IP" \
    --end-ip-address "$CURRENT_IP" \
    --output none

echo -e "${YELLOW}Creating SQL user for managed identity...${NC}"
sqlcmd -S "$SQL_SERVER_FQDN" \
    -d "$SQL_DB_NAME" \
    --authentication-method=ActiveDirectoryDefault \
    -Q "
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = '${IDENTITY_NAME}')
BEGIN
    CREATE USER [${IDENTITY_NAME}] FROM EXTERNAL PROVIDER;
END
ALTER ROLE db_datareader ADD MEMBER [${IDENTITY_NAME}];
ALTER ROLE db_datawriter ADD MEMBER [${IDENTITY_NAME}];
ALTER ROLE db_ddladmin ADD MEMBER [${IDENTITY_NAME}];
PRINT 'User ${IDENTITY_NAME} configured successfully';
"

echo -e "${YELLOW}Removing temporary firewall rule...${NC}"
az sql server firewall-rule delete \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SQL_SERVER_NAME" \
    --name "$FIREWALL_RULE_NAME" \
    --output none || true

echo -e "${GREEN}SQL access configured.${NC}"
echo ""

# ============================================
# Step 4: Summary
# ============================================
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Infrastructure Provisioning Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Resources:"
echo "  Resource Group:    $RESOURCE_GROUP"
echo "  Container Registry: $ACR_NAME ($ACR_LOGIN_SERVER)"
echo "  SQL Server:        $SQL_SERVER_NAME"
echo "  Database:          $SQL_DB_NAME"
echo "  Managed Identity:  $IDENTITY_NAME"
echo "  Container Env:     $CONTAINER_ENV_NAME"
echo "  App Insights:      ${APP_NAME}-appinsights"
echo "  Grafana:           ${APP_NAME}-grafana ($GRAFANA_ENDPOINT)"
if [[ -n "$CONTAINER_APP_NAME" && "$CONTAINER_APP_NAME" != "" ]]; then
    echo "  Container App:     $CONTAINER_APP_NAME (https://${CONTAINER_APP_FQDN})"
fi
echo ""

echo -e "${CYAN}Next: Configure GitHub Actions${NC}"
echo ""
echo "1. Create a service principal with Contributor access:"
echo ""
echo "   az ad sp create-for-rbac \\"
echo "     --name \"${APP_NAME}-github-actions\" \\"
echo "     --role Contributor \\"
echo "     --scopes /subscriptions/\$(az account show --query id -o tsv)/resourceGroups/${RESOURCE_GROUP}"
echo ""
echo "2. Configure the service principal as SQL AD admin:"
echo ""
echo "   SP_OBJECT_ID=\$(az ad sp show --id <clientId-from-step-1> --query id -o tsv)"
echo "   az sql server ad-admin create \\"
echo "     --resource-group ${RESOURCE_GROUP} \\"
echo "     --server ${SQL_SERVER_NAME} \\"
echo "     --display-name \"GitHub Actions\" \\"
echo "     --object-id \$SP_OBJECT_ID"
echo ""
echo "3. Add these GitHub repository secrets:"
echo ""
echo "   Required:"
echo "     AZURE_CLIENT_ID          = <clientId from step 1>"
echo "     AZURE_TENANT_ID          = $(az account show --query tenantId -o tsv 2>/dev/null || echo '<your-tenant-id>')"
echo "     AZURE_SUBSCRIPTION_ID    = $(az account show --query id -o tsv 2>/dev/null || echo '<your-subscription-id>')"
echo "     AZURE_APP_NAME           = $APP_NAME"
echo "     JWT_SIGNING_KEY          = <your-jwt-key-min-32-chars>"
echo ""
echo "   Optional:"
echo "     APP_DOMAIN               = <custom-domain>"
echo "     MICROSOFT_CLIENT_ID      = <microsoft-oauth-client-id>"
echo "     MICROSOFT_CLIENT_SECRET  = <microsoft-oauth-client-secret>"
echo "     GOOGLE_CLIENT_ID         = <google-oauth-client-id>"
echo "     GOOGLE_CLIENT_SECRET     = <google-oauth-client-secret>"
echo "     APPLE_CLIENT_ID          = <apple-oauth-client-id>"
echo "     APPLE_CLIENT_SECRET      = <apple-oauth-client-secret>"
echo "     EMAIL_CONNECTION_STRING  = <azure-communication-services>"
echo "     EMAIL_SENDER_ADDRESS     = <verified-sender-address>"
echo ""
echo "4. Trigger a deployment by merging a PR to main or running the workflow manually."
echo ""
