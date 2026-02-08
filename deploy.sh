#!/bin/bash
#
# Deploy OneBigHead to Azure Container Apps with SQL Azure
# Uses user-assigned managed identity for all cross-service authentication
#
# Prerequisites:
#   - Azure CLI installed and authenticated (az login)
#   - Docker installed
#   - sqlcmd installed (for migration execution)
#
# Usage:
#   ./deploy.sh [options]
#
# Required parameters (via env vars or command line):
#   APP_NAME           - Base name for all Azure resources
#   LOCATION           - Azure region (e.g., eastus)
#   JWT_SIGNING_KEY    - JWT signing key (min 32 characters)
#
# Optional parameters:
#   SQL_ADMIN_USER     - SQL admin username (default: sqladmin)
#   SQL_ADMIN_PASSWORD - SQL admin password (generated if not provided)
#   MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET - Microsoft OAuth credentials
#   GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET - Google OAuth credentials
#   APPLE_CLIENT_ID, APPLE_CLIENT_SECRET - Apple OAuth credentials
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
    echo "Required Options:"
    echo "  -n, --name NAME           Base name for Azure resources"
    echo "  -l, --location LOCATION   Azure region (e.g., eastus)"
    echo "  -j, --jwt-key KEY         JWT signing key (min 32 chars)"
    echo ""
    echo "SQL Options:"
    echo "  -u, --sql-user USER       SQL admin username (default: sqladmin)"
    echo "  -p, --sql-password PASS   SQL admin password (generated if not set)"
    echo ""
    echo "OAuth Options (at least one provider recommended):"
    echo "  --microsoft-client-id ID      Microsoft OAuth client ID"
    echo "  --microsoft-client-secret SEC Microsoft OAuth client secret"
    echo "  --google-client-id ID         Google OAuth client ID"
    echo "  --google-client-secret SEC    Google OAuth client secret"
    echo "  --apple-client-id ID          Apple OAuth client ID"
    echo "  --apple-client-secret SEC     Apple OAuth client secret"
    echo ""
    echo "Workflow Options:"
    echo "  --skip-infra              Skip infrastructure creation"
    echo "  --skip-build              Skip application build"
    echo "  --skip-migration          Skip database migration"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Environment variables (alternative to command line):"
    echo "  APP_NAME, LOCATION, JWT_SIGNING_KEY, SQL_ADMIN_USER, SQL_ADMIN_PASSWORD"
    echo "  MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET"
    echo "  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET"
    echo "  APPLE_CLIENT_ID, APPLE_CLIENT_SECRET"
}

# Parse command line arguments
SKIP_INFRA=false
SKIP_BUILD=false
SKIP_MIGRATION=false

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
        -j|--jwt-key)
            JWT_SIGNING_KEY="$2"
            shift 2
            ;;
        -u|--sql-user)
            SQL_ADMIN_USER="$2"
            shift 2
            ;;
        -p|--sql-password)
            SQL_ADMIN_PASSWORD="$2"
            shift 2
            ;;
        --microsoft-client-id)
            MICROSOFT_CLIENT_ID="$2"
            shift 2
            ;;
        --microsoft-client-secret)
            MICROSOFT_CLIENT_SECRET="$2"
            shift 2
            ;;
        --google-client-id)
            GOOGLE_CLIENT_ID="$2"
            shift 2
            ;;
        --google-client-secret)
            GOOGLE_CLIENT_SECRET="$2"
            shift 2
            ;;
        --apple-client-id)
            APPLE_CLIENT_ID="$2"
            shift 2
            ;;
        --apple-client-secret)
            APPLE_CLIENT_SECRET="$2"
            shift 2
            ;;
        --skip-infra)
            SKIP_INFRA=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-migration)
            SKIP_MIGRATION=true
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

if [[ -z "$JWT_SIGNING_KEY" ]]; then
    echo -e "${RED}Error: JWT_SIGNING_KEY is required${NC}"
    print_usage
    exit 1
fi

if [[ ${#JWT_SIGNING_KEY} -lt 32 ]]; then
    echo -e "${RED}Error: JWT_SIGNING_KEY must be at least 32 characters${NC}"
    exit 1
fi

# Set defaults
SQL_ADMIN_USER="${SQL_ADMIN_USER:-sqladmin}"
if [[ -z "$SQL_ADMIN_PASSWORD" ]]; then
    SQL_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9!@#$%' | head -c 24)
    echo -e "${YELLOW}Generated SQL admin password (save this): $SQL_ADMIN_PASSWORD${NC}"
fi

# Derive resource names
RESOURCE_GROUP="${APP_NAME}-rg"
ACR_NAME="${APP_NAME}acr"
SQL_DB_NAME="${APP_NAME}"
CONTAINER_ENV_NAME="${APP_NAME}-env"
CONTAINER_APP_NAME="${APP_NAME}-app"
IDENTITY_NAME="${APP_NAME}-identity"
APP_INSIGHTS_NAME="${APP_NAME}-appinsights"
LOG_ANALYTICS_NAME="${APP_NAME}-logs"
GRAFANA_NAME="${APP_NAME}-grafana"

# SQL Server name handling: use existing if skipping infra, otherwise generate new
if [[ "$SKIP_INFRA" = true ]]; then
    # Look up existing SQL server name from resource group
    SQL_SERVER_NAME=$(az sql server list --resource-group "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null)
    if [[ -z "$SQL_SERVER_NAME" ]]; then
        echo -e "${RED}Error: No SQL server found in resource group $RESOURCE_GROUP${NC}"
        echo -e "${RED}Cannot use --skip-infra without existing infrastructure${NC}"
        exit 1
    fi
else
    # Generate a short random suffix for globally unique SQL server name
    RANDOM_SUFFIX=$(openssl rand -hex 3)
    SQL_SERVER_NAME="${APP_NAME}-sql-${RANDOM_SUFFIX}"
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}OneBigHead Azure Deployment${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Configuration:"
echo "  App Name:        $APP_NAME"
echo "  Location:        $LOCATION"
echo "  Resource Group:  $RESOURCE_GROUP"
echo "  ACR:             $ACR_NAME"
echo "  SQL Server:      $SQL_SERVER_NAME"
echo "  Database:        $SQL_DB_NAME"
echo "  Identity:        $IDENTITY_NAME"
echo ""

# ============================================
# Step 1: Build Application
# ============================================
if [[ "$SKIP_BUILD" = false ]]; then
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Step 1: Building Application${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    "$SCRIPT_DIR/build/build.sh" --clean -o publish
    
    # Generate migration script using EF Core
    echo -e "${YELLOW}Generating migration script...${NC}"
    cd "$SCRIPT_DIR/backend"
    dotnet ef migrations script --idempotent -o "$SCRIPT_DIR/publish/migrate.sql"
    cd "$SCRIPT_DIR"
    
    echo -e "${GREEN}Build complete.${NC}"
    echo ""
fi

# ============================================
# Step 2: Create Azure Infrastructure
# ============================================
if [[ "$SKIP_INFRA" = false ]]; then
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Step 2: Creating Azure Infrastructure${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    # Create resource group
    echo -e "${YELLOW}Creating resource group...${NC}"
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
    
    # Create Azure Container Registry
    echo -e "${YELLOW}Creating Azure Container Registry...${NC}"
    az acr create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$ACR_NAME" \
        --sku Basic \
        --output none
    
    # Create SQL Server
    echo -e "${YELLOW}Creating SQL Server...${NC}"
    az sql server create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$SQL_SERVER_NAME" \
        --location "$LOCATION" \
        --admin-user "$SQL_ADMIN_USER" \
        --admin-password "$SQL_ADMIN_PASSWORD" \
        --output none
    
    # Enable Azure AD authentication on SQL Server
    echo -e "${YELLOW}Configuring Azure AD authentication for SQL Server...${NC}"
    CURRENT_USER_ID=$(az ad signed-in-user show --query id -o tsv)
    CURRENT_USER_NAME=$(az ad signed-in-user show --query userPrincipalName -o tsv)
    
    az sql server ad-admin create \
        --resource-group "$RESOURCE_GROUP" \
        --server "$SQL_SERVER_NAME" \
        --display-name "$CURRENT_USER_NAME" \
        --object-id "$CURRENT_USER_ID" \
        --output none
    
    # Create SQL Database
    echo -e "${YELLOW}Creating SQL Database...${NC}"
    az sql db create \
        --resource-group "$RESOURCE_GROUP" \
        --server "$SQL_SERVER_NAME" \
        --name "$SQL_DB_NAME" \
        --service-objective S0 \
        --output none
    
    # Allow Azure services to access SQL Server
    echo -e "${YELLOW}Configuring SQL Server firewall...${NC}"
    az sql server firewall-rule create \
        --resource-group "$RESOURCE_GROUP" \
        --server "$SQL_SERVER_NAME" \
        --name AllowAzureServices \
        --start-ip-address 0.0.0.0 \
        --end-ip-address 0.0.0.0 \
        --output none
    
    # Create Container Apps Environment
    echo -e "${YELLOW}Creating Container Apps Environment...${NC}"
    az containerapp env create \
        --name "$CONTAINER_ENV_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --output none
    
    # Create Log Analytics Workspace (required by Application Insights)
    echo -e "${YELLOW}Creating Log Analytics Workspace...${NC}"
    az monitor log-analytics workspace create \
        --resource-group "$RESOURCE_GROUP" \
        --workspace-name "$LOG_ANALYTICS_NAME" \
        --location "$LOCATION" --output none

    LOG_ANALYTICS_ID=$(az monitor log-analytics workspace show \
        --resource-group "$RESOURCE_GROUP" \
        --workspace-name "$LOG_ANALYTICS_NAME" --query id -o tsv)

    # Create Application Insights
    echo -e "${YELLOW}Creating Application Insights...${NC}"
    az monitor app-insights component create \
        --app "$APP_INSIGHTS_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --workspace "$LOG_ANALYTICS_ID" \
        --kind web --application-type web --output none

    # Create Azure Managed Grafana
    echo -e "${YELLOW}Creating Azure Managed Grafana...${NC}"
    az grafana create \
        --name "$GRAFANA_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" --output none

    echo -e "${GREEN}Infrastructure created.${NC}"
    echo ""
fi

# ============================================
# Step 3: Create User-Assigned Managed Identity
# ============================================
echo -e "${CYAN}----------------------------------------${NC}"
echo -e "${CYAN}Step 3: Creating Managed Identity${NC}"
echo -e "${CYAN}----------------------------------------${NC}"

# Check if identity exists
if az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" &>/dev/null; then
    echo -e "${YELLOW}Managed identity already exists, retrieving...${NC}"
else
    echo -e "${YELLOW}Creating user-assigned managed identity...${NC}"
    az identity create \
        --name "$IDENTITY_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --output none
fi

# Get identity details
IDENTITY_PRINCIPAL_ID=$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query principalId -o tsv)
IDENTITY_CLIENT_ID=$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query clientId -o tsv)
IDENTITY_ID=$(az identity show --name "$IDENTITY_NAME" --resource-group "$RESOURCE_GROUP" --query id -o tsv)

echo "Identity Principal ID: $IDENTITY_PRINCIPAL_ID"
echo "Identity Client ID: $IDENTITY_CLIENT_ID"

# Wait for identity to propagate to Azure AD
echo -e "${YELLOW}Waiting for identity to propagate to Azure AD...${NC}"
for i in {1..30}; do
    if az ad sp show --id "$IDENTITY_PRINCIPAL_ID" &>/dev/null; then
        echo -e "${GREEN}Identity propagated successfully${NC}"
        break
    fi
    echo "  Waiting for identity propagation ($i/30)..."
    sleep 5
done

# Get ACR resource ID and grant AcrPull role
ACR_ID=$(az acr show --name "$ACR_NAME" --resource-group "$RESOURCE_GROUP" --query "id" -o tsv)
ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)

echo -e "${YELLOW}Granting AcrPull role to managed identity...${NC}"
az role assignment create \
    --assignee "$IDENTITY_PRINCIPAL_ID" \
    --role AcrPull \
    --scope "$ACR_ID" \
    --output none 2>/dev/null || echo "Role assignment may already exist"

# Grant Grafana Monitoring Reader access to the resource group
echo -e "${YELLOW}Granting Monitoring Reader role to Grafana...${NC}"
GRAFANA_PRINCIPAL_ID=$(az grafana show --name "$GRAFANA_NAME" \
    --resource-group "$RESOURCE_GROUP" --query "identity.principalId" -o tsv 2>/dev/null)
RESOURCE_GROUP_ID=$(az group show --name "$RESOURCE_GROUP" --query id -o tsv)

if [[ -n "$GRAFANA_PRINCIPAL_ID" ]]; then
    az role assignment create \
        --assignee "$GRAFANA_PRINCIPAL_ID" \
        --role "Monitoring Reader" \
        --scope "$RESOURCE_GROUP_ID" --output none 2>/dev/null || true
fi

echo -e "${GREEN}Managed identity configured.${NC}"
echo ""

# ============================================
# Step 4: Build and Push Docker Image
# ============================================
echo -e "${CYAN}----------------------------------------${NC}"
echo -e "${CYAN}Step 4: Building and Pushing Docker Image${NC}"
echo -e "${CYAN}----------------------------------------${NC}"

# Login to ACR
echo -e "${YELLOW}Logging in to ACR...${NC}"
az acr login --name "$ACR_NAME"

# Build and push image
IMAGE_TAG="${ACR_LOGIN_SERVER}/${APP_NAME}:$(date +%Y%m%d%H%M%S)"
IMAGE_LATEST="${ACR_LOGIN_SERVER}/${APP_NAME}:latest"

echo -e "${YELLOW}Building Docker image for linux/amd64...${NC}"
docker build --platform linux/amd64 -t "$IMAGE_TAG" -t "$IMAGE_LATEST" "$SCRIPT_DIR"

echo -e "${YELLOW}Pushing Docker image...${NC}"
docker push "$IMAGE_TAG"
docker push "$IMAGE_LATEST"

echo -e "${GREEN}Image pushed: $IMAGE_TAG${NC}"
echo ""

# ============================================
# Step 5: Create/Update Container App
# ============================================
echo -e "${CYAN}----------------------------------------${NC}"
echo -e "${CYAN}Step 5: Deploying Container App${NC}"
echo -e "${CYAN}----------------------------------------${NC}"

# Build connection string for managed identity (include client ID for user-assigned identity)
SQL_CONNECTION_STRING="Server=tcp:${SQL_SERVER_NAME}.database.windows.net,1433;Database=${SQL_DB_NAME};Authentication=Active Directory Managed Identity;User Id=${IDENTITY_CLIENT_ID};Encrypt=True;TrustServerCertificate=False;"

# Build secrets array (only sensitive values)
SECRETS=("jwt-signing-key=$JWT_SIGNING_KEY")
if [[ -n "$MICROSOFT_CLIENT_SECRET" ]]; then
    SECRETS+=("microsoft-client-secret=$MICROSOFT_CLIENT_SECRET")
fi
if [[ -n "$GOOGLE_CLIENT_SECRET" ]]; then
    SECRETS+=("google-client-secret=$GOOGLE_CLIENT_SECRET")
fi
if [[ -n "$APPLE_CLIENT_SECRET" ]]; then
    SECRETS+=("apple-client-secret=$APPLE_CLIENT_SECRET")
fi

# Build environment variables array
# Note: Client IDs are not secrets (they're public identifiers), only client secrets need protection
ENV_VARS=("ASPNETCORE_ENVIRONMENT=Production")
ENV_VARS+=("ConnectionStrings__DefaultConnection=$SQL_CONNECTION_STRING")
ENV_VARS+=("Authentication__Jwt__SigningKey=secretref:jwt-signing-key")

# Microsoft OAuth
if [[ -n "$MICROSOFT_CLIENT_ID" ]]; then
    ENV_VARS+=("Authentication__Providers__Microsoft__ClientId=$MICROSOFT_CLIENT_ID")
    ENV_VARS+=("Authentication__Providers__Microsoft__Enabled=true")
fi
if [[ -n "$MICROSOFT_CLIENT_SECRET" ]]; then
    ENV_VARS+=("Authentication__Providers__Microsoft__ClientSecret=secretref:microsoft-client-secret")
fi

# Google OAuth
if [[ -n "$GOOGLE_CLIENT_ID" ]]; then
    ENV_VARS+=("Authentication__Providers__Google__ClientId=$GOOGLE_CLIENT_ID")
    ENV_VARS+=("Authentication__Providers__Google__Enabled=true")
fi
if [[ -n "$GOOGLE_CLIENT_SECRET" ]]; then
    ENV_VARS+=("Authentication__Providers__Google__ClientSecret=secretref:google-client-secret")
fi

# Apple OAuth
if [[ -n "$APPLE_CLIENT_ID" ]]; then
    ENV_VARS+=("Authentication__Providers__Apple__ClientId=$APPLE_CLIENT_ID")
    ENV_VARS+=("Authentication__Providers__Apple__Enabled=true")
fi
if [[ -n "$APPLE_CLIENT_SECRET" ]]; then
    ENV_VARS+=("Authentication__Providers__Apple__ClientSecret=secretref:apple-client-secret")
fi

# Add Application Insights connection string
APP_INSIGHTS_CONNECTION_STRING=$(az monitor app-insights component show \
    --app "$APP_INSIGHTS_NAME" --resource-group "$RESOURCE_GROUP" \
    --query connectionString -o tsv 2>/dev/null)
if [[ -n "$APP_INSIGHTS_CONNECTION_STRING" ]]; then
    ENV_VARS+=("APPLICATIONINSIGHTS_CONNECTION_STRING=$APP_INSIGHTS_CONNECTION_STRING")
fi

# Check if container app exists
if az containerapp show --name "$CONTAINER_APP_NAME" --resource-group "$RESOURCE_GROUP" &>/dev/null; then
    echo -e "${YELLOW}Updating existing Container App...${NC}"
    
    # Get the existing app URL for OAuth base URL
    APP_URL=$(az containerapp show \
        --name "$CONTAINER_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query "properties.configuration.ingress.fqdn" \
        -o tsv)
    ENV_VARS+=("Authentication__OAuth__BaseUrl=https://${APP_URL}")
    
    # Update secrets first
    echo -e "${YELLOW}Updating secrets...${NC}"
    az containerapp secret set \
        --name "$CONTAINER_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --secrets "${SECRETS[@]}" \
        --output none
    
    # Update image and environment variables
    az containerapp update \
        --name "$CONTAINER_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --image "$IMAGE_TAG" \
        --set-env-vars "${ENV_VARS[@]}" \
        --output none
else
    echo -e "${YELLOW}Creating Container App with user-assigned managed identity...${NC}"
    
    az containerapp create \
        --name "$CONTAINER_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --environment "$CONTAINER_ENV_NAME" \
        --image "$IMAGE_TAG" \
        --user-assigned "$IDENTITY_ID" \
        --registry-server "$ACR_LOGIN_SERVER" \
        --registry-identity "$IDENTITY_ID" \
        --target-port 8080 \
        --ingress external \
        --min-replicas 1 \
        --max-replicas 3 \
        --secrets "${SECRETS[@]}" \
        --env-vars "${ENV_VARS[@]}" \
        --output none
    
    # Get the newly created app URL and set OAuth base URL
    echo -e "${YELLOW}Configuring OAuth base URL...${NC}"
    APP_URL=$(az containerapp show \
        --name "$CONTAINER_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query "properties.configuration.ingress.fqdn" \
        -o tsv)
    
    az containerapp update \
        --name "$CONTAINER_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --set-env-vars "Authentication__OAuth__BaseUrl=https://${APP_URL}" \
        --output none
fi

echo -e "${GREEN}Container App deployed.${NC}"
echo ""

# ============================================
# Step 6: Configure SQL Azure Access for Managed Identity
# ============================================
echo -e "${CYAN}----------------------------------------${NC}"
echo -e "${CYAN}Step 6: Configuring SQL Azure Access${NC}"
echo -e "${CYAN}----------------------------------------${NC}"

echo -e "${YELLOW}Granting SQL database access to managed identity...${NC}"

# Allow current client IP for migration
echo -e "${YELLOW}Adding current IP to SQL Server firewall for migration...${NC}"
CURRENT_IP=$(curl -s https://api.ipify.org)
az sql server firewall-rule create \
    --resource-group "$RESOURCE_GROUP" \
    --server "$SQL_SERVER_NAME" \
    --name "DeploymentClient-$(date +%s)" \
    --start-ip-address "$CURRENT_IP" \
    --end-ip-address "$CURRENT_IP" \
    --output none

# Create SQL user for managed identity
SQL_SERVER_FQDN="${SQL_SERVER_NAME}.database.windows.net"

echo -e "${YELLOW}Creating SQL user for managed identity...${NC}"
echo -e "${CYAN}Executing SQL commands to create managed identity user...${NC}"

# Create the SQL user for the user-assigned managed identity
# Using ActiveDirectoryDefault to authenticate with current Azure CLI credentials
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

echo -e "${GREEN}SQL access configured.${NC}"
echo ""

# ============================================
# Step 7: Run Database Migrations
# ============================================
if [[ "$SKIP_MIGRATION" = false ]]; then
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Step 7: Running Database Migrations${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    # Ensure migration script exists (in case --skip-build was used)
    if [[ ! -f "$SCRIPT_DIR/publish/migrate.sql" ]]; then
        mkdir -p "$SCRIPT_DIR/publish"
        echo -e "${YELLOW}Generating migration script...${NC}"
        cd "$SCRIPT_DIR/backend"
        dotnet ef migrations script --idempotent -o "$SCRIPT_DIR/publish/migrate.sql"
        cd "$SCRIPT_DIR"
    fi
    
    echo -e "${YELLOW}Applying migrations to SQL Azure...${NC}"
    
    sqlcmd -S "$SQL_SERVER_FQDN" \
        -d "$SQL_DB_NAME" \
        --authentication-method=ActiveDirectoryDefault \
        -i "$SCRIPT_DIR/publish/migrate.sql"
    
    echo -e "${GREEN}Migrations applied.${NC}"
    echo ""
fi

# ============================================
# Step 8: Deployment Complete
# ============================================

# Get final app URL (may have been set earlier, but ensure we have it)
if [[ -z "$APP_URL" ]]; then
    APP_URL=$(az containerapp show \
        --name "$CONTAINER_APP_NAME" \
        --resource-group "$RESOURCE_GROUP" \
        --query "properties.configuration.ingress.fqdn" \
        -o tsv)
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Successful!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${CYAN}Application URL: https://${APP_URL}${NC}"
echo ""
echo "Resources:"
echo "  Resource Group:    $RESOURCE_GROUP"
echo "  Container App:     $CONTAINER_APP_NAME"
echo "  Managed Identity:  $IDENTITY_NAME"
echo "  SQL Server:        $SQL_SERVER_NAME"
echo "  Database:          $SQL_DB_NAME"
echo "  App Insights:      $APP_INSIGHTS_NAME"
echo "  Log Analytics:     $LOG_ANALYTICS_NAME"
if [[ -n "$GRAFANA_NAME" ]]; then
    GRAFANA_URL=$(az grafana show --name "$GRAFANA_NAME" --resource-group "$RESOURCE_GROUP" --query "properties.endpoint" -o tsv 2>/dev/null)
    echo "  Grafana:           $GRAFANA_NAME"
    if [[ -n "$GRAFANA_URL" ]]; then
        echo "  Grafana URL:       $GRAFANA_URL"
    fi
fi
echo ""

# Show OAuth status
echo "OAuth Providers Configured:"
if [[ -n "$MICROSOFT_CLIENT_ID" ]]; then
    echo "  Microsoft: Enabled"
else
    echo "  Microsoft: Not configured"
fi
if [[ -n "$GOOGLE_CLIENT_ID" ]]; then
    echo "  Google: Enabled"
else
    echo "  Google: Not configured"
fi
if [[ -n "$APPLE_CLIENT_ID" ]]; then
    echo "  Apple: Enabled"
else
    echo "  Apple: Not configured"
fi
echo ""

echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Configure OAuth redirect URIs in provider consoles:"
echo "     Redirect URI: https://${APP_URL}/api/auth/callback/{provider}"
echo ""
if [[ -z "$MICROSOFT_CLIENT_ID" && -z "$GOOGLE_CLIENT_ID" && -z "$APPLE_CLIENT_ID" ]]; then
echo "  2. Add OAuth providers (if not configured during deployment):"
echo "     az containerapp secret set \\"
echo "       --name $CONTAINER_APP_NAME \\"
echo "       --resource-group $RESOURCE_GROUP \\"
echo "       --secrets \"microsoft-client-id=<id>\" \"microsoft-client-secret=<secret>\""
echo ""
echo "     az containerapp update \\"
echo "       --name $CONTAINER_APP_NAME \\"
echo "       --resource-group $RESOURCE_GROUP \\"
echo "       --set-env-vars \\"
echo "         \"Authentication__Providers__Microsoft__ClientId=secretref:microsoft-client-id\" \\"
echo "         \"Authentication__Providers__Microsoft__ClientSecret=secretref:microsoft-client-secret\" \\"
echo "         \"Authentication__Providers__Microsoft__Enabled=true\""
echo ""
fi
echo "  View logs:"
echo "     az containerapp logs show --name $CONTAINER_APP_NAME --resource-group $RESOURCE_GROUP --follow"
echo ""
