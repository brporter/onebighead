# Deploying to Azure Container Apps

Deployment is split into two phases:

1. **Infrastructure provisioning** — run `deploy.sh` (or `deploy.ps1` on Windows) to create all Azure resources via Bicep
2. **Application deployment** — GitHub Actions builds, pushes, and deploys your app on every merge to `main`

## Quick Start

```bash
# 1. Provision infrastructure
./deploy.sh --name onebighead --location eastus

# 2. Configure GitHub secrets (the script prints what's needed)

# 3. Merge a PR to main (or trigger the workflow manually)
```

## Prerequisites

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) with Bicep (`az bicep install`)
- [sqlcmd](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility) (for SQL identity user creation)
- [jq](https://jqlang.github.io/jq/) (for bash script; not needed for PowerShell)
- An Azure subscription with permissions to create resources

## Phase 1: Infrastructure Provisioning

### Running the Script

**Bash (macOS/Linux):**

```bash
./deploy.sh --name onebighead --location eastus
```

**PowerShell (Windows):**

```powershell
./deploy.ps1 -Name onebighead -Location eastus
```

### Script Options

| Option | Bash | PowerShell | Description |
|--------|------|------------|-------------|
| App name | `-n, --name` | `-Name` | Base name for Azure resources (3-16 chars, required) |
| Location | `-l, --location` | `-Location` | Azure region (required) |
| Skip infra | `--skip-infra` | `-SkipInfra` | Re-read outputs and re-run SQL user without Bicep |
| Skip app | `--skip-app` | `-SkipApp` | Omit Container App from Bicep (for infra-only re-runs) |

### What Gets Created

| Resource | Name Pattern | Notes |
|----------|-------------|-------|
| Resource Group | `{name}-rg` | Created at subscription scope |
| Container Registry | `{name}acr` | Basic SKU |
| User-Assigned Managed Identity | `{name}-identity` | Used by Container App for ACR pull and SQL access |
| SQL Server | `{name}-sql-{unique}` | Entra-only auth (no SQL passwords) |
| SQL Database | `{name}` | General Purpose Serverless (auto-pause after 60 min) |
| SQL Firewall Rule | `AllowAzureServices` | Allows Azure service access |
| Log Analytics Workspace | `{name}-logs` | PerGB2018 SKU |
| Application Insights | `{name}-appinsights` | Linked to Log Analytics |
| Container Apps Environment | `{name}-env` | Linked to Log Analytics |
| Container App | `{name}-app` | Placeholder image; workflow deploys the real image |
| Azure Managed Grafana | `{name}-grafana` | Monitoring Reader on resource group |

The Container App is created with a placeholder image (`mcr.microsoft.com/k8se/quickstart:latest`). The GitHub Actions workflow replaces it with your application image on the first deployment.

### Bicep Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `appName` | string | — | Base name for all resources (3-16 chars) |
| `location` | string | — | Azure region (e.g., `eastus`) |
| `sqlAdAdminObjectId` | string | — | Entra ID object ID for SQL admin |
| `sqlAdAdminDisplayName` | string | — | Entra ID display name for SQL admin |
| `deployContainerApp` | bool | `true` | Set `false` to skip Container App on re-runs |

### Bicep Outputs

| Output | Description |
|--------|-------------|
| `acrLoginServer` | ACR login server (e.g., `onebigheadacr.azurecr.io`) |
| `acrName` | ACR name |
| `sqlServerName` | SQL Server name |
| `sqlServerFqdn` | SQL Server FQDN |
| `sqlDatabaseName` | SQL database name |
| `identityName` | Managed identity name |
| `identityClientId` | Managed identity client ID |
| `identityId` | Managed identity resource ID |
| `containerEnvName` | Container Apps Environment name |
| `appInsightsConnectionString` | Application Insights connection string |
| `grafanaEndpoint` | Grafana dashboard URL |
| `containerAppName` | Container App name (empty if `deployContainerApp=false`) |
| `containerAppFqdn` | Container App FQDN (empty if `deployContainerApp=false`) |

## Phase 2: Configure GitHub Actions

### 1. Create a Service Principal

```bash
az ad sp create-for-rbac \
  --name "onebighead-github-actions" \
  --role Contributor \
  --scopes /subscriptions/<subscription-id>/resourceGroups/onebighead-rg
```

### 2. Configure as SQL AD Admin

The service principal needs to be a SQL AD admin to run migrations and create the managed identity user:

```bash
SP_OBJECT_ID=$(az ad sp show --id <clientId> --query id -o tsv)

az sql server ad-admin create \
  --resource-group onebighead-rg \
  --server <sql-server-name> \
  --display-name "GitHub Actions" \
  --object-id $SP_OBJECT_ID
```

### 3. Add GitHub Secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `AZURE_CLIENT_ID` | Yes | Service principal client ID |
| `AZURE_TENANT_ID` | Yes | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Yes | Azure subscription ID |
| `AZURE_APP_NAME` | Yes | Base name for Azure resources |
| `JWT_SIGNING_KEY` | Yes | JWT signing key (min 32 characters) |
| `APP_DOMAIN` | No | Custom domain (if not set, uses Container App URL) |
| `MICROSOFT_CLIENT_ID` | No | Microsoft OAuth client ID |
| `MICROSOFT_CLIENT_SECRET` | No | Microsoft OAuth client secret |
| `GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `APPLE_CLIENT_ID` | No | Apple OAuth client ID |
| `APPLE_CLIENT_SECRET` | No | Apple OAuth client secret |
| `EMAIL_CONNECTION_STRING` | No | Azure Communication Services connection string |
| `EMAIL_SENDER_ADDRESS` | No | Verified sender address |

### 4. Trigger First Deployment

Merge a PR to `main` or run the workflow manually from the Actions tab.

The workflow will:
1. Run unit and integration tests
2. Build frontend and backend
3. Push Docker image to ACR
4. Set Container App secrets and update image/env vars
5. Create the SQL managed identity user (idempotent)
6. Run database migrations
7. Seed reference data
8. Verify health check

## Re-provisioning Infrastructure

When you need to add new Azure resources (e.g., Redis Cache), update the Bicep templates and re-run the deploy script.

### Adding New Resources

Use `--skip-app` to leave the Container App untouched while provisioning new infrastructure:

```bash
./deploy.sh --name onebighead --location eastus --skip-app
```

This passes `deployContainerApp=false` to Bicep. Since Bicep uses ARM incremental mode, omitting the Container App from the template does **not** delete it — ARM only adds or updates resources that are in the template, never removes ones that aren't.

### Re-running SQL User Setup

Use `--skip-infra` to skip Bicep entirely and just re-run the SQL managed identity user creation:

```bash
./deploy.sh --name onebighead --location eastus --skip-infra
```

This reads deployment outputs from the last Bicep run and re-runs the idempotent SQL user setup.

## Environment Variables Reference

These environment variables are set on the Container App:

| Variable | Set By | Description |
|----------|--------|-------------|
| `ASPNETCORE_ENVIRONMENT` | Bicep | Always `Production` |
| `ConnectionStrings__DefaultConnection` | Bicep | SQL connection string (managed identity) |
| `APPLICATIONINSIGHTS_CONNECTION_STRING` | Bicep | Application Insights telemetry |
| `Authentication__Jwt__SigningKey` | Workflow | JWT signing key (secret ref) |
| `Authentication__OAuth__BaseUrl` | Workflow | Public URL for OAuth callbacks |
| `Authentication__Providers__*__ClientId` | Workflow | OAuth client IDs |
| `Authentication__Providers__*__ClientSecret` | Workflow | OAuth client secrets (secret refs) |
| `Authentication__Providers__*__Enabled` | Workflow | OAuth provider toggle |
| `Email__ConnectionString` | Workflow | Email service (secret ref) |
| `Email__SenderAddress` | Workflow | Email sender address |
| `Email__AppBaseUrl` | Workflow | App URL for email links |

## Custom Domain Configuration

```bash
# Add custom domain
az containerapp hostname add \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --hostname yourdomain.com

# Bind certificate (after DNS validation)
az containerapp hostname bind \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --hostname yourdomain.com \
  --environment onebighead-env \
  --validation-method CNAME
```

Then set the `APP_DOMAIN` GitHub secret to your domain so the workflow uses it for OAuth and health checks.

## Viewing Logs

```bash
az containerapp logs show \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --follow
```

## Troubleshooting

### Container fails to start

Check system logs:

```bash
az containerapp logs show --name onebighead-app --resource-group onebighead-rg --type system
```

### OAuth authentication fails

1. Verify `Authentication__OAuth__BaseUrl` matches your application's public URL
2. Ensure OAuth redirect URIs are configured in each provider's developer console
3. Check that client IDs and secrets are correctly set in GitHub Secrets

### Database connection fails

1. Verify the managed identity user has been created (both `deploy.sh` and the workflow do this)
2. Check that the `AllowAzureServices` firewall rule exists on the SQL Server
3. Ensure the connection string uses `Active Directory Managed Identity` authentication

### First deployment shows placeholder app

The Container App starts with a placeholder image. It will be replaced on the first workflow run. Trigger the workflow manually from the Actions tab if you haven't merged a PR yet.
