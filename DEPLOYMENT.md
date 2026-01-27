# Deploying to Azure Container Apps

This guide provides step-by-step instructions for deploying the OneBigHead application to Azure Container Apps.

## Quick Start (Automated Deployment)

The `deploy.sh` script automates the entire deployment process including infrastructure creation, managed identity configuration, and database migration:

```bash
./deploy.sh \
  --name onebighead \
  --location eastus \
  --jwt-key "your-jwt-signing-key-at-least-32-chars"
```

This script:
- Creates all Azure resources (Resource Group, ACR, SQL Azure, Container Apps)
- Configures managed identity for ACR pull access
- Configures managed identity for SQL Azure authentication
- Runs database migrations automatically
- Deploys the application

### Script Options

| Option | Description |
|--------|-------------|
| `-n, --name` | Base name for Azure resources (required) |
| `-l, --location` | Azure region (required, e.g., eastus) |
| `-j, --jwt-key` | JWT signing key (required, min 32 chars) |
| `-u, --sql-user` | SQL admin username (default: sqladmin) |
| `-p, --sql-password` | SQL admin password (auto-generated if not set) |
| `--skip-infra` | Skip infrastructure creation (for redeployments) |
| `--skip-build` | Skip application build |
| `--skip-migration` | Skip database migration |

### Redeployment

For subsequent deployments after infrastructure exists:

```bash
./deploy.sh \
  --name onebighead \
  --location eastus \
  --jwt-key "your-jwt-signing-key" \
  --skip-infra
```

---

## Manual Deployment

If you prefer manual deployment or need more control, follow the steps below.

## Prerequisites

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) installed and authenticated
- [Docker](https://docs.docker.com/get-docker/) installed
- [sqlcmd](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility) installed (for migrations)
- An Azure subscription
- Application built and ready for containerization

## Step 1: Build the Application

Build the application and create the Docker image:

```bash
# Build the application
./build/build.sh --clean -o publish

# Build the Docker image
docker build -t onebighead .
```

## Step 2: Set Up Azure Resources

### Create a Resource Group

```bash
az group create --name onebighead-rg --location eastus
```

### Create an Azure Container Registry (ACR)

```bash
az acr create --resource-group onebighead-rg --name onebigheadacr --sku Basic
```

### Create a Container Apps Environment

```bash
az containerapp env create \
  --name onebighead-env \
  --resource-group onebighead-rg \
  --location eastus
```

### Create an Azure SQL Database (Optional)

If using SQL Azure for production:

```bash
# Create SQL Server
az sql server create \
  --name onebighead-sql \
  --resource-group onebighead-rg \
  --location eastus \
  --admin-user sqladmin \
  --admin-password '<YourStrongPassword>'

# Create database
az sql db create \
  --resource-group onebighead-rg \
  --server onebighead-sql \
  --name onebighead \
  --service-objective S0
```

## Step 3: Push the Docker Image to ACR

```bash
# Log in to ACR
az acr login --name onebigheadacr

# Tag the image
docker tag onebighead onebigheadacr.azurecr.io/onebighead:latest

# Push the image
docker push onebigheadacr.azurecr.io/onebighead:latest
```

## Step 4: Configure Secrets in Azure Container Apps

Azure Container Apps supports secrets for sensitive configuration values. Create secrets for all sensitive environment variables:

```bash
az containerapp secret set \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --secrets \
    "db-connection-string=<your-sql-connection-string>" \
    "jwt-signing-key=<your-jwt-signing-key>" \
    "microsoft-client-id=<your-microsoft-client-id>" \
    "microsoft-client-secret=<your-microsoft-client-secret>" \
    "google-client-id=<your-google-client-id>" \
    "google-client-secret=<your-google-client-secret>" \
    "apple-client-id=<your-apple-client-id>" \
    "apple-client-secret=<your-apple-client-secret>"
```

## Step 5: Deploy the Container App

Create the Container App with environment variables mapped to secrets:

```bash
az containerapp create \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --environment onebighead-env \
  --image onebigheadacr.azurecr.io/onebighead:latest \
  --registry-server onebigheadacr.azurecr.io \
  --target-port 8080 \
  --ingress external \
  --min-replicas 1 \
  --max-replicas 3 \
  --secrets \
    "db-connection-string=<your-sql-connection-string>" \
    "jwt-signing-key=<your-jwt-signing-key>" \
    "microsoft-client-id=<your-microsoft-client-id>" \
    "microsoft-client-secret=<your-microsoft-client-secret>" \
    "google-client-id=<your-google-client-id>" \
    "google-client-secret=<your-google-client-secret>" \
    "apple-client-id=<your-apple-client-id>" \
    "apple-client-secret=<your-apple-client-secret>" \
  --env-vars \
    "ConnectionStrings__DefaultConnection=secretref:db-connection-string" \
    "Authentication__Jwt__SigningKey=secretref:jwt-signing-key" \
    "Authentication__OAuth__BaseUrl=https://onebighead-app.<region>.azurecontainerapps.io" \
    "Authentication__Providers__Microsoft__ClientId=secretref:microsoft-client-id" \
    "Authentication__Providers__Microsoft__ClientSecret=secretref:microsoft-client-secret" \
    "Authentication__Providers__Microsoft__Enabled=true" \
    "Authentication__Providers__Google__ClientId=secretref:google-client-id" \
    "Authentication__Providers__Google__ClientSecret=secretref:google-client-secret" \
    "Authentication__Providers__Google__Enabled=false" \
    "Authentication__Providers__Apple__ClientId=secretref:apple-client-id" \
    "Authentication__Providers__Apple__ClientSecret=secretref:apple-client-secret" \
    "Authentication__Providers__Apple__Enabled=false"
```

> **Note:** Replace `<region>` with your actual region (e.g., `eastus`) in the `Authentication__OAuth__BaseUrl` value after deployment, or use a custom domain.

## Step 6: Configure ACR Access

Grant the Container App access to pull images from ACR:

```bash
az containerapp registry set \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --server onebigheadacr.azurecr.io \
  --identity system
```

## Environment Variables Reference

The following environment variables must be configured:

| Variable | Description | Secret |
|----------|-------------|--------|
| `ConnectionStrings__DefaultConnection` | SQL Server connection string | Yes |
| `Authentication__Jwt__SigningKey` | JWT signing key (min 32 characters) | Yes |
| `Authentication__OAuth__BaseUrl` | Public URL of your application | No |
| `Authentication__Providers__Microsoft__ClientId` | Microsoft OAuth client ID | Yes |
| `Authentication__Providers__Microsoft__ClientSecret` | Microsoft OAuth client secret | Yes |
| `Authentication__Providers__Microsoft__Enabled` | Enable Microsoft OAuth (`true`/`false`) | No |
| `Authentication__Providers__Google__ClientId` | Google OAuth client ID | Yes |
| `Authentication__Providers__Google__ClientSecret` | Google OAuth client secret | Yes |
| `Authentication__Providers__Google__Enabled` | Enable Google OAuth (`true`/`false`) | No |
| `Authentication__Providers__Apple__ClientId` | Apple OAuth service ID | Yes |
| `Authentication__Providers__Apple__ClientSecret` | Apple OAuth client secret | Yes |
| `Authentication__Providers__Apple__Enabled` | Enable Apple OAuth (`true`/`false`) | No |

## Updating Environment Variables

To update environment variables after deployment:

```bash
az containerapp update \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --set-env-vars "Authentication__Providers__Google__Enabled=true"
```

To update secrets:

```bash
az containerapp secret set \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --secrets "google-client-secret=<new-secret-value>"
```

## Applying Database Migrations

Before the application can run, apply database migrations to SQL Azure:

```bash
# Generate idempotent migration script for SQL Server
cd backend
dotnet ef migrations script --idempotent -o ../publish/migrate.sql

# Apply to SQL Azure
sqlcmd -S onebighead-sql.database.windows.net -d onebighead -U sqladmin -P '<YourPassword>' -i ../publish/migrate.sql
```

> **Note:** The project includes a `DesignTimeDbContextFactory` that configures EF Core to use SQL Server when generating migration scripts, enabling idempotent script generation.

## Custom Domain Configuration

To configure a custom domain:

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

After configuring a custom domain, update the OAuth base URL:

```bash
az containerapp update \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --set-env-vars "Authentication__OAuth__BaseUrl=https://yourdomain.com"
```

## Viewing Logs

```bash
az containerapp logs show \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --follow
```

## Troubleshooting

### Container fails to start

Check the logs for startup errors:

```bash
az containerapp logs show --name onebighead-app --resource-group onebighead-rg --type system
```

### OAuth authentication fails

1. Verify `Authentication__OAuth__BaseUrl` matches your application's public URL
2. Ensure OAuth redirect URIs are configured in each provider's developer console
3. Check that client IDs and secrets are correctly set

### Database connection fails

1. Verify the connection string format for SQL Azure
2. Ensure the Container App's outbound IP is allowed in SQL Server firewall rules:

```bash
az sql server firewall-rule create \
  --resource-group onebighead-rg \
  --server onebighead-sql \
  --name AllowContainerApp \
  --start-ip-address <container-app-ip> \
  --end-ip-address <container-app-ip>
```

---

## CI/CD Pipeline (GitHub Actions)

The repository includes a GitHub Actions workflow (`.github/workflows/deploy.yml`) that automatically deploys to Azure when a PR is merged to `main`.

### Pipeline Features

- **Automatic deployment** on PR merge to main
- **Test execution** (unit and integration tests) before deployment
- **Container image build and push** to Azure Container Registry
- **Database migrations** run automatically against SQL Azure
- **Revision management** - new deployments create new Container App revisions, automatically deactivating old containers
- **Health check verification** after deployment

### Infrastructure Provisioning

**The pipeline does NOT handle infrastructure provisioning.** Infrastructure must be created once before the first pipeline run using the manual deployment script.

This is intentional because:
1. Infrastructure changes are infrequent and require careful review
2. SQL Server names must be globally unique (generated with random suffix)
3. Service principal permissions need one-time setup
4. OAuth provider configuration requires manual registration

### Prerequisites (One-Time Setup)

Before the pipeline can run for the first time:

#### 1. Provision Azure Infrastructure

Run the deployment script to create all Azure resources:

```bash
./deploy.sh \
  --name onebighead \
  --location eastus \
  --jwt-key "your-jwt-signing-key-at-least-32-chars" \
  --microsoft-client-id "<your-id>" \
  --microsoft-client-secret "<your-secret>"
```

This creates:
- Resource Group
- Azure Container Registry
- SQL Azure Server and Database
- Container Apps Environment
- User-assigned Managed Identity with appropriate permissions

#### 2. Create Azure Service Principal

Create a service principal with permissions to deploy:

```bash
# Create service principal with Contributor role on the resource group
az ad sp create-for-rbac \
  --name "onebighead-github-actions" \
  --role Contributor \
  --scopes /subscriptions/<subscription-id>/resourceGroups/onebighead-rg \
  --sdk-auth
```

Save the JSON output - you'll need it for GitHub secrets.

Additionally, grant the service principal SQL Azure admin access for migrations:

```bash
# Get the service principal object ID
SP_OBJECT_ID=$(az ad sp show --id <clientId-from-json> --query id -o tsv)

# Add as SQL Azure AD admin
az sql server ad-admin create \
  --resource-group onebighead-rg \
  --server <sql-server-name> \
  --display-name "GitHub Actions" \
  --object-id $SP_OBJECT_ID
```

#### 3. Configure GitHub Repository Secrets

In your GitHub repository, go to **Settings → Secrets and variables → Actions** and add:

| Secret Name | Description | Required |
|-------------|-------------|----------|
| `AZURE_CREDENTIALS` | Full JSON output from service principal creation | Yes |
| `AZURE_APP_NAME` | Base name for Azure resources (e.g., `onebighead`) | Yes |
| `AZURE_LOCATION` | Azure region (e.g., `eastus`) | Yes |
| `JWT_SIGNING_KEY` | JWT signing key (min 32 characters) | Yes |
| `SQL_ADMIN_PASSWORD` | SQL admin password (from initial deployment) | Yes |
| `MICROSOFT_CLIENT_ID` | Microsoft OAuth client ID | If using Microsoft auth |
| `MICROSOFT_CLIENT_SECRET` | Microsoft OAuth client secret | If using Microsoft auth |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | If using Google auth |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | If using Google auth |
| `APPLE_CLIENT_ID` | Apple OAuth client ID | If using Apple auth |
| `APPLE_CLIENT_SECRET` | Apple OAuth client secret | If using Apple auth |

#### 4. Configure GitHub Environment (Optional but Recommended)

Create a `production` environment in **Settings → Environments**:
- Add required reviewers for deployment approval
- Configure environment-specific secrets if needed
- Set deployment branch restrictions to `main`

### Pipeline Workflow

When a PR is merged to `main`:

1. **Test Job** runs unit and integration tests
2. **Deploy Job** (requires test success):
   - Builds frontend and backend
   - Generates migration script
   - Builds and pushes Docker image to ACR
   - Updates Container App with new image (creates new revision)
   - Runs database migrations
   - Verifies health check

### Container Revision Management

Azure Container Apps automatically manages revisions:
- Each deployment creates a new revision with the commit SHA as the image tag
- The `az containerapp update` command activates the new revision
- Old revisions are automatically deactivated (but retained for rollback)
- Traffic automatically routes to the new active revision

To rollback to a previous revision:

```bash
# List revisions
az containerapp revision list \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --output table

# Activate a specific revision
az containerapp revision activate \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --revision <revision-name>
```

### Monitoring Deployments

View deployment logs in GitHub Actions, or check Container App logs:

```bash
az containerapp logs show \
  --name onebighead-app \
  --resource-group onebighead-rg \
  --follow
```
