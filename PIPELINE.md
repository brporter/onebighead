# CI/CD Pipeline Configuration Guide

This guide provides step-by-step instructions for configuring the GitHub Actions deployment pipeline for OneBigHead.

## Overview

The deployment pipeline automatically deploys to Azure Container Apps when a pull request is merged to the `main` branch. Before the pipeline can run, you must:

1. Provision Azure infrastructure (one-time)
2. Create an Azure service principal for GitHub Actions
3. Configure GitHub repository secrets
4. (Optional) Set up a GitHub environment with deployment protection

---

## Step 1: Provision Azure Infrastructure

The pipeline does **not** provision infrastructure. You must run the deployment script once to create all Azure resources.

```bash
./deploy.sh \
  --name <your-app-name> \
  --location <azure-region> \
  --jwt-key "<your-jwt-signing-key>"
```

**Example:**
```bash
./deploy.sh \
  --name onebighead \
  --location eastus \
  --jwt-key "MySecureJwtSigningKey32CharsMin!"
```

**What this creates:**
- Resource Group: `<app-name>-rg`
- Azure Container Registry: `<app-name>acr`
- SQL Azure Server: `<app-name>-sql-<random>` (globally unique)
- SQL Azure Database: `<app-name>`
- Container Apps Environment: `<app-name>-env`
- Container App: `<app-name>-app`
- Managed Identity: `<app-name>-identity`

**Save these values** from the deployment output:
- SQL admin password (if auto-generated)
- SQL server name (includes random suffix)
- Application URL

---

## Step 2: Create Azure Service Principal

Create a service principal that GitHub Actions will use to authenticate with Azure.

### 2.1 Create the Service Principal

```bash
az ad sp create-for-rbac \
  --name "<app-name>-github-actions" \
  --role Contributor \
  --scopes /subscriptions/<subscription-id>/resourceGroups/<app-name>-rg \
  --sdk-auth
```

**Example:**
```bash
az ad sp create-for-rbac \
  --name "onebighead-github-actions" \
  --role Contributor \
  --scopes /subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/onebighead-rg \
  --sdk-auth
```

**Find your subscription ID:**
```bash
az account show --query id -o tsv
```

**Output** (save this entire JSON - you'll need it for `AZURE_CREDENTIALS`):
```json
{
  "clientId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "clientSecret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "subscriptionId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "activeDirectoryEndpointUrl": "https://login.microsoftonline.com",
  "resourceManagerEndpointUrl": "https://management.azure.com/",
  "activeDirectoryGraphResourceId": "https://graph.windows.net/",
  "sqlManagementEndpointUrl": "https://management.core.windows.net:8443/",
  "galleryEndpointUrl": "https://gallery.azure.com/",
  "managementEndpointUrl": "https://management.core.windows.net/"
}
```

### 2.2 Grant SQL Azure Admin Access

The service principal needs to run database migrations. Add it as a SQL Azure AD administrator:

```bash
# Get the service principal's object ID (use clientId from the JSON above)
SP_OBJECT_ID=$(az ad sp show --id <clientId> --query id -o tsv)

# Get your SQL server name
SQL_SERVER_NAME=$(az sql server list --resource-group <app-name>-rg --query "[0].name" -o tsv)

# Add as SQL AD admin
az sql server ad-admin create \
  --resource-group <app-name>-rg \
  --server $SQL_SERVER_NAME \
  --display-name "GitHub Actions" \
  --object-id $SP_OBJECT_ID
```

**Example:**
```bash
SP_OBJECT_ID=$(az ad sp show --id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx --query id -o tsv)
SQL_SERVER_NAME=$(az sql server list --resource-group onebighead-rg --query "[0].name" -o tsv)

az sql server ad-admin create \
  --resource-group onebighead-rg \
  --server $SQL_SERVER_NAME \
  --display-name "GitHub Actions" \
  --object-id $SP_OBJECT_ID
```

---

## Step 3: Configure GitHub Repository Secrets

Navigate to your GitHub repository:
1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret** for each secret below

### Required Secrets

| Secret Name | Description | How to Obtain |
|-------------|-------------|---------------|
| `AZURE_CREDENTIALS` | Service principal JSON for Azure authentication | Copy the entire JSON output from Step 2.1 |
| `AZURE_APP_NAME` | Base name used for all Azure resources | The `--name` value you used in `deploy.sh` (e.g., `onebighead`) |
| `AZURE_LOCATION` | Azure region where resources are deployed | The `--location` value you used in `deploy.sh` (e.g., `eastus`) |
| `JWT_SIGNING_KEY` | Secret key for signing JWT tokens | The `--jwt-key` value you used in `deploy.sh` (minimum 32 characters) |

### Optional Secrets

| Secret Name | Description | How to Obtain |
|-------------|-------------|---------------|
| `APP_DOMAIN` | Custom domain for OAuth redirects | Your custom domain (e.g., `onebighead.com`). If not set, uses the auto-generated Container App URL. |

### Secret Details

#### `APP_DOMAIN`

**Value:** Your custom domain name (without `https://`)

**Example value:** `onebighead.com`

If you've configured a custom domain for your Container App, set this secret to ensure OAuth redirect URIs use your custom domain instead of the auto-generated `*.azurecontainerapps.io` URL.

**When to use:**
- You have a custom domain configured in Azure Container Apps
- Your OAuth providers (Microsoft, Google, Apple) have redirect URIs configured with your custom domain

**If not set:** The pipeline will use the Container App's default URL (e.g., `myapp-app.azurecontainerapps.io`)

#### `AZURE_CREDENTIALS`

**Value:** The complete JSON object from Step 2.1

**Example value:**
```json
{"clientId":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx","clientSecret":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","subscriptionId":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx","tenantId":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx","activeDirectoryEndpointUrl":"https://login.microsoftonline.com","resourceManagerEndpointUrl":"https://management.azure.com/","activeDirectoryGraphResourceId":"https://graph.windows.net/","sqlManagementEndpointUrl":"https://management.core.windows.net:8443/","galleryEndpointUrl":"https://gallery.azure.com/","managementEndpointUrl":"https://management.core.windows.net/"}
```

> **Note:** Paste as a single line or preserve the JSON formatting exactly.

#### `AZURE_APP_NAME`

**Value:** The base name for your Azure resources (lowercase, no spaces or special characters)

**Example value:** `onebighead`

This value is used to derive all resource names:
- Resource Group: `onebighead-rg`
- Container Registry: `onebigheadacr`
- Container App: `onebighead-app`

#### `AZURE_LOCATION`

**Value:** The Azure region code

**Example value:** `eastus`

**Common values:** `eastus`, `eastus2`, `westus`, `westus2`, `westeurope`, `northeurope`, `southeastasia`

#### `JWT_SIGNING_KEY`

**Value:** A secure random string of at least 32 characters

**Example value:** `MySecureJwtSigningKey32Characters!`

**Generate a secure key:**
```bash
openssl rand -base64 32
```

> **Important:** Use the same value you used during initial deployment. Changing this will invalidate all existing user tokens.

---

## Step 4: Configure OAuth Provider Secrets (Optional)

If your application uses OAuth authentication, configure the appropriate provider secrets.

### Microsoft (Entra ID / Azure AD)

| Secret Name | Description |
|-------------|-------------|
| `MICROSOFT_CLIENT_ID` | Application (client) ID |
| `MICROSOFT_CLIENT_SECRET` | Client secret value |

**How to obtain:**

1. Go to [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID** → **App registrations**
2. Select your application (or create one: **New registration**)
3. **Client ID:** Copy from **Overview** → **Application (client) ID**
4. **Client Secret:** 
   - Go to **Certificates & secrets** → **Client secrets**
   - Click **New client secret**
   - Copy the **Value** (not the Secret ID) immediately - it won't be shown again

**Configure redirect URI:**
- Go to **Authentication** → **Add a platform** → **Web**
- Add redirect URI: `https://<your-app-url>/api/auth/callback/microsoft`

### Google

| Secret Name | Description |
|-------------|-------------|
| `GOOGLE_CLIENT_ID` | OAuth 2.0 Client ID |
| `GOOGLE_CLIENT_SECRET` | OAuth 2.0 Client Secret |

**How to obtain:**

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Select or create a project
3. Go to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. Select **Web application**
6. **Client ID:** Copy the generated Client ID
7. **Client Secret:** Copy the generated Client Secret

**Configure redirect URI:**
- Under **Authorized redirect URIs**, add: `https://<your-app-url>/api/auth/callback/google`

### Apple

| Secret Name | Description |
|-------------|-------------|
| `APPLE_CLIENT_ID` | Services ID (not App ID) |
| `APPLE_CLIENT_SECRET` | Generated client secret JWT |

**How to obtain:**

Apple Sign In requires more setup than other providers:

1. Go to [Apple Developer Portal](https://developer.apple.com/account)
2. **App ID:**
   - Go to **Certificates, Identifiers & Profiles** → **Identifiers**
   - Create an **App ID** with Sign In with Apple capability enabled
3. **Services ID (this is your Client ID):**
   - Create a **Services ID** under **Identifiers**
   - Enable **Sign In with Apple**
   - Configure the domain and return URL: `https://<your-app-url>/api/auth/callback/apple`
   - Copy the **Identifier** (e.g., `com.yourcompany.yourapp.signin`)
4. **Key for Client Secret:**
   - Go to **Keys** → **Create a key**
   - Enable **Sign In with Apple**
   - Download the `.p8` file and note the **Key ID**
5. **Generate Client Secret:**
   
   Apple requires a JWT as the client secret. Generate it using:
   ```bash
   # You'll need: Team ID, Key ID, Services ID, and the .p8 private key
   # Use a JWT library or online tool to create a JWT with:
   # - Header: {"alg": "ES256", "kid": "<Key ID>"}
   # - Payload: {
   #     "iss": "<Team ID>",
   #     "iat": <current timestamp>,
   #     "exp": <timestamp + 6 months max>,
   #     "aud": "https://appleid.apple.com",
   #     "sub": "<Services ID>"
   #   }
   # - Sign with the .p8 private key
   ```

> **Note:** Apple client secrets expire (max 6 months). You'll need to rotate them periodically.

---

## Step 5: Configure GitHub Environment (Recommended)

For additional security, create a protected environment:

1. Go to **Settings** → **Environments**
2. Click **New environment**
3. Name it `production`
4. Configure protection rules:
   - **Required reviewers:** Add team members who must approve deployments
   - **Wait timer:** Optional delay before deployment starts
   - **Deployment branches:** Restrict to `main` only

The pipeline is already configured to use the `production` environment.

---

## Step 6: Verify Configuration

### Test the Pipeline

1. Create a feature branch
2. Make a small change (e.g., update a comment)
3. Create a pull request to `main`
4. Merge the pull request
5. Watch the **Actions** tab for the deployment workflow

### Troubleshooting

**Pipeline doesn't trigger:**
- Ensure the PR was merged (not just closed)
- Check that the target branch is `main`

**Azure login fails:**
- Verify `AZURE_CREDENTIALS` contains valid JSON
- Check the service principal hasn't expired
- Ensure the subscription ID is correct

**Container push fails:**
- Verify `AZURE_APP_NAME` matches your actual resource names
- Check the service principal has Contributor role on the resource group

**Database migration fails:**
- Ensure the service principal is configured as SQL AD admin (Step 2.2)
- Check SQL Server firewall allows Azure services

**OAuth not working after deployment:**
- Verify client IDs and secrets are correct
- Check redirect URIs are configured in each provider's console
- Ensure the `Authentication__OAuth__BaseUrl` matches your app URL
- **If using a custom domain:** Set the `APP_DOMAIN` secret to your domain (e.g., `onebighead.com`)

---

## Secret Reference Summary

### Required Secrets

| Secret | Example Value | Source |
|--------|---------------|--------|
| `AZURE_CREDENTIALS` | `{"clientId":"...","clientSecret":"...","subscriptionId":"...","tenantId":"..."}` | `az ad sp create-for-rbac --sdk-auth` output |
| `AZURE_APP_NAME` | `onebighead` | Your chosen app name from `deploy.sh` |
| `AZURE_LOCATION` | `eastus` | Azure region from `deploy.sh` |
| `JWT_SIGNING_KEY` | `MySecureJwtSigningKey32Characters!` | Same value used in `deploy.sh --jwt-key` |

### Optional Secrets

| Secret | Example Value | Source |
|--------|---------------|--------|
| `APP_DOMAIN` | `onebighead.com` | Your custom domain (if configured) |

### OAuth Secrets (Optional)

| Secret | Example Value | Source |
|--------|---------------|--------|
| `MICROSOFT_CLIENT_ID` | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | Azure Portal → Entra ID → App registrations → Overview |
| `MICROSOFT_CLIENT_SECRET` | `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` | Azure Portal → Entra ID → App registrations → Certificates & secrets |
| `GOOGLE_CLIENT_ID` | `123456789-xxxxxxxxxx.apps.googleusercontent.com` | Google Cloud Console → Credentials → OAuth 2.0 Client IDs |
| `GOOGLE_CLIENT_SECRET` | `GOCSPX-xxxxxxxxxxxxxxxxxxxxxxxx` | Google Cloud Console → Credentials → OAuth 2.0 Client IDs |
| `APPLE_CLIENT_ID` | `com.yourcompany.yourapp.signin` | Apple Developer Portal → Services ID Identifier |
| `APPLE_CLIENT_SECRET` | `eyJhbGciOiJFUzI1NiIsImtpZCI6Ii...` | Generated JWT signed with Apple private key |

---

## Pipeline Workflow Summary

When a PR is merged to `main`:

```
┌─────────────────┐
│   check-merge   │  Verify PR was merged (not just closed)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│      test       │  Run unit tests (233) + integration tests (111)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     deploy      │  
│  ┌───────────┐  │  1. Build frontend + backend
│  │   Build   │  │  2. Generate migration script
│  └─────┬─────┘  │
│        ▼        │
│  ┌───────────┐  │  3. Build Docker image
│  │   Push    │  │  4. Push to Azure Container Registry
│  └─────┬─────┘  │
│        ▼        │
│  ┌───────────┐  │  5. Update Container App (new revision)
│  │  Deploy   │  │  6. Old revision automatically deactivated
│  └─────┬─────┘  │
│        ▼        │
│  ┌───────────┐  │  7. Run database migrations
│  │  Migrate  │  │
│  └─────┬─────┘  │
│        ▼        │
│  ┌───────────┐  │  8. Verify /health endpoint
│  │  Verify   │  │
│  └───────────┘  │
└─────────────────┘
```
