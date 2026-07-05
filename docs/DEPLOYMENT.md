# Deploying OneBigHead

Production runs on the shell.betaporter.dev VM behind a shared Caddy reverse
proxy, with the database remaining in Azure SQL. Deployment is continuous:
merging a PR to `main` builds and publishes a Docker image, and watchtower on
the VM picks it up automatically.

## Architecture

```
GitHub Actions (on merge to main)
  ├─ run tests
  ├─ apply EF migrations + seed data ──────────► Azure SQL (serverless)
  └─ build image, push ghcr.io/brporter/onebighead:latest
                                                      │
shell.betaporter.dev                                  │ polls every 5 min
  /opt/shared      caddy (TLS, reverse proxy)         │
                   watchtower ◄───────────────────────┘
  /opt/onebighead  app container (this repo, deploy/vm/docker-compose.yml)
  /opt/phosphor    phosphor stack (unrelated app, same pattern)
```

- **Shared services** (`/opt/shared`, tracked in the `shared-infra` repo):
  Caddy terminates TLS for every app on the machine and proxies
  `onebighead.com` to this app's container over the shared external `web`
  Docker network. Watchtower redeploys any container labeled
  `com.centurylinklabs.watchtower.enable=true` when its image changes.
- **App stack** (`/opt/onebighead`, from `deploy/vm/`): a single `app` service
  running `ghcr.io/brporter/onebighead:latest` with secrets in a local `.env`
  file (see `deploy/vm/.env.example`).
- **Database**: the existing Azure SQL serverless database. Migrations and
  seeding run from GitHub Actions, not from the VM.

## Pipeline flow (`.github/workflows/deploy.yml`)

1. `test` job — backend tests, frontend lint + build
2. `deploy` job:
   - build frontend + backend into `publish/`
   - generate idempotent EF migration script
   - open a temporary SQL firewall rule, apply migrations, seed reference
     data, close the rule (authenticated via Azure OIDC)
   - build the Docker image and push `:latest` + `:<sha>` to ghcr.io
   - poll `https://onebighead.com/health` for up to 10 minutes while
     watchtower swaps the container

Migrations run **before** the image is published, so new code never arrives
ahead of its schema. Rollback: push the previous image digest as `:latest`
(or `docker compose pull` a pinned tag on the VM).

## One-time setup

### 1. VM app stack

```bash
# On the VM
sudo mkdir -p /opt/onebighead
# Copy deploy/vm/docker-compose.yml to /opt/onebighead/
# Copy deploy/vm/.env.example to /opt/onebighead/.env and fill in values
cd /opt/onebighead
sudo docker compose up -d
```

The shared `web` network and the caddy/watchtower stack must already exist
(see the `shared-infra` repo).

### 2. Database access for the app

The SQL server is Entra-only (no SQL passwords). The app authenticates as the
VM's **system-assigned managed identity** — the VM (`shell`) requests tokens
from the Azure Instance Metadata Service, which containers reach by default,
so no credentials are stored anywhere.

The connection string in `/opt/onebighead/.env` uses
`Authentication=Active Directory Managed Identity` (see `.env.example`).

The identity needs a database user. Either set the `SQL_APP_PRINCIPAL_NAME`
GitHub secret to `shell` (the pipeline ensures the user on every deploy), or
create it once by hand as a SQL admin, connected to the app database:

```sql
CREATE USER [shell] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [shell];
ALTER ROLE db_datawriter ADD MEMBER [shell];
ALTER ROLE db_ddladmin ADD MEMBER [shell];
```

Also add an Azure SQL firewall rule allowing the VM's public IP so the app can
reach the database.

### 3. GitHub secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `AZURE_CLIENT_ID` | Yes | CI service principal (OIDC) — used for SQL firewall + migrations |
| `AZURE_TENANT_ID` | Yes | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Yes | Azure subscription ID |
| `AZURE_APP_NAME` | Yes | Base name of Azure resources (e.g., `onebighead`) |
| `APP_DOMAIN` | No | Public hostname; defaults to `onebighead.com` |
| `SQL_APP_PRINCIPAL_NAME` | No | Entra principal the VM app connects as — the VM's managed identity, i.e. `shell` (see above) |

The ACR/Container App secrets (`JWT_SIGNING_KEY`, OAuth client IDs/secrets,
email settings) are no longer consumed by the pipeline — those values now live
in `/opt/onebighead/.env` on the VM.

### 4. ghcr.io package visibility

The VM pulls anonymously, so the `onebighead` package must be **public**:
GitHub → your profile → Packages → `onebighead` → Package settings → Change
visibility. (Alternatively, `docker login ghcr.io` on the VM with a read-only
PAT and keep it private.)

### 5. DNS

Point `onebighead.com` (and `www`) at the VM's public IP. Caddy will obtain
certificates automatically once DNS resolves to the machine; until then it
retries issuance in the background without affecting other sites.

## Operations

```bash
# Watch a deploy land
sudo docker logs -f phosphor-watchtower-1   # shared watchtower (project name may vary)

# App logs
cd /opt/onebighead
sudo docker compose logs -f app

# Force an immediate pull instead of waiting for the 5-minute poll
sudo docker compose pull app
sudo docker compose up -d app
```

### Manual migration from the container

The published image includes a self-contained EF bundle at `/app/efbundle`
and the seeder at `/app/dbseed` if you ever need to run them by hand.

## Legacy Azure Container Apps deployment

The previous ACA-based pipeline and its Bicep provisioning are documented in
`docs/PIPELINE.md` and `deployment/`. The Bicep templates are still the source
of the Azure SQL server, Log Analytics, and Application Insights resources;
the Container App itself is no longer deployed to.
