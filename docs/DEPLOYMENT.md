# Deploying OneBigHead

Production runs on the shell.betaporter.dev VM behind a shared Caddy reverse
proxy, with a PostgreSQL container on the same VM. Deployment is continuous:
merging a PR to `main` builds and publishes a Docker image, and watchtower on
the VM picks it up automatically.

## Architecture

```
GitHub Actions (on merge to main)
  ├─ run tests
  └─ build image, push ghcr.io/brporter/onebighead:latest
                                                      │
shell.betaporter.dev                                  │ polls every 5 min
  /opt/shared      caddy (TLS, reverse proxy)         │
                   watchtower ◄───────────────────────┘
  /opt/onebighead  app container ──► postgres container (same compose stack)
  /opt/phosphor    phosphor stack (unrelated app, same pattern)
```

- **Shared services** (`/opt/shared`, tracked in the `shared-infra` repo):
  Caddy terminates TLS for every app on the machine and proxies
  `onebighead.com` to this app's container over the shared external `web`
  Docker network. Watchtower redeploys any container labeled
  `com.centurylinklabs.watchtower.enable=true` when its image changes.
- **App stack** (`/opt/onebighead`, from `deploy/vm/`): an `app` service
  running `ghcr.io/brporter/onebighead:latest` plus a `postgres` service
  running the official `postgres:17` image, with secrets in a local `.env`
  file (see `deploy/vm/.env.example`).
- **Database**: the `postgres` container in the same compose stack, with data
  in the `pgdata` named volume. The pipeline does **not** touch it —
  migrations and seeding are run manually (see
  [Applying migrations](#applying-migrations) below).

## Pipeline flow (`.github/workflows/deploy.yml`)

1. `test` job — backend tests, frontend lint + build
2. `deploy` job — build frontend + backend into `publish/` (including the EF
   migration bundle and seeder), build the Docker image, push `:latest` +
   `:<sha>` to ghcr.io

Watchtower deploys the new image within ~5 minutes of the push. The pipeline
needs **no repository secrets** — the ghcr.io push uses the automatic
`GITHUB_TOKEN`. Rollback: push the previous image digest as `:latest` (or
`docker compose pull` a pinned tag on the VM).

When a release includes schema changes, run the migration bundle before (or
right after) the image lands — the app tolerates a brief window where code is
ahead of schema only if the migration is additive, so prefer running it first.

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

The `postgres` service initializes itself on first start from the `.env`
values: `POSTGRES_PASSWORD` sets the password for the `onebighead` role, and
the `onebighead` database is created automatically. The app connects over the
compose-internal network using `ConnectionStrings__DefaultConnection`
(`Host=postgres;...` — see `.env.example`); the database is not exposed
outside the VM.

Data lives in the `pgdata` named volume, so it survives container recreation
and image updates. Back it up with `pg_dump`:

```bash
cd /opt/onebighead
sudo docker compose exec postgres pg_dump -U onebighead onebighead > backup.sql
```

### 3. GitHub secrets

None. The pipeline pushes to ghcr.io with the automatic `GITHUB_TOKEN`.

The legacy secrets (`AZURE_*`, `JWT_SIGNING_KEY`, OAuth client IDs/secrets,
email settings) are no longer consumed — runtime values live in
`/opt/onebighead/.env` on the VM, and database operations are manual.

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

### Applying migrations

The published image includes a self-contained EF bundle at `/app/efbundle`
and the seeder at `/app/dbseed`. Run them from the VM against the postgres
container using the app container's own connection string:

```bash
cd /opt/onebighead
sudo docker compose exec app sh -c '/app/efbundle --connection "$ConnectionStrings__DefaultConnection"'
sudo docker compose exec app sh -c 'cd /app && ./dbseed seeds --force'
```

## History

The app previously deployed to Azure Container Apps with an Azure SQL
database. That pipeline, its Bicep provisioning, and the related scripts have
been removed — see git history if you need them.
