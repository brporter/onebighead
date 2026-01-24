# Development Setup

## Prerequisites

- .NET 10.0 SDK
- Node.js (for frontend)
- Docker (for local SQL Server)

## Local SQL Server Setup

This project uses SQL Server for all environments. For local development, use Docker:

```bash
# Start the local SQL Server instance
docker compose up -d

# Verify it's running
docker ps --filter "name=onebighead-sqlserver"
```

The SQL Server instance will be available at `localhost:1433` with:
- Username: `sa`
- Password: `DevPassword123!`
- Database: `onebighead` (created automatically on first run)

## User Secrets Configuration

This project uses .NET User Secrets to store sensitive configuration values during development. User secrets are stored outside the repository, preventing accidental commits of sensitive data.

### Required Secrets

The following secrets must be configured before running the backend:

| Secret Key | Description |
|------------|-------------|
| `Authentication:Providers:Microsoft:ClientSecret` | Microsoft OAuth client secret |

### Setting Up Secrets

1. Navigate to the backend project directory:
   ```bash
   cd backend
   ```

2. Set the required secrets:
   ```bash
   dotnet user-secrets set "Authentication:Providers:Microsoft:ClientSecret" "<your-secret-value>"
   ```

3. Verify your secrets are configured:
   ```bash
   dotnet user-secrets list
   ```

### Additional OAuth Providers

If you're configuring additional OAuth providers (Google, Apple), add their secrets similarly:

```bash
dotnet user-secrets set "Authentication:Providers:Google:ClientSecret" "<your-google-secret>"
dotnet user-secrets set "Authentication:Providers:Apple:ClientSecret" "<your-apple-secret>"
```

## Running the Application

### Backend

```bash
cd backend
dotnet run
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Database Migrations

### Development

In Debug builds, migrations run automatically on application startup. The database is created and migrated automatically when you run the backend.

To create a new migration after modifying models:

```bash
cd backend
dotnet ef migrations add <MigrationName>
```

### Resetting the Database

To reset the local development database (drop all data and start fresh):

```powershell
# From the repository root
./reset-database.ps1

# Skip confirmation prompt
./reset-database.ps1 -Force
```

After resetting, run the backend to recreate the database with fresh migrations:

```bash
cd backend
dotnet run
```

### Production (SQL Azure)

Production uses a migration bundle strategy. The bundle is a self-contained executable that applies migrations.

#### Creating a Migration Bundle

```bash
cd backend
dotnet ef migrations bundle --configuration Release --output ../publish/efbundle.exe
```

#### Applying Migrations with the Bundle

The bundle includes the connection string from appsettings, or you can override it:

```bash
# Using embedded connection string
./efbundle.exe

# Overriding connection string
./efbundle.exe --connection "Server=tcp:YOUR_SERVER.database.windows.net,1433;Database=onebighead;..."
```

For CI/CD pipelines, the bundle can be deployed alongside the application and executed before starting the app.
