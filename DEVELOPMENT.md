# Development Setup

## Prerequisites

- .NET 10.0 SDK
- Node.js (for frontend)

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

In development, migrations run automatically on application startup. The SQLite database (`development.db`) is created and migrated automatically.

To create a new migration after modifying models:

```bash
cd backend
dotnet ef migrations add <MigrationName>
```

### Production (SQL Azure)

Production uses SQL Azure and migrations must be applied separately using SQL scripts. **Do not run migrations automatically in production.**

#### Generating Migration Scripts

Generate an idempotent SQL script that can be safely run multiple times:

```bash
cd backend
dotnet ef migrations script --idempotent -o ../publish/migrate.sql
```

To generate a script for specific migrations (e.g., from a baseline):

```bash
dotnet ef migrations script <FromMigration> <ToMigration> --idempotent -o ../publish/migrate.sql
```

#### Applying Migrations to SQL Azure

Using Azure AD authentication:

```bash
sqlcmd -S <your-server>.database.windows.net -d onebighead -G -i ../publish/migrate.sql
```

Using SQL authentication:

```bash
sqlcmd -S <your-server>.database.windows.net -d onebighead -U <username> -P <password> -i ../publish/migrate.sql
```

From Azure Cloud Shell or CI/CD with Managed Identity:

```bash
sqlcmd -S <your-server>.database.windows.net -d onebighead --authentication-method=ActiveDirectoryManagedIdentity -i migrate.sql
```
