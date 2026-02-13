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
   cd backend/src/backend
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

### Quick Start (Recommended)

Use the development startup script to launch everything:

**Windows (PowerShell):**
```powershell
./scripts/dev-start.ps1              # Start everything
./scripts/dev-start.ps1 -ResetDatabase   # Reset database first
./scripts/dev-start.ps1 -SkipTests       # Skip tests for faster startup
./scripts/dev-start.ps1 -Help            # Show all options
```

**macOS/Linux (Bash):**
```bash
./scripts/dev-start.sh               # Start everything
./scripts/dev-start.sh --reset-database  # Reset database first
./scripts/dev-start.sh --skip-tests      # Skip tests for faster startup
./scripts/dev-start.sh --help            # Show all options
```

The script will:
1. Start SQL Server Docker container if not running
2. Optionally reset the database
3. Run backend tests and build
4. Start the backend (displays PID for easy management)
5. Start the Vite frontend dev server

### Manual Startup

#### Backend

```bash
cd backend/src/backend
dotnet run
```

#### Frontend

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
cd backend/src/backend
dotnet ef migrations add <MigrationName>
```

### Resetting the Database

To reset the local development database (drop all data and start fresh):

**Windows (PowerShell):**
```powershell
./scripts/reset-database.ps1          # With confirmation prompt
./scripts/reset-database.ps1 -Force   # Skip confirmation
```

**macOS/Linux (Bash):**
```bash
./scripts/reset-database.sh           # With confirmation prompt
./scripts/reset-database.sh --force   # Skip confirmation
```

After resetting, run the backend to recreate the database with fresh migrations:

```bash
cd backend/src/backend
dotnet run
```

### Production (SQL Azure)

Production uses a migration bundle strategy. The bundle is a self-contained executable that applies migrations.

#### Creating a Migration Bundle

```bash
cd backend/src/backend
dotnet ef migrations bundle --configuration Release --output ../../../publish/efbundle.exe
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

## System Administration

### Bootstrapping Administrators

System administrators are users with elevated privileges who can manage tenants, users, and system templates. After deployment, bootstrap initial administrators by running:

```sql
-- From backend/src/backend/Scripts/bootstrap-admins.sql
UPDATE Users 
SET IsSystemAdministrator = 1 
WHERE Email = 'bryan@bryanporter.com';
```

Or using sqlcmd:

```bash
sqlcmd -S localhost -U sa -P "DevPassword123!" -d onebighead -i backend/src/backend/Scripts/bootstrap-admins.sql
```

### Admin Capabilities

System administrators have access to `/admin` which provides:
- **Tenant Management**: View all tenants with usage statistics (users, collections, items, images), delete tenants
- **User Management**: Search users by email, view user details, grant/revoke admin privileges, delete users
- **System Templates**: Create and manage system-level item templates available to all users

## Frontend Architecture

### API Client

The frontend uses a centralized API client located in `frontend/src/api/`. This provides:
- Type-safe API methods for all endpoints
- Centralized error handling
- Request cancellation support
- Consistent authentication headers

**Usage:**

```typescript
import { collectionsApi, itemsApi, ApiError } from './api';

// Get all collections
const collections = await collectionsApi.getAll();

// Create an item
const item = await itemsApi.create(newItem);

// Handle errors
try {
  await collectionsApi.delete(id);
} catch (error) {
  if (error instanceof ApiError) {
    console.error(`API Error: ${error.message} (${error.status})`);
  }
}
```

**Available API modules:**
- `collectionsApi` - Collection CRUD
- `categoriesApi` - Category CRUD
- `itemsApi` - Item CRUD with ETag support
- `imagesApi` - Image upload/delete
- `templatesApi` - Item template management
- `suggestionsApi` - Property suggestions
- `authApi` - Authentication
- `adminApi` - System administration
- `exportApi` - Data export

### Code Splitting

Routes are lazy-loaded using `React.lazy()` and `Suspense` for better initial load performance. The main bundle is kept small while route-specific code loads on-demand.

## Testing

### Backend Tests

```bash
cd backend/tests/backend.tests
dotnet test
```

Coverage report is generated in `backend/tests/backend.tests/TestResults/`.

### Frontend Tests

```bash
cd frontend
npm run test        # Watch mode
npm run test:run    # Single run
npm run test:coverage  # With coverage
```
