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
