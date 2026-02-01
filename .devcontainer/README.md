# OneBigHead DevContainer

This directory contains the configuration for developing OneBigHead in a containerized environment using VS Code Dev Containers or GitHub Codespaces.

## What's Included

The devcontainer provides a complete development environment with:

- **.NET 10 SDK** - For backend development and testing
- **Node.js 22** - For frontend development (React 19 + Vite)
- **Git & GitHub CLI** - For version control and GitHub operations
- **SQL Server** - Automatically started via Docker Compose
- **VS Code Extensions** - Pre-configured extensions for C#, TypeScript, React, and more

## Using with GitHub Codespaces

1. Navigate to the repository on GitHub
2. Click the **Code** button
3. Select the **Codespaces** tab
4. Click **Create codespace on main** (or your desired branch)

The environment will automatically:
- Install all dependencies (frontend and backend)
- Start SQL Server
- Run tests to verify the setup
- Forward ports for easy access (Backend: 5149, Frontend: 5173, SQL: 1433)

## Using with VS Code Dev Containers

### Prerequisites
- [Visual Studio Code](https://code.visualstudio.com/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

### Steps
1. Clone the repository
2. Open the repository in VS Code
3. When prompted, click **Reopen in Container**
   - Or use Command Palette (F1) → "Dev Containers: Reopen in Container"

## Starting the Application

After the container is ready, you can start the application:

### Option 1: Use the Dev Start Script (Recommended)
```bash
./dev-start.sh
```

This will start both backend and frontend with a single command.

### Option 2: Start Services Manually

**Backend:**
```bash
cd backend
dotnet run
```

**Frontend:**
```bash
cd frontend
npm run dev
```

## Port Forwarding

The following ports are automatically forwarded:

- **5149** - Backend API (ASP.NET Core)
- **5173** - Frontend Dev Server (Vite)
- **1433** - SQL Server

In GitHub Codespaces, these ports are accessible via the Ports panel. The frontend dev server will automatically open in your browser.

## Database Configuration

The SQL Server instance is automatically configured with:
- **Server:** localhost:1433
- **Username:** sa
- **Password:** DevPassword123!
- **Database:** onebighead (created automatically on first run)

The backend is pre-configured to connect to this database via environment variables.

## User Secrets

OAuth provider secrets are not included in the container. Configure them after the container starts:

```bash
cd backend
dotnet user-secrets set "Authentication:Providers:Microsoft:ClientSecret" "<your-secret>"
```

See [DEVELOPMENT.md](../DEVELOPMENT.md) for more details on user secrets configuration.

## Troubleshooting

### SQL Server Not Ready
If you get connection errors, SQL Server might still be starting. Wait a few moments and try again.

### Port Already in Use
If ports are in use, stop any local instances of the application or SQL Server before starting the container.

### Dependencies Not Installed
The post-create script should handle this automatically, but if needed:

```bash
# Frontend
cd frontend && npm install

# Backend
cd backend && dotnet restore
```

## Customization

The devcontainer configuration can be customized by editing:

- **devcontainer.json** - VS Code settings, extensions, and features
- **docker-compose.devcontainer.yml** - Container networking and dependencies
- **post-create.sh** - Setup script that runs after container creation

## More Information

- [Dev Containers Documentation](https://code.visualstudio.com/docs/devcontainers/containers)
- [GitHub Codespaces Documentation](https://docs.github.com/en/codespaces)
- [Project Development Guide](../DEVELOPMENT.md)
