# OneBigHead

A multi-workspace collection management application with a .NET 10 backend API and React 19 frontend. Users can create collections of items organized into hierarchical categories, with support for custom item templates, image uploads, and public/private visibility controls.

## Project Structure

```
onebighead/
├── backend/                        # All backend-related projects
│   ├── src/backend/                # Main .NET API project
│   ├── src/backend.generators/     # Roslyn source generators
│   ├── tests/backend.tests/        # xUnit tests
│   ├── grafana/                     # Grafana dashboard config
│   ├── seeds/                      # Database seed JSON files
│   └── tools/                      # DB utilities (dbreset, dbseed)
├── frontend/                       # React 19 + Vite frontend
├── deployment/                     # Deployment artifacts
│   ├── infra/                      # Azure Bicep templates
│   ├── build/                      # Build scripts
│   ├── deploy.sh / deploy.ps1     # Infrastructure provisioning
│   └── Dockerfile                  # Production container image
├── scripts/                        # Development utility scripts
│   ├── dev-start.sh / .ps1        # Full dev environment startup
│   └── reset-database.sh / .ps1   # Database reset
├── docs/                           # Documentation
└── docker-compose.yml              # Local SQL Server
```

## Quick Start

```bash
# Start everything (SQL Server, tests, backend, frontend)
./scripts/dev-start.sh       # macOS/Linux
./scripts/dev-start.ps1      # Windows
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed setup instructions.

## Documentation

- [Development Setup](docs/DEVELOPMENT.md) - Local development environment and workflow
- [Deployment Guide](docs/DEPLOYMENT.md) - Azure deployment and infrastructure
- [CI/CD Pipeline](docs/PIPELINE.md) - GitHub Actions workflow documentation
- [Observability](docs/OBSERVABILITY.md) - Monitoring, tracing, and telemetry
