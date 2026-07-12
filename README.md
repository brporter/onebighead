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
├── deploy/vm/                      # Production VM compose stack (app + PostgreSQL)
├── deployment/                     # Deployment artifacts
│   ├── build/                      # Build scripts
│   └── Dockerfile                  # Production container image
├── scripts/                        # Development utility scripts
│   ├── dev-start.sh / .ps1        # Full dev environment startup
│   └── reset-database.sh / .ps1   # Database reset
├── docs/                           # Documentation
└── docker-compose.yml              # Local PostgreSQL
```

## Quick Start

```bash
# Start everything (PostgreSQL, tests, backend, frontend)
./scripts/dev-start.sh       # macOS/Linux
./scripts/dev-start.ps1      # Windows
```

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed setup instructions.

## Documentation

- [Development Setup](docs/DEVELOPMENT.md) - Local development environment and workflow
- [Deployment Guide](docs/DEPLOYMENT.md) - Production VM deployment and CI/CD pipeline
- [Observability](docs/OBSERVABILITY.md) - Monitoring, tracing, and telemetry
