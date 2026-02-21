# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OneBigHead is a multi-workspace collection management application with a .NET 10 backend API and React 19 frontend. Users can create collections of items organized into hierarchical categories, with support for custom item templates, image uploads, and public/private visibility controls.

This project is worked on from different machines running different operating systems. When on Windows, use cmd or PowerShell when navigating the project and executing commands (such as building, etc.)

When making edits, always first execute unit tests and verify that all unit tests are passing BEFORE performing any edits. When your edits are complete, re-run ALL unit tests, and verify that all unit tests are passing. Even if a unit test is failing and it is not related to a change you made, that unit test MUST be fixed completely prior to proceeding.

Ensure ALL new code or edits include corresponding unit tests. Code coverage MUST be 100% for all new code or edits.

## Commands

### Development Startup

```bash
# Full startup (recommended) - starts Docker SQL Server, runs tests, launches backend and frontend
./scripts/dev-start.sh                    # macOS/Linux
./scripts/dev-start.ps1                   # Windows

# Options
--skip-tests / -SkipTests        # Skip tests for faster startup
--reset-database / -ResetDatabase # Reset database first
```

### Backend (.NET 10)

```bash
cd backend/src/backend
dotnet run                        # Run the API server
dotnet test ../../tests/backend.tests     # Run all backend tests
dotnet ef migrations add <Name>   # Create new migration after model changes
```

### Frontend (React 19 + Vite)

```bash
cd frontend
npm run dev                       # Start Vite dev server
npm run build                     # Production build
npm run lint                      # Run ESLint
npm run test                      # Run tests in watch mode
npm run test:run                  # Single test run
npm run test:coverage             # Tests with coverage
```

### Database

```bash
docker compose up -d              # Start local SQL Server
./scripts/reset-database.sh       # Reset local database (drop and recreate)
```

## Architecture

### Backend Structure

```
backend/
├── src/
│   ├── backend/             # Main API project
│   │   ├── Controllers/     # API endpoints (see "When to use ApiControllerBase" below)
│   │   ├── Models/          # EF Core entities
│   │   ├── Data/            # Repository pattern (I*Repository interfaces + implementations)
│   │   ├── DTOs/            # Request/response data transfer objects
│   │   ├── Services/        # Business logic services
│   │   └── Authentication/  # Custom cookie-based JWT authentication
│   └── backend.generators/  # Roslyn source generators
├── tests/
│   └── backend.tests/       # xUnit tests
├── grafana/                 # Grafana dashboard config
├── seeds/                   # Database seed JSON files
└── tools/                   # DB utilities (dbreset, dbseed)
```

**Controllers:**
- Inherit from `ApiControllerBase` for workspace-scoped endpoints (Collections, Items, Categories, etc.)
- Inherit from `ControllerBase` directly for: authentication, system-wide data, cross-workspace admin, or anonymous endpoints

**DTOs:**
- All request/response classes go in `DTOs/` folder (not inline in controllers)
- Organize by domain: `CollectionRequests.cs`, `CategoryRequests.cs`, `AuthRequests.cs`, etc.

Key patterns:
- Multi-workspace: All data access is scoped by `WorkspaceId` via repository methods
- Visibility: Items/categories/collections have `isPublicOverride` and computed `effectiveIsPublic`
- Migrations run automatically in Debug builds; use migration bundles for production

### Frontend Structure

```
frontend/src/
├── api/                  # Type-safe API client modules
├── components/           # React components organized by domain
│   ├── common/          # Reusable UI components (BackNav, ImageGallery, etc.)
│   ├── category/        # Category-related components
│   ├── collection/      # Collection-related components
│   ├── item/            # Item-related components
│   ├── support/         # Support ticket components
│   ├── template/        # Template editor components
│   ├── user/            # User-related components
│   └── wizard/          # Setup wizard components
├── contexts/            # React contexts (UserContext, DataContext)
├── utils/               # Utility functions and type definitions
├── views/               # Route-level page components
├── styles/              # CSS files
│   ├── App.css          # Base styles and CSS custom properties
│   └── components/      # Component-specific CSS (for new components)
├── App.tsx              # Main app component
├── main.tsx             # Entry point
└── router.tsx           # React Router configuration
```

**Component naming conventions:**
- `*View` - Route-level page components (in `views/`)
- `*Modal` - Modal dialog components
- `*Editor` - Data entry/editing components
- `*List` - List display components
- `*Card` - Card-style display components

**CSS organization:**
- Base styles and CSS custom properties are in `styles/App.css`
- New component-specific styles should go in `styles/components/` or co-located with the component
- Use BEM naming: `.component`, `.component__element`, `.component--modifier`

Key patterns:
- All API calls go through the centralized `api/` modules, never direct fetch
- `DataContext` provides data operations and local caching throughout the app
- Routes are lazy-loaded with `React.lazy()` and `Suspense`
- Components use barrel exports (`index.ts`) for cleaner imports

### Data Flow

1. Frontend components use `DataContext` hooks for all data operations
2. DataContext calls typed API modules (`collectionsApi`, `itemsApi`, etc.)
3. API modules use the shared `api/client.ts` with consistent error handling
4. Backend controllers validate workspace context and delegate to repositories
5. Repositories use EF Core with SQL Server

### Domain Model

- **Workspace**: Multi-workspace container, has many Users and Collections
- **Collection**: Top-level container, has Categories and Items
- **Category**: Hierarchical (parent/child), can have ItemTemplates assigned
- **Item**: Belongs to Collection and optionally Category, has Properties and Images
- **ItemTemplate**: Defines property schema, can be system-wide or user-created
- **CollectionTheme**: Pre-built category/template bundles for quick collection setup
