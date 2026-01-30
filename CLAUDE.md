# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OneBigHead is a multi-tenant collection management application with a .NET 10 backend API and React 19 frontend. Users can create collections of items organized into hierarchical categories, with support for custom item templates, image uploads, and public/private visibility controls.

## Commands

### Development Startup

```bash
# Full startup (recommended) - starts Docker SQL Server, runs tests, launches backend and frontend
./dev-start.sh                    # macOS/Linux
./dev-start.ps1                   # Windows

# Options
--skip-tests / -SkipTests        # Skip tests for faster startup
--reset-database / -ResetDatabase # Reset database first
```

### Backend (.NET 10)

```bash
cd backend
dotnet run                        # Run the API server
dotnet test ../backend.tests      # Run all backend tests
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
./reset-database.sh               # Reset local database (drop and recreate)
```

## Architecture

### Backend Structure

- **Controllers/**: API endpoints inheriting from `ApiControllerBase` which provides tenant context
- **Models/**: EF Core entities (Collection, Category, Item, ItemTemplate, User, Tenant, etc.)
- **Data/**: Repository pattern - interfaces (I*Repository) and implementations, plus `AppDbContext`
- **DTOs/**: Data transfer objects for API requests/responses
- **Services/**: Business logic (ImageProvider, VisibilityService, EmailService, TokenService)
- **Authentication/**: Custom cookie-based JWT authentication scheme

Key patterns:
- Multi-tenancy: All data access is scoped by `TenantId` via repository methods
- Visibility: Items/categories/collections have `isPublicOverride` and computed `effectiveIsPublic`
- Migrations run automatically in Debug builds; use migration bundles for production

### Frontend Structure

- **src/api/**: Type-safe API client modules (collections, items, categories, templates, etc.)
- **src/views/**: Route-level page components (CollectionView, CategoryView, ItemView, SettingsView)
- **src/DataContext.tsx**: Central React context managing all data operations with caching
- **src/types.ts**: TypeScript interfaces matching backend DTOs
- **src/router.tsx**: React Router configuration with lazy-loaded routes
- **tests/**: Component and integration tests using Vitest + Testing Library

Key patterns:
- All API calls go through the centralized `api/` modules, never direct fetch
- `DataContext` provides data operations and local caching throughout the app
- Routes are lazy-loaded with `React.lazy()` and `Suspense`

### Data Flow

1. Frontend components use `DataContext` hooks for all data operations
2. DataContext calls typed API modules (`collectionsApi`, `itemsApi`, etc.)
3. API modules use the shared `api/client.ts` with consistent error handling
4. Backend controllers validate tenant context and delegate to repositories
5. Repositories use EF Core with SQL Server

### Domain Model

- **Tenant**: Multi-tenant container, has many Users and Collections
- **Collection**: Top-level container, has Categories and Items
- **Category**: Hierarchical (parent/child), can have ItemTemplates assigned
- **Item**: Belongs to Collection and optionally Category, has Properties and Images
- **ItemTemplate**: Defines property schema, can be system-wide or user-created
- **CollectionTheme**: Pre-built category/template bundles for quick collection setup
