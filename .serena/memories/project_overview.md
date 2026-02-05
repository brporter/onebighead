# OneBigHead Project Overview

## Purpose
OneBigHead is a multi-workspace collection management SaaS application. Users can create collections of items organized into hierarchical categories, with support for custom item templates, image uploads, and public/private visibility controls.

## Tech Stack
- **Backend**: .NET 10.0 with ASP.NET Core, Entity Framework Core
- **Frontend**: React 19 with TypeScript, Vite build tool, React Router v7
- **Database**: SQL Server (Docker locally, SQL Azure in production)
- **Authentication**: OAuth 2.0/OIDC with Microsoft, Google, and Apple providers
- **Testing**: xUnit (backend), Vitest + Testing Library (frontend)

## Architecture

### Backend Structure
- `Controllers/` - API endpoints inheriting from `ApiControllerBase` (provides workspace context)
- `Models/` - EF Core entities (Collection, Category, Item, ItemTemplate, User, Workspace, etc.)
- `Data/` - Repository pattern with interfaces (I*Repository) and implementations, plus AppDbContext
- `DTOs/` - Data transfer objects for API requests/responses
- `Services/` - Business logic (ImageProvider, VisibilityService, etc.)
- `Authentication/` - Custom cookie-based JWT authentication scheme

### Frontend Structure
- `src/api/` - Type-safe API client modules (never use direct fetch)
- `src/views/` - Route-level page components
- `src/DataContext.tsx` - Central React context for data operations with caching
- `src/UserContext.tsx` - User authentication state
- `src/types.ts` - TypeScript interfaces matching backend DTOs
- `src/router.tsx` - React Router configuration with lazy-loaded routes
- `tests/` - Component and integration tests

### Key Patterns
- Multi-workspace: All data access scoped by WorkspaceId via repository methods
- Repository Pattern: All database access through repository interfaces
- Context API: React state management via DataContext and UserContext
- Lazy Loading: Routes use React.lazy() and Suspense
- BEM CSS: Naming convention like `setupWizard__container`

### Domain Model
- **Workspace**: Multi-workspace container, has Users and Collections
- **Collection**: Top-level container, has Categories and Items
- **Category**: Hierarchical (parent/child), can have ItemTemplates assigned
- **Item**: Belongs to Collection and optionally Category, has Properties and Images
- **ItemTemplate**: Defines property schema (system-wide or user-created)
- **CollectionTheme**: Pre-built category/template bundles for quick setup
