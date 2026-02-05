# Code Style and Conventions

## Backend (.NET/C#)

### Naming
- Classes/Methods: PascalCase (e.g., `CollectionRepository`, `GetByIdAsync`)
- Parameters/Variables: camelCase (e.g., `collectionId`, `workspaceId`)
- Interfaces: Prefix with I (e.g., `ICollectionRepository`)
- Async methods: Suffix with Async (e.g., `CreateAsync`)

### Patterns
- Repository pattern for all data access
- Constructor dependency injection
- DTOs for API request/response objects
- Controllers inherit from `ApiControllerBase`

### Testing
- xUnit test framework
- Test classes named `*Tests.cs`
- Arrange-Act-Assert pattern

## Frontend (React/TypeScript)

### Naming
- Components: PascalCase files and exports (e.g., `CollectionView.tsx`)
- Hooks: camelCase with use prefix (e.g., `useData()`, `useUser()`)
- API modules: camelCase (e.g., `collectionsApi`)
- Types/Interfaces: PascalCase (e.g., `Collection`, `CreateItemRequest`)

### Patterns
- Functional components with hooks (no class components)
- Context API for global state (DataContext, UserContext)
- All API calls through centralized `api/` modules
- Lazy loading routes with React.lazy() + Suspense
- TypeScript strict mode

### CSS
- BEM naming convention (e.g., `setupWizard__container`, `setupWizard__header--active`)
- Separate CSS files per component/view
- No CSS framework (pure CSS)

### Testing
- Vitest + Testing Library
- Test files in `tests/` directory or co-located as `*.test.tsx`
- Focus on user interaction testing
