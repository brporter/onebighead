# Task Completion Checklist

When completing a task, ensure the following:

## Code Quality
1. Code follows existing patterns and conventions in the codebase
2. No hardcoded values that should be configurable
3. Error handling is appropriate

## Backend Changes
1. Run tests: `cd backend.tests && dotnet test`
2. If models changed: Create migration with `dotnet ef migrations add <Name>`
3. Build succeeds: `cd backend && dotnet build`

## Frontend Changes  
1. Run lint: `cd frontend && npm run lint`
2. Run tests: `cd frontend && npm run test:run`
3. Build succeeds: `cd frontend && npm run build`

## Database Changes
1. Migration created if models changed
2. Migration tested with: `./reset-database.sh && dotnet run`
3. Consider backwards compatibility

## Testing
- Unit tests written for new functionality
- Existing tests still pass
- Test coverage maintained

## Before Committing
1. All tests pass (backend and frontend)
2. No lint errors
3. Code builds successfully
4. Review changes with `git diff`
