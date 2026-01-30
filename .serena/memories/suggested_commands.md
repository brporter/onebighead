# Suggested Commands

## Development Startup (Recommended)
```bash
./dev-start.sh               # macOS - starts Docker, runs tests, launches backend + frontend
./dev-start.sh --skip-tests  # Skip tests for faster startup
./dev-start.sh --reset-database  # Reset database first
```

## Backend (.NET 10)
```bash
cd backend
dotnet run                        # Run the API server (port 5043)
dotnet build                      # Build only
dotnet test ../backend.tests      # Run all backend tests
dotnet ef migrations add <Name>   # Create new migration after model changes
```

## Frontend (React 19 + Vite)
```bash
cd frontend
npm install                       # Install dependencies
npm run dev                       # Start Vite dev server (port 5173)
npm run build                     # Production build
npm run lint                      # Run ESLint
npm run test                      # Run tests in watch mode
npm run test:run                  # Single test run
npm run test:coverage             # Tests with coverage
```

## Database
```bash
docker compose up -d              # Start local SQL Server
docker ps --filter "name=onebighead"  # Verify container running
./reset-database.sh               # Reset local database (drop and recreate)
./reset-database.sh --force       # Skip confirmation
```

## Testing
```bash
# Backend
cd backend.tests && dotnet test

# Frontend  
cd frontend && npm run test:run
cd frontend && npm run test:coverage
```

## System Utilities (macOS/Darwin)
```bash
git status / git diff / git log   # Git operations
ls -la                            # List files
grep -r "pattern" .               # Search in files
find . -name "*.cs"               # Find files
```
