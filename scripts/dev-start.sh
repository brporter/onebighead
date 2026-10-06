#!/usr/bin/env bash
# Start the local database, verify the project, migrate/seed, and launch both servers.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"
RESET_DATABASE=false
SKIP_TESTS=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --reset-database) RESET_DATABASE=true ;;
        --skip-tests) SKIP_TESTS=true ;;
        -h|--help)
            echo "Usage: ./scripts/dev-start.sh [--reset-database] [--skip-tests]"
            echo "Requires .NET 10, Node 22+, and Docker. Ctrl+C stops both servers."
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

docker compose up --wait --wait-timeout 60 postgres
dotnet tool restore
if [ "$SKIP_TESTS" = false ]; then
    ./scripts/verify.sh
else
    dotnet restore onebighead.slnx
    cd frontend
    npm ci
    cd "$REPO_ROOT"
fi
dotnet build backend/src/backend --no-restore --verbosity minimal

cd backend/src/backend
if [ "$RESET_DATABASE" = true ]; then
    "$REPO_ROOT/scripts/reset-database.sh" --force
else
    ASPNETCORE_ENVIRONMENT=Development dotnet ef database update --no-build
    dotnet run --no-build -- --seed
fi

dotnet run --no-build &
BACKEND_PID=$!
cleanup() {
    if kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
cd "$REPO_ROOT/frontend"
echo "Backend PID: $BACKEND_PID. Frontend: http://localhost:5173"
npm run dev
