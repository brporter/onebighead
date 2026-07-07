#!/bin/bash
# dev-start.sh
# Development startup script for macOS/Linux
# Starts PostgreSQL, builds and tests, then launches backend and frontend

set -e

RESET_DATABASE=false
SKIP_TESTS=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CONTAINER_NAME="onebighead-postgres"
BACKEND_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

show_help() {
    cat << EOF
dev-start.sh - Development startup script

Usage: ./dev-start.sh [options]

Options:
    --reset-database    Reset the database before starting
    --skip-tests        Skip running tests (faster startup)
    -h, --help          Show this help message

This script will:
    1. Start the PostgreSQL Docker container if not running
    2. Restore tools, run tests, and build backend (produces efbundle)
    3. Apply migrations (or reset database if requested)
    4. Start the backend (displays PID)
    5. Build and start the frontend dev server
EOF
    exit 0
}

cleanup() {
    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo ""
        echo -e "${YELLOW}Frontend stopped.${NC}"
        read -p "Stop backend process $BACKEND_PID? (Y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            kill "$BACKEND_PID" 2>/dev/null || true
            echo -e "${GREEN}Backend stopped.${NC}"
        else
            echo -e "${YELLOW}Backend still running (PID: $BACKEND_PID)${NC}"
        fi
    fi
}

trap cleanup EXIT

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --reset-database)
            RESET_DATABASE=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo ""
            show_help
            exit 1
            ;;
    esac
done

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  OneBigHead Development Startup${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Step 1: Check/Start PostgreSQL container
echo -e "${YELLOW}[1/5] Checking PostgreSQL container...${NC}"
if ! docker ps --filter "name=$CONTAINER_NAME" --format "{{.Names}}" | grep -q "$CONTAINER_NAME"; then
    echo -e "${CYAN}      PostgreSQL not running. Starting via docker compose...${NC}"
    cd "$REPO_ROOT"
    docker compose up -d
    
    # Wait for PostgreSQL to be ready
    echo -e "${CYAN}      Waiting for PostgreSQL to be ready...${NC}"
    retries=30
    while [ $retries -gt 0 ]; do
        health=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
        if [ "$health" = "healthy" ]; then
            break
        fi
        sleep 2
        retries=$((retries - 1))
        echo -e "${GRAY}      Waiting... ($retries retries left)${NC}"
    done
    
    if [ $retries -eq 0 ]; then
        echo -e "${RED}      Error: PostgreSQL did not become ready in time${NC}"
        exit 1
    fi
    echo -e "${GREEN}      PostgreSQL is ready!${NC}"
else
    echo -e "${GREEN}      PostgreSQL is already running.${NC}"
fi

# Step 2: Restore tools, run tests, and build backend
echo ""
echo -e "${YELLOW}[2/5] Building and testing backend...${NC}"

echo -e "${CYAN}      Restoring tools...${NC}"
cd "$REPO_ROOT"
dotnet tool restore --verbosity minimal

echo -e "${CYAN}      Restoring packages...${NC}"
cd "$REPO_ROOT/backend/src/backend"
if ! dotnet restore --verbosity minimal; then
    echo -e "${RED}      Package restore failed!${NC}"
    exit 1
fi

if [ "$SKIP_TESTS" = false ]; then
    echo -e "${CYAN}      Running tests...${NC}"
    cd "$REPO_ROOT/backend/tests/backend.tests"
    if ! dotnet test --no-restore --verbosity minimal; then
        echo -e "${RED}      Backend tests failed!${NC}"
        exit 1
    fi
    echo -e "${GREEN}      Tests passed!${NC}"
else
    echo -e "${GRAY}      Skipping tests (remove --skip-tests to run)${NC}"
fi

echo -e "${CYAN}      Building backend...${NC}"
cd "$REPO_ROOT/backend/src/backend"
if ! dotnet build --no-restore --verbosity minimal; then
    echo -e "${RED}      Backend build failed!${NC}"
    exit 1
fi
echo -e "${GREEN}      Backend build succeeded!${NC}"

echo -e "${CYAN}      Creating migration bundle...${NC}"
cd "$REPO_ROOT/backend/src/backend"
if ! dotnet ef migrations bundle --force --no-build; then
    echo -e "${RED}      Migration bundle creation failed!${NC}"
    exit 1
fi
echo -e "${GREEN}      Migration bundle created.${NC}"

# Step 3: Apply migrations (or reset database if requested)
echo ""
if [ "$RESET_DATABASE" = true ]; then
    echo -e "${YELLOW}[3/5] Resetting database...${NC}"
    "$SCRIPT_DIR/reset-database.sh" --force
    echo -e "${GREEN}      Database reset complete.${NC}"
else
    echo -e "${YELLOW}[3/5] Applying pending migrations...${NC}"
    EFBUNDLE="$REPO_ROOT/backend/src/backend/efbundle"
    if [ -f "$EFBUNDLE" ]; then
        "$EFBUNDLE" --connection "Host=localhost;Port=5432;Database=onebighead;Username=postgres;Password=DevPassword123!"
        echo -e "${GREEN}      Migrations applied.${NC}"
    else
        echo -e "${YELLOW}      Warning: efbundle not found.${NC}"
    fi
fi

# Step 4: Start backend
echo ""
echo -e "${YELLOW}[4/5] Starting backend...${NC}"
cd "$REPO_ROOT/backend/src/backend"
dotnet run --no-build &
BACKEND_PID=$!

echo ""
echo -e "${CYAN}      ┌─────────────────────────────────────────┐${NC}"
printf "${CYAN}      │  BACKEND PROCESS ID: %-17s │${NC}\n" "$BACKEND_PID"
printf "${CYAN}      │  To stop: kill %-22s │${NC}\n" "$BACKEND_PID"
echo -e "${CYAN}      └─────────────────────────────────────────┘${NC}"
echo ""

# Give backend a moment to start
echo -e "${GRAY}      Waiting for backend to initialize...${NC}"
sleep 3

# Step 5: Build and start frontend
echo ""
echo -e "${YELLOW}[5/5] Building and starting frontend...${NC}"
cd "$REPO_ROOT/frontend"

echo -e "${CYAN}      Installing dependencies...${NC}"
npm install --silent

echo -e "${CYAN}      Starting Vite dev server...${NC}"
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Development environment ready!${NC}"
echo -e "${GREEN}  Backend PID: $BACKEND_PID${NC}"
echo -e "${GREEN}  Frontend: Starting below...${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Run npm dev in the foreground so user can see output and Ctrl+C to stop
npm run dev
