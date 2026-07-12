#!/bin/bash
# reset-database.sh
# Resets the local development database by dropping it, applying migrations via efbundle, and seeding.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CONTAINER_NAME="onebighead-postgres"
DATABASE_NAME="onebighead"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-DevPassword123!}"
FORCE=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--force)
            FORCE=true
            shift
            ;;
        -h|--help)
            cat << EOF
reset-database.sh - Reset the local development database

Usage: ./reset-database.sh [options]

Options:
    -f, --force    Skip confirmation prompt
    -h, --help     Show this help message

Environment variables:
    POSTGRES_PASSWORD    PostgreSQL password (default: DevPassword123!)
EOF
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check if container is running
if ! docker ps --filter "name=$CONTAINER_NAME" --format "{{.Names}}" | grep -q "$CONTAINER_NAME"; then
    echo -e "${RED}Error: PostgreSQL container '$CONTAINER_NAME' is not running.${NC}"
    echo -e "${YELLOW}Start it with: docker compose up -d${NC}"
    exit 1
fi

# Confirm unless forced
if [ "$FORCE" = false ]; then
    read -p "This will delete all data in the '$DATABASE_NAME' database. Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Cancelled.${NC}"
        exit 0
    fi
fi

echo -e "${CYAN}Dropping database '$DATABASE_NAME'...${NC}"

# Drop the database - capture output for error reporting
set +e
DROP_OUTPUT=$(docker exec "$CONTAINER_NAME" psql \
    -U postgres -d postgres \
    -c "DROP DATABASE IF EXISTS \"$DATABASE_NAME\" WITH (FORCE)" 2>&1)
DROP_STATUS=$?
set -e

if [ $DROP_STATUS -eq 0 ]; then
    echo -e "${GREEN}Database dropped successfully.${NC}"
else
    echo -e "${YELLOW}Warning: Could not drop database (it may not exist yet)${NC}"
    if [ -n "$DROP_OUTPUT" ]; then
        echo -e "${RED}psql output:${NC}"
        echo "$DROP_OUTPUT"
    fi
fi

# Build and apply migrations via efbundle
EFBUNDLE="$REPO_ROOT/backend/src/backend/efbundle"
BACKEND_PROJECT="$REPO_ROOT/backend/src/backend/backend.csproj"

echo -e "${CYAN}Building migration bundle...${NC}"
dotnet ef migrations bundle \
    --project "$BACKEND_PROJECT" \
    --force \
    --output "$EFBUNDLE" \
    --no-build 2>/dev/null || \
dotnet ef migrations bundle \
    --project "$BACKEND_PROJECT" \
    --force \
    --output "$EFBUNDLE"

if [ -f "$EFBUNDLE" ]; then
    echo -e "${CYAN}Applying migrations...${NC}"
    "$EFBUNDLE" --connection "Host=localhost;Port=5432;Database=$DATABASE_NAME;Username=postgres;Password=$POSTGRES_PASSWORD"
    echo -e "${GREEN}Migrations applied successfully.${NC}"
else
    echo -e "${RED}Error: Failed to create migration bundle.${NC}"
    exit 1
fi

# Seed database
CONNECTION_STRING="Host=localhost;Port=5432;Database=$DATABASE_NAME;Username=postgres;Password=$POSTGRES_PASSWORD"
SEEDS_PATH="$REPO_ROOT/backend/seeds"
DBSEED_PROJECT="$REPO_ROOT/backend/tools/dbseed/dbseed.csproj"
if [ -f "$DBSEED_PROJECT" ]; then
    echo -e "${CYAN}Seeding database...${NC}"
    ConnectionStrings__DefaultConnection="$CONNECTION_STRING" dotnet run --project "$DBSEED_PROJECT" -- "$SEEDS_PATH" --force
    echo -e "${GREEN}Database seeded successfully.${NC}"
else
    echo -e "${YELLOW}Warning: dbseed project not found at $DBSEED_PROJECT${NC}"
fi

echo ""
echo -e "${GREEN}Database reset complete.${NC}"
