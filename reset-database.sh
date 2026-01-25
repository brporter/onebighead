#!/bin/bash
# reset-database.sh
# Resets the local development database by dropping and recreating it.
# The database will be recreated automatically when the backend starts.

set -e

CONTAINER_NAME="onebighead-sqlserver"
DATABASE_NAME="onebighead"
SA_PASSWORD="DevPassword123!"
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
    echo -e "${RED}Error: SQL Server container '$CONTAINER_NAME' is not running.${NC}"
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

# Drop the database
if docker exec "$CONTAINER_NAME" /opt/mssql-tools18/bin/sqlcmd \
    -S localhost -U sa -P "$SA_PASSWORD" -C \
    -Q "IF EXISTS (SELECT name FROM sys.databases WHERE name = N'$DATABASE_NAME') BEGIN ALTER DATABASE [$DATABASE_NAME] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$DATABASE_NAME]; END" 2>/dev/null; then
    echo -e "${GREEN}Database dropped successfully.${NC}"
else
    echo -e "${YELLOW}Warning: Could not drop database (it may not exist yet)${NC}"
fi

echo ""
echo -e "${GREEN}Database reset complete.${NC}"
echo -e "${CYAN}Run 'dotnet run' in the backend folder to recreate the database with fresh migrations.${NC}"
