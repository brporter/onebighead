#!/bin/bash
#
# Build script for macOS/Linux
# Builds both the .NET backend and React frontend projects,
# then combines them into a single unified output directory.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Get script directory and repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

# Default values
OUTPUT_PATH="./publish"
SKIP_FRONTEND=false
SKIP_BACKEND=false
CLEAN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_PATH="$2"
            shift 2
            ;;
        --skip-frontend)
            SKIP_FRONTEND=true
            shift
            ;;
        --skip-backend)
            SKIP_BACKEND=true
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -o, --output PATH    Output directory (default: ./publish)"
            echo "  --skip-frontend      Skip building the frontend"
            echo "  --skip-backend       Skip building the backend"
            echo "  -c, --clean          Clean output directories before building"
            echo "  -h, --help           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

BACKEND_DIR="$REPO_ROOT/backend"
FRONTEND_DIR="$REPO_ROOT/frontend"
OUTPUT_DIR="$REPO_ROOT/$OUTPUT_PATH"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}OneBigHead Release Build${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo "Repository Root: $REPO_ROOT"
echo "Output Directory: $OUTPUT_DIR"
echo ""

# Clean if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning output directories...${NC}"
    
    if [ -d "$OUTPUT_DIR" ]; then
        rm -rf "$OUTPUT_DIR"
    fi
    
    if [ -d "$FRONTEND_DIR/dist" ]; then
        rm -rf "$FRONTEND_DIR/dist"
    fi
    
    echo -e "${GREEN}Clean complete.${NC}"
    echo ""
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build Frontend
if [ "$SKIP_FRONTEND" = false ]; then
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Building Frontend...${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    cd "$FRONTEND_DIR"
    
    echo -e "${YELLOW}Installing npm dependencies...${NC}"
    npm ci
    
    echo -e "${YELLOW}Building production bundle...${NC}"
    npm run build
    
    echo -e "${GREEN}Frontend build complete.${NC}"
    echo ""
    
    cd "$REPO_ROOT"
fi

# Build Backend
if [ "$SKIP_BACKEND" = false ]; then
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Building Backend...${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    cd "$BACKEND_DIR"
    
    echo -e "${YELLOW}Publishing .NET application...${NC}"
    dotnet publish -c Release -o "$OUTPUT_DIR"
    
    echo -e "${GREEN}Backend build complete.${NC}"
    echo ""
    
    cd "$REPO_ROOT"
fi

# Copy frontend assets to backend wwwroot
if [ "$SKIP_FRONTEND" = false ]; then
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${CYAN}Copying Frontend Assets...${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    FRONTEND_DIST="$FRONTEND_DIR/dist"
    WWWROOT_COLLECTIONS="$OUTPUT_DIR/wwwroot/collections"
    
    mkdir -p "$WWWROOT_COLLECTIONS"
    
    echo -e "${YELLOW}Copying frontend build to $WWWROOT_COLLECTIONS...${NC}"
    cp -r "$FRONTEND_DIST"/* "$WWWROOT_COLLECTIONS/"
    
    echo -e "${GREEN}Frontend assets copied.${NC}"
    echo ""
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${CYAN}Output directory: $OUTPUT_DIR${NC}"
echo ""
echo -e "${YELLOW}To run the application:${NC}"
echo "  cd $OUTPUT_DIR"
echo "  ./backend"
echo ""

