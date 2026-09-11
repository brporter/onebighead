#!/bin/sh
# Entrypoint for the local hosting container.
# Applies EF Core migrations, seeds system data, then starts the app.
set -e

if [ -z "$ConnectionStrings__DefaultConnection" ]; then
    echo "Error: ConnectionStrings__DefaultConnection environment variable is not set." >&2
    exit 1
fi

echo "Applying database migrations..."
/app/efbundle --connection "$ConnectionStrings__DefaultConnection"

# The backend is a Debug build, so the development-only --seed flag exists.
# Seeding:Path defaults to "seeds" relative to the content root (/app).
echo "Seeding system data..."
dotnet /app/backend.dll --seed

echo "Starting backend..."
exec dotnet /app/backend.dll
