#!/usr/bin/env bash
# Run the same checks locally and in CI. Docker must be running for PostgreSQL tests.
set -euo pipefail
cd "$(dirname "$0")/.."
dotnet restore onebighead.slnx
dotnet test backend/tests/backend.tests/backend.tests.csproj --no-restore --verbosity minimal
cd frontend
npm ci
npm run typecheck
npm run lint
npm run test:run
npm run build
