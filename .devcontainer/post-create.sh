#!/bin/bash
set -e

echo "🚀 Setting up OneBigHead development environment..."

# Navigate to workspace
cd /workspaces/onebighead

# Install frontend dependencies
echo "📦 Installing frontend dependencies..."
cd frontend
npm install
cd ..

# Restore backend dependencies
echo "📦 Restoring backend dependencies..."
cd backend
dotnet restore
cd ..

# Wait for SQL Server to be fully ready
echo "⏳ Waiting for SQL Server to be ready..."
for i in {1..30}; do
  if timeout 2 bash -c "cat < /dev/null > /dev/tcp/localhost/1433" 2>/dev/null; then
    echo "✅ SQL Server is ready!"
    break
  fi
  echo "  Still waiting for SQL Server... (attempt $i/30)"
  sleep 2
done

# Run backend tests to ensure everything is working
echo "🧪 Running backend tests..."
cd backend.tests
dotnet test --verbosity minimal || echo "⚠️  Some tests failed, but continuing setup..."
cd ..

# Setup user secrets (optional - will be populated manually by user)
echo "🔐 User secrets setup..."
echo "   To configure OAuth providers, run:"
echo "   cd backend && dotnet user-secrets set 'Authentication:Providers:Microsoft:ClientSecret' '<your-secret>'"

echo ""
echo "✨ Setup complete! You can now:"
echo "   • Start backend: cd backend && dotnet run"
echo "   • Start frontend: cd frontend && npm run dev"
echo "   • Or use the dev-start script: ./dev-start.sh"
echo ""
