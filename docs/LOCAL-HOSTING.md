# Local Hosting in Containers

This runs the complete application — frontend, backend, database migrations,
and seed data — in Docker, without installing the .NET SDK or Node on the host.

## Start

From the repository root:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

The first build takes several minutes (it compiles the frontend and backend
inside the image). The site is then available at **http://localhost:8080**.

## Stop

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml down
```

## How it works

- `deployment/Dockerfile.localhost` is a multi-stage build:
  1. A Node stage runs `npm ci` and `npm run build` for the frontend.
  2. A .NET SDK stage publishes the backend in **Debug** configuration and
     creates an EF Core migration bundle (`efbundle`).
  3. The runtime stage combines the backend, the frontend build (served from
     `wwwroot/collections`), the migration bundle, and `backend/seeds`.
- On container start, `deployment/docker-entrypoint.local.sh` applies
  migrations, runs `dotnet backend.dll --seed` (the Debug-only seed flag,
  which inserts missing rows and updates existing ones to match the seed
  files), then starts the app.
- The app runs with `ASPNETCORE_ENVIRONMENT=Local`, which loads
  `backend/src/backend/appsettings.Local.json`: it serves the built frontend
  like production, but sets the auth cookie with `Secure=false` so sign-in
  works over plain HTTP on localhost.

## Signing in without an OAuth provider

The Debug build includes a development-only endpoint. Sign in as any email
address (the user and a workspace are created on first use):

```bash
curl -i -X POST http://localhost:8080/api/auth/dev-login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com"}'
```

Or from the browser console on http://localhost:8080:

```js
await fetch('/api/auth/dev-login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'you@example.com' }),
});
location.href = '/collections';
```

Real OAuth sign-in (Microsoft) also works if you expose the app at the
configured `Authentication:OAuth:BaseUrl` and supply the provider's client
secret.
