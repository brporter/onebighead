# OneBigHead frontend

React 19, TypeScript, React Router, and Vite. Use Node 22+.

## Run locally

From the repository root, run `./scripts/dev-start.sh` (macOS/Linux) or
`./scripts/dev-start.ps1` (PowerShell 7.3+). These commands start PostgreSQL,
verify the project, apply migrations, seed data, and launch both servers.
The frontend runs at http://localhost:5173 and proxies API and Razor page
requests to http://localhost:5148. Vite serves client routes directly.

To run only the frontend, run `npm ci` and then `npm run dev` here.

## Check changes

- `npm run typecheck` — check source and test types.
- `npm run lint` — run ESLint.
- `npm run test:run` — run unit tests once.
- `npm run test:coverage` — produce an Istanbul coverage report.
- `npm run build` — create the production bundle in `dist`.

`../scripts/verify.sh` and `../scripts/verify.ps1` run the full backend and
frontend checks used in CI. PostgreSQL integration tests require Docker.

Use native forms, buttons, dialogs, and popovers for standard browser behavior.
The shared `ModalDialog` lets callers retain confirmation and busy-state rules.
Browser checks complement jsdom tests for focus, Escape, and popover dismissal.
