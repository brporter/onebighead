import { defineConfig, type Plugin } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Redirect /collections to /collections/ to match base URL
function trailingSlashRedirect(): Plugin {
  return {
    name: 'trailing-slash-redirect',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url === '/collections') {
          res.writeHead(301, { Location: '/collections/' });
          res.end();
          return;
        }
        next();
      });
    },
  };
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), trailingSlashRedirect()],
  base: '/collections/',
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5148/',
        changeOrigin: true,
        secure: false,
      },
      '/api/auth': {
        target: 'http://localhost:5148/',
        changeOrigin: true,
        secure: false,
      },
      '^/$': {
        target: 'http://localhost:5148',
        changeOrigin: true,
        secure: false
      },
      '/about': {
        target: 'http://localhost:5148',
        changeOrigin: true,
        secure: false
      },
      '/signup': {
        target: 'http://localhost:5148',
        changeOrigin: true,
        secure: false
      },
      '/signin': {
        target: 'http://localhost:5148',
        changeOrigin: true,
        secure: false
      },
      '/privacy': {
        target: 'http://localhost:5148',
        changeOrigin: true,
        secure: false
      },
      '/css': {
        target: 'http://localhost:5148',
        changeOrigin: true,
        secure: false
      },
      '/admin': {
        target: 'http://localhost:5148',
        changeOrigin: true,
        secure: false
      }
    }
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
    include: ['tests/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'istanbul',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/main.tsx', 'src/vite-env.d.ts', 'src/types.ts'],
      thresholds: {
        statements: 99,
        branches: 90,
        functions: 100,
        lines: 100,
      },
    },
  },
});

