import { defineConfig, type Plugin } from 'vitest/config';
import react from '@vitejs/plugin-react';

// SPA fallback middleware - serves index.html for client-side routes
function spaFallback(): Plugin {
  return {
    name: 'spa-fallback',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url || '';
        // Client-side routes that should serve index.html
        const spaRoutes = ['/collections', '/settings', '/setup', '/welcome', '/terms'];
        const isSpaRoute = spaRoutes.some(route => url === route || url.startsWith(route + '/') || url.startsWith(route + '?'));

        if (isSpaRoute && !url.includes('.')) {
          req.url = '/index.html';
        }
        next();
      });
    },
  };
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), spaFallback()],
  base: '/',
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

