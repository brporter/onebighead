import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/collections/',
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5147/',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, '')
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
      exclude: ['src/main.tsx', 'src/vite-env.d.ts', 'src/types.ts', 'src/data/index.ts'],
      thresholds: {
        statements: 99,
        branches: 90,
        functions: 100,
        lines: 100,
      },
    },
  },
});

