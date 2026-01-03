import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5147/',
        changeOrigin: true,            // necessary for name-based virtual hosted sites
        secure: false,                 // if you want to bypass SSL certificate checks
        rewrite: (path) => path.replace(/^\/api/, '') // remove /auth from the final URL
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

