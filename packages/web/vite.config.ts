import path from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [tailwindcss(), react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Dev-only proxy. Runtime code uses relative "/api" and same-origin WS derived from window.location.
      '/api': {
        target: process.env.KLEOZ_API_PROXY_TARGET ?? 'http://127.0.0.1:3000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
