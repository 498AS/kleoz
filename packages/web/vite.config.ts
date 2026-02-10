import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Dev-only proxy. Runtime code uses relative "/api" and same-origin WS derived from window.location.
      '/api': process.env.KLEOZ_API_PROXY_TARGET ?? 'http://localhost:3000'
    }
  }
});
