import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [
    react(),
  ],

  server: {
    host: '0.0.0.0',
    allowedHosts: ['localhost', '127.0.0.1'],
    port: 5173,
    strictPort: true,

    proxy: {
      '/api': {
        target: 'http://backend:8000',
        changeOrigin: true,
      },

      '/health': {
        target: 'http://backend:8000',
        changeOrigin: true,
      },
    },
  },
})
