import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
  server: {
    fs: {
      // Allow serving files from the project root (to read output graphs)
      // Allow access to parent directory (project root) and output folder
      allow: ['..']
    },
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true,
      }
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  define: {
    // Inject the absolute path to the output directory
    // This allows the frontend to access files from the C++ backend
    'import.meta.env.VITE_OUTPUT_DIR': JSON.stringify(
      path.resolve(__dirname, '..', 'output').replace(/\\/g, '/')
    )
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    // CRITICAL: Don't use polyfills that might break in Electron
    target: 'esnext',
    minify: 'esbuild',
    sourcemap: false,
    // Ensure assets use relative paths
    rollupOptions: {
      output: {
        manualChunks: undefined
      }
    }
  }
})