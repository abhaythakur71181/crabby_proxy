import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    host: "::",
    port: 5173,
    proxy: {
      // Forward API calls to the Crabby Proxy admin server
      "/api": {
        target: "http://127.0.0.1:8081",
        changeOrigin: true,
      },
      "/health": {
        target: "http://127.0.0.1:8081",
        changeOrigin: true,
      },
      "/metrics": {
        target: "http://127.0.0.1:8081",
        changeOrigin: true,
      },
      "/stats": {
        target: "http://127.0.0.1:8081",
        changeOrigin: true,
      },
    },
    hmr: {
      overlay: false,
    },
  },
  plugins: [react()].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
    dedupe: [
      "react",
      "react-dom",
      "react/jsx-runtime",
      "react/jsx-dev-runtime",
      "@tanstack/react-query",
      "@tanstack/query-core",
    ],
  },
}));
