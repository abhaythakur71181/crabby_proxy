import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// Dev: /api, /health and the live WebSocket are proxied to the Rust backend so
// the browser stays same-origin (no CORS setup needed while developing).
// Prod: the bundle calls VITE_API_BASE_URL directly (or same-origin when empty
// and fronted by a reverse proxy).
const BACKEND = process.env.CRABBY_BACKEND ?? "http://127.0.0.1:8081";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  server: {
    port: 5174,
    proxy: {
      "/api": { target: BACKEND, changeOrigin: true, ws: true },
      "/health": { target: BACKEND, changeOrigin: true },
    },
  },
  build: {
    target: "es2022",
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ["react", "react-dom", "react-router", "@tanstack/react-query"],
          motion: ["motion"],
        },
      },
    },
  },
});
