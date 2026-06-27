// @lovable.dev/vite-tanstack-config already includes the following — do NOT add them manually
// or the app will break with duplicate plugins:
//   - tanstackStart, viteReact, tailwindcss, tsConfigPaths, nitro (build-only using cloudflare as a default target),
//     componentTagger (dev-only), VITE_* env injection, @ path alias, React/TanStack dedupe,
//     error logger plugins, and sandbox detection (port/host/strictPort).
// You can pass additional config via defineConfig({ vite: { ... }, etc... }) if needed.
import { defineConfig } from "@lovable.dev/vite-tanstack-config";

export default defineConfig({
  tanstackStart: {
    // Redirect TanStack Start's bundled server entry to src/server.ts (our SSR error wrapper).
    // nitro/vite builds from this
    server: { entry: "server" },
  },
  // Dev: proxy the admin API + health to the Rust backend so the browser talks
  // same-origin (no CORS). In production nginx fills this role. Override target
  // with CRABBY_BACKEND.
  vite: {
    server: {
      proxy: {
        "/api": {
          target: process.env.CRABBY_BACKEND || "http://127.0.0.1:8081",
          changeOrigin: true,
        },
        "/health": {
          target: process.env.CRABBY_BACKEND || "http://127.0.0.1:8081",
          changeOrigin: true,
        },
      },
    },
  },
});
