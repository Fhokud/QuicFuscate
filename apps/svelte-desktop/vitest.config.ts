import { resolve } from "node:path";
import { sveltekit } from "@sveltejs/kit/vite";
import { svelteTesting } from "@testing-library/svelte/vite";
import { configDefaults, defineConfig } from "vitest/config";

const workspaceRoot = resolve(__dirname, "../..");
const desktopUnitTestRoot = resolve(workspaceRoot, "scripts/tests/frontend/desktop/unit");

export default defineConfig({
  plugins: [sveltekit(), svelteTesting()],
  resolve: {
    conditions: ["browser"],
    alias: {
      "@testing-library/svelte": resolve(__dirname, "node_modules/@testing-library/svelte"),
    },
  },
  server: {
    fs: {
      allow: [workspaceRoot],
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: [resolve(desktopUnitTestRoot, "setup.ts")],
    include: [resolve(desktopUnitTestRoot, "src/**/*.{test,spec}.{ts,tsx}")],
    css: true,
    exclude: [...configDefaults.exclude, "e2e/**", "dist/**"],
  },
});
