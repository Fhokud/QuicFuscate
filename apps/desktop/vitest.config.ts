import react from "@vitejs/plugin-react-swc";
import { resolve } from "path";
import { configDefaults, defineConfig } from "vitest/config";

const desktopUnitTestRoot = resolve(__dirname, "../../scripts/tests/frontend/desktop/unit");

export default defineConfig({
  plugins: [react()],
  server: {
    fs: {
      allow: [resolve(__dirname, "../..")],
    },
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "./src"),
      "react/jsx-runtime": resolve(__dirname, "./node_modules/react/jsx-runtime.js"),
      "react/jsx-dev-runtime": resolve(__dirname, "./node_modules/react/jsx-dev-runtime.js"),
      react: resolve(__dirname, "./node_modules/react"),
      "react-dom": resolve(__dirname, "./node_modules/react-dom"),
      "@testing-library/react": resolve(__dirname, "./node_modules/@testing-library/react"),
      "@heroui/react": resolve(__dirname, "./node_modules/@heroui/react"),
      "@tauri-apps/api/core": resolve(__dirname, "./node_modules/@tauri-apps/api/core.js"),
      jotai: resolve(__dirname, "./node_modules/jotai"),
      "jotai/vanilla": resolve(__dirname, "./node_modules/jotai/vanilla.js"),
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: [resolve(desktopUnitTestRoot, "setup.ts")],
    include: [resolve(desktopUnitTestRoot, "src/**/*.{test,spec}.{ts,tsx}")],
    deps: {
      moduleDirectories: ["node_modules", resolve(__dirname, "node_modules")],
    },
    css: true,
    exclude: [...configDefaults.exclude, "e2e/**", "dist/**"],
  },
});
