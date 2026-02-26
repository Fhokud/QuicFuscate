import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";

const isE2E = process.env.E2E === "1";

function vendorChunkName(id: string): string | undefined {
  if (!id.includes("node_modules/")) return undefined;

  const modulePath = id.split("node_modules/")[1];
  if (!modulePath) return undefined;

  const parts = modulePath.split("/");
  if (parts.length === 0) return undefined;

  let pkg = parts[0];
  if (pkg.startsWith("@") && parts.length > 1) {
    pkg = `${parts[0]}/${parts[1]}`;
  }

  if (pkg === "react" || pkg === "react-dom" || pkg === "scheduler") {
    return "vendor-react-core";
  }

  if (pkg === "@heroui/theme") {
    return "vendor-heroui-theme";
  }

  if (
    pkg.startsWith("@heroui/") ||
    pkg.startsWith("@react-aria/") ||
    pkg.startsWith("@react-stately/")
  ) {
    return "vendor-ui";
  }

  if (pkg.startsWith("@internationalized/")) {
    return "vendor-i18n";
  }

  if (pkg === "framer-motion" || pkg === "motion-dom" || pkg === "motion-utils") {
    return "vendor-motion";
  }

  if (pkg === "jotai") {
    return "vendor-state";
  }

  if (pkg === "lucide-react") {
    return "vendor-icons";
  }

  return undefined;
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          return vendorChunkName(id);
        },
      },
    },
  },
  server: {
    proxy: isE2E
      ? undefined
      : {
          "/api": {
            target: "http://127.0.0.1:9898",
            // Keep browser host header so server same-origin CSRF checks remain valid.
            changeOrigin: false,
          },
        },
  },
  clearScreen: false,
});
