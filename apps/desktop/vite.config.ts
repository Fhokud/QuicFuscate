import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";
import { execFile } from "node:child_process";

const host = process.env.TAURI_DEV_HOST;

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

  if (pkg.startsWith("@tauri-apps/")) {
    return "vendor-tauri";
  }

  if (pkg === "lucide-react") {
    return "vendor-icons";
  }

  return undefined;
}

function runExecFile(command: string, args: string[]): Promise<string> {
  return new Promise((resolvePromise, rejectPromise) => {
    execFile(command, args, { encoding: "utf8", maxBuffer: 1024 * 1024 }, (error, stdout) => {
      if (error) {
        rejectPromise(error);
        return;
      }
      resolvePromise(stdout ?? "");
    });
  });
}

async function readHostClipboardText(): Promise<string> {
  if (process.platform === "darwin") {
    return await runExecFile("pbpaste", []);
  }
  if (process.platform === "win32") {
    return await runExecFile("powershell", ["-NoProfile", "-Command", "Get-Clipboard -Raw"]);
  }
  if (process.platform === "linux") {
    try {
      return await runExecFile("wl-paste", ["-n"]);
    } catch {
      // fall through
    }
    try {
      return await runExecFile("xclip", ["-selection", "clipboard", "-o"]);
    } catch {
      // fall through
    }
    return await runExecFile("xsel", ["--clipboard", "--output"]);
  }
  return "";
}

function clipboardDevBridgePlugin() {
  return {
    name: "clipboard-dev-bridge",
    configureServer(server: any) {
      server.middlewares.use("/__dev_clipboard/read", async (req: any, res: any) => {
        if (req.method !== "GET") {
          res.statusCode = 405;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ error: "method_not_allowed" }));
          return;
        }

        try {
          const text = await readHostClipboardText();
          res.statusCode = 200;
          res.setHeader("cache-control", "no-store");
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ text }));
        } catch {
          res.statusCode = 200;
          res.setHeader("cache-control", "no-store");
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ text: "" }));
        }
      });
    },
  };
}

export default defineConfig(async () => ({
  plugins: [react(), tailwindcss(), clipboardDevBridgePlugin()],
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
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: { ignored: ["**/src-tauri/**"] },
  },
}));
