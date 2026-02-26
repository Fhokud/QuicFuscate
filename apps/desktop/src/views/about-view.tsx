import { useEffect, useState } from "react";
import {
  ABOUT_PAGE_CONTENT,
  AboutPageLayout,
} from "../content/about-content";

export function AboutView() {
  const [cpuFeatures, setCpuFeatures] = useState<string[]>([]);

  useEffect(() => {
    (async () => {
      try {
        if (typeof window !== "undefined" && "__TAURI_INTERNALS__" in window) {
          const { invoke } = await import("@tauri-apps/api/core");
          const features = await invoke<string[]>("detect_cpu_features");
          setCpuFeatures(features);
        }
      } catch {
        /* browser dev mode - no Tauri runtime */
      }
    })();
  }, []);

  return (
    <AboutPageLayout version={ABOUT_PAGE_CONTENT.defaultVersion} cpuFeatures={cpuFeatures} />
  );
}
