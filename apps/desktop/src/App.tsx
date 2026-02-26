import { useCallback, useEffect, useRef, useState } from "react";
import { useAtom, useAtomValue, useSetAtom } from "jotai";
import { AnimatePresence, motion } from "framer-motion";
import { Sidebar } from "@/components/layout/sidebar";
import { ErrorBoundary } from "@/components/error-boundary";
import { useKeyboardShortcuts } from "@/lib/use-keyboard-shortcuts";
import { TunnelsView } from "@/views/tunnels-view";
import { SettingsView } from "@/views/settings-view";
import { LogsView } from "@/views/logs-view";
import { AboutView } from "@/views/about-view";
import { ToastContainer } from "@/components/ui/toast";
import {
  errorAtom,
  logsAtom,
  navTabAtom,
  selectedTunnelIdAtom,
  settingsAtom,
  tunnelStatesAtom,
  tunnelStatsAtom,
  tunnelsAtom,
} from "@/stores/atoms";
import type { NavTab } from "@/stores/types";

type PersistedTunnel = {
  id?: unknown;
  name?: unknown;
  remote?: unknown;
  sni?: unknown;
  qkey?: unknown;
  createdAt?: unknown;
  hasToken?: unknown;
  countryCode?: unknown;
  location?: unknown;
  debugSniOverride?: unknown;
};

function normalizePersistedTunnels(input: unknown): Array<{
  id: string;
  name: string;
  remote: string;
  sni: string;
  qkey: string;
  createdAt: number;
  hasToken: boolean;
  countryCode?: string;
  location?: string;
  debugSniOverride?: string;
}> {
  if (!Array.isArray(input)) return [];
  const result: Array<{
    id: string;
    name: string;
    remote: string;
    sni: string;
    qkey: string;
    createdAt: number;
    hasToken: boolean;
    countryCode?: string;
    location?: string;
    debugSniOverride?: string;
  }> = [];

  for (const raw of input as PersistedTunnel[]) {
    if (!raw || typeof raw !== "object") continue;
    const id = typeof raw.id === "string" ? raw.id.trim() : "";
    const remote = typeof raw.remote === "string" ? raw.remote.trim() : "";
    const sni = typeof raw.sni === "string" ? raw.sni.trim() : "";
    if (!id || !remote || !sni) continue;

    const name = typeof raw.name === "string" && raw.name.trim().length > 0 ? raw.name.trim() : remote;
    const qkey = typeof raw.qkey === "string" ? raw.qkey : "";
    const createdAt =
      typeof raw.createdAt === "number" && Number.isFinite(raw.createdAt) && raw.createdAt > 0
        ? raw.createdAt
        : Date.now();
    const hasToken = Boolean(raw.hasToken);
    const countryCode =
      typeof raw.countryCode === "string" && /^[A-Za-z]{2}$/.test(raw.countryCode.trim())
        ? raw.countryCode.trim().toUpperCase()
        : undefined;
    const location = typeof raw.location === "string" && raw.location.trim().length > 0 ? raw.location.trim() : undefined;
    const debugSniOverride =
      typeof raw.debugSniOverride === "string" && raw.debugSniOverride.trim().length > 0
        ? raw.debugSniOverride.trim()
        : undefined;

    result.push({
      id,
      name,
      remote,
      sni,
      qkey,
      createdAt,
      hasToken,
      countryCode,
      location,
      debugSniOverride,
    });
  }
  return result;
}

const views: Record<NavTab, React.ComponentType> = {
  tunnels: TunnelsView,
  settings: SettingsView,
  logs: LogsView,
  about: AboutView,
};

export function App() {
  const activeTab = useAtomValue(navTabAtom);
  const View = views[activeTab];

  const [tunnels, setTunnels] = useAtom(tunnelsAtom);
  const [selectedId, setSelectedId] = useAtom(selectedTunnelIdAtom);
  const [settings, setSettings] = useAtom(settingsAtom);
  const setTunnelStates = useSetAtom(tunnelStatesAtom);
  const setTunnelStats = useSetAtom(tunnelStatsAtom);
  const setLogs = useSetAtom(logsAtom);
  const setError = useSetAtom(errorAtom);

  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const logCursorRef = useRef<number>(0);
  const tunnelsRef = useRef(tunnels);
  const selectedIdRef = useRef(selectedId);
  const settingsRef = useRef(settings);
  const [hydrationDone, setHydrationDone] = useState(!window.__TAURI_INTERNALS__);
  tunnelsRef.current = tunnels;
  selectedIdRef.current = selectedId;
  settingsRef.current = settings;

  const persistNow = useCallback(async () => {
    if (!window.__TAURI_INTERNALS__) return;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("save_state", {
        data: {
          schemaVersion: 1,
          tunnels: tunnelsRef.current,
          selectedTunnelId: selectedIdRef.current,
          settings: settingsRef.current,
        },
      });
    } catch {
      // Best-effort persistence.
    }
  }, []);

  // Load persisted state on startup (desktop runtime only).
  useEffect(() => {
    if (!window.__TAURI_INTERNALS__) return;
    let cancelled = false;
    (async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const loaded = await invoke<any | null>("load_state");
        if (cancelled || !loaded) return;

        const loadedTunnels = normalizePersistedTunnels(loaded.tunnels);
        const loadedSettings = loaded.settings ?? null;
        const loadedSelected = typeof loaded.selectedTunnelId === "string" ? loaded.selectedTunnelId : null;

        if (loadedTunnels.length > 0) setTunnels(loadedTunnels);
        if (loadedSettings) {
          setSettings((prev) => ({
            general: { ...prev.general, ...(loadedSettings.general ?? {}) },
            hardware: { ...prev.hardware, ...(loadedSettings.hardware ?? {}) },
          }));
        }

        const selectedIsValid = !!loadedSelected && loadedTunnels.some((t: any) => t?.id === loadedSelected);
        if (selectedIsValid) {
          setSelectedId(loadedSelected);
        } else if (loadedTunnels.length > 0) {
          setSelectedId(loadedTunnels[0].id);
        }
      } catch {
        // Ignore: dev browser mode or missing file.
      } finally {
        if (!cancelled) setHydrationDone(true);
      }
    })();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Persist state on change (debounced).
  useEffect(() => {
    if (!window.__TAURI_INTERNALS__) return;
    if (!hydrationDone) return;
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => { void persistNow(); }, 450);
    return () => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    };
  }, [tunnels, selectedId, settings, hydrationDone, persistNow]);

  // Event-based settings sync: tray/external updates are pushed from Tauri backend.
  useEffect(() => {
    if (!window.__TAURI_INTERNALS__) return;
    let cancelled = false;
    let unlisten: null | (() => void) = null;
    (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        const off = await listen<{ settings?: unknown }>("qf://settings-changed", (event) => {
          const payloadSettings = event.payload?.settings;
          if (!payloadSettings || typeof payloadSettings !== "object") return;
          const general =
            (payloadSettings as Record<string, unknown>).general &&
            typeof (payloadSettings as Record<string, unknown>).general === "object"
              ? ((payloadSettings as Record<string, unknown>).general as Record<string, unknown>)
              : null;
          const hardware =
            (payloadSettings as Record<string, unknown>).hardware &&
            typeof (payloadSettings as Record<string, unknown>).hardware === "object"
              ? ((payloadSettings as Record<string, unknown>).hardware as Record<string, unknown>)
              : null;
          setSettings((prev) => ({
            ...prev,
            general: {
              ...prev.general,
              ...(general ?? {}),
            },
            hardware: {
              ...prev.hardware,
              ...(hardware ?? {}),
            },
          }));
        });
        if (cancelled) {
          off();
          return;
        }
        unlisten = off;
      } catch {
        // Event bridge is best-effort in desktop runtime.
      }
    })();
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [setSettings]);

  useEffect(() => {
    if (!window.__TAURI_INTERNALS__) return;
    const onVisibility = () => {
      if (document.visibilityState === "hidden") void persistNow();
    };
    const onBeforeUnload = () => { void persistNow(); };

    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("beforeunload", onBeforeUnload);
    };
  }, [persistNow]);

  // Engine poller: status, stats, logs.
  useEffect(() => {
    if (!window.__TAURI_INTERNALS__) return;
    let stopped = false;

    const statusInterval = setInterval(async () => {
      if (stopped) return;
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const status = await invoke<{ state: string; activeTunnelId?: string | null; lastError?: string | null }>("engine_status");
        const activeTunnelId = status.activeTunnelId ?? null;

        setTunnelStates((prev) => {
          const next: Record<string, any> = { ...prev };
          for (const t of tunnelsRef.current) {
            if (activeTunnelId && t.id === activeTunnelId && status.state === "Connected") next[t.id] = "active";
            else if (next[t.id] === "activating" || next[t.id] === "deactivating") continue;
            else next[t.id] = "inactive";
          }
          return next;
        });

        if (status.lastError) setError(status.lastError);
      } catch {
        // ignore
      }
    }, 500);

    const statsInterval = setInterval(async () => {
      if (stopped) return;
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const status = await invoke<{ state: string; activeTunnelId?: string | null }>("engine_status");
        const activeTunnelId = status.activeTunnelId ?? null;
        const stats = await invoke<any | null>("engine_stats");
        if (!activeTunnelId || !stats) {
          setTunnelStats({});
          return;
        }
        setTunnelStats((prev) => ({
          ...prev,
          [activeTunnelId]: {
            latencyMs: stats.latencyMs ?? 0,
            lossPercent: stats.lossPercent ?? 0,
            rxBytes: stats.bytesIn ?? 0,
            txBytes: stats.bytesOut ?? 0,
            rxPackets: stats.packetsIn ?? 0,
            txPackets: stats.packetsOut ?? 0,
            uptimeSecs: stats.uptimeSecs ?? 0,
            stealthMode: stats.stealthMode ?? "auto",
            fecMode: stats.fecMode ?? "auto",
            fecActivityPercent: stats.fecActivityPercent ?? 0,
            fecRecoveredPackets: stats.fecRecoveredPackets ?? 0,
            currentSni:
              typeof stats.currentSni === "string" && stats.currentSni.trim().length > 0
                ? stats.currentSni.trim()
                : undefined,
          },
        }));
      } catch {
        // ignore
      }
    }, 900);

    const logsInterval = setInterval(async () => {
      if (stopped) return;
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const resp = await invoke<{ cursor: number; lines: { tsMs: number; level: string; message: string }[] }>("engine_logs_since", {
          cursor: logCursorRef.current,
        });
        if (!resp || !Array.isArray(resp.lines) || resp.lines.length === 0) {
          logCursorRef.current = resp?.cursor ?? logCursorRef.current;
          return;
        }
        logCursorRef.current = resp.cursor ?? logCursorRef.current;
        setLogs((prev) => {
          const next = prev.concat(
            resp.lines.map((l) => ({
              timestamp: l.tsMs,
              level: (l.level as any) ?? "info",
              message: l.message,
            })),
          );
          return next.length > 2000 ? next.slice(next.length - 2000) : next;
        });
      } catch {
        // ignore
      }
    }, 350);

    return () => {
      stopped = true;
      clearInterval(statusInterval);
      clearInterval(statsInterval);
      clearInterval(logsInterval);
    };
  }, [setError, setLogs, setTunnelStates, setTunnelStats]);

  // Keyboard shortcuts
  useKeyboardShortcuts({
    onRefresh: () => {
      // no-op for now
    },
  });

  return (
    <div id="qf-app-stage" className="desktop-stage flex flex-col h-full w-full bg-transparent overflow-hidden text-text-primary select-none">
      <ToastContainer />
      {/* Main layout: sidebar + content */}
      <div className="flex flex-1 min-h-0">
        <Sidebar />

        {/* Content area */}
        <main className="flex-1 flex flex-col min-h-0 bg-transparent">
          <ErrorBoundary>
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.12 }}
                className="flex flex-col flex-1 min-h-0 content-typography"
              >
                <View />
              </motion.div>
            </AnimatePresence>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
