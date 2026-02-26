import { atom } from "jotai";
import type {
  TunnelConfig,
  TunnelState,
  TunnelStats,
  AppSettings,
  LogEntry,
  NavTab,
} from "./types";

/** Active navigation tab */
export const navTabAtom = atom<NavTab>("tunnels");

/** All imported tunnels */
export const tunnelsAtom = atom<TunnelConfig[]>([]);

/** Currently selected tunnel id */
export const selectedTunnelIdAtom = atom<string | null>(null);

/** Derived: selected tunnel config */
export const selectedTunnelAtom = atom((get) => {
  const id = get(selectedTunnelIdAtom);
  if (!id) return null;
  return get(tunnelsAtom).find((t) => t.id === id) ?? null;
});

/** Per-tunnel activation state (keyed by tunnel id) */
export const tunnelStatesAtom = atom<Record<string, TunnelState>>({});

/** Derived: state of the selected tunnel */
export const selectedTunnelStateAtom = atom<TunnelState>((get) => {
  const id = get(selectedTunnelIdAtom);
  if (!id) return "inactive";
  return get(tunnelStatesAtom)[id] ?? "inactive";
});

/** Per-tunnel live stats (keyed by tunnel id, null when inactive) */
export const tunnelStatsAtom = atom<Record<string, TunnelStats | null>>({});

/** Derived: stats of the selected tunnel */
export const selectedTunnelStatsAtom = atom<TunnelStats | null>((get) => {
  const id = get(selectedTunnelIdAtom);
  if (!id) return null;
  return get(tunnelStatsAtom)[id] ?? null;
});

/** Error message (global) */
export const errorAtom = atom<string | null>(null);

/** Engine logs */
export const logsAtom = atom<LogEntry[]>([]);

/** Client-level settings defaults */
export const settingsAtom = atom<AppSettings>({
  general: {
    logLevel: "info",
    autoConnectOnLaunch: false,
    startAtLogin: false,
    updaterEnabled: false,
    updaterChannel: "stable",
  },
  hardware: {
    detectedFeatures: [],
  },
});
