import { atom } from "jotai";
import type { NavTab, ClientInfo, QKeyEntry, StatusData, MetricsMap } from "@/stores/types";

const NAV_TAB_STORAGE_KEY = "qf-admin-nav-tab";
const NAV_TABS: readonly NavTab[] = ["dashboard", "configuration", "logs", "about"] as const;

function isNavTab(value: string): value is NavTab {
  return (NAV_TABS as readonly string[]).includes(value);
}

function readStoredNavTab(): NavTab {
  if (typeof window === "undefined") return "dashboard";
  const raw = window.sessionStorage.getItem(NAV_TAB_STORAGE_KEY);
  if (!raw) return "dashboard";
  return isNavTab(raw) ? raw : "dashboard";
}

function writeStoredNavTab(value: NavTab): void {
  if (typeof window === "undefined") return;
  window.sessionStorage.setItem(NAV_TAB_STORAGE_KEY, value);
}

const navTabBaseAtom = atom<NavTab>(readStoredNavTab());
export const navTabAtom = atom(
  (get) => get(navTabBaseAtom),
  (_get, set, next: NavTab) => {
    set(navTabBaseAtom, next);
    writeStoredNavTab(next);
  },
);

export const statusAtom = atom<StatusData | null>(null);
export const statusLoadingAtom = atom<boolean>(false);
export const statusErrorAtom = atom<string | null>(null);

export const clientsAtom = atom<ClientInfo[]>([]);
export const clientsLoadingAtom = atom<boolean>(false);
export const clientsErrorAtom = atom<string | null>(null);

export const metricsAtom = atom<MetricsMap | null>(null);
export const metricsLoadingAtom = atom<boolean>(false);
export const metricsErrorAtom = atom<string | null>(null);

export const qkeyListAtom = atom<QKeyEntry[]>([]);
export const qkeyListLoadingAtom = atom<boolean>(false);
export const qkeyListErrorAtom = atom<string | null>(null);

export const authRequiredAtom = atom<boolean>(false);
export const authErrorAtom = atom<string | null>(null);

// Admin status (used to enforce "default credentials" password change flow globally)
export const adminUserAtom = atom<string | null>(null);
export const adminRequiresPasswordChangeAtom = atom<boolean>(false);

// Tracks unsaved changes in Configuration view to guard in-app navigation.
export const configDirtyAtom = atom<boolean>(false);
// Tracks unsaved changes in Logs view to guard in-app navigation.
export const logsDirtyAtom = atom<boolean>(false);
