import { useEffect, useCallback } from "react";
import { useSetAtom } from "jotai";
import { navTabAtom } from "@/stores/atoms";

type ShortcutAction = 
  | "tunnels" | "settings" | "logs" | "about"
  | "newTunnel" | "connect" | "disconnect" | "refresh" | "help";

interface Shortcuts {
  [key: string]: ShortcutAction;
}

const SHORTCUTS: Shortcuts = {
  // Navigation: Cmd/Ctrl + 1-4
  "mod+1": "tunnels",
  "mod+2": "settings", 
  "mod+3": "logs",
  "mod+4": "about",
  
  // Actions
  "mod+n": "newTunnel",
  "mod+c": "connect",
  "mod+d": "disconnect",
  "mod+r": "refresh",
  "mod+/": "help",
};

export function useKeyboardShortcuts(handlers: {
  onNewTunnel?: () => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onRefresh?: () => void;
  onHelp?: () => void;
}) {
  const setNavTab = useSetAtom(navTabAtom);

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    // Ignore if typing in input/textarea
    const target = e.target as HTMLElement;
    if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) {
      return;
    }

    const keys: string[] = [];
    if (e.metaKey || e.ctrlKey) keys.push("mod");
    if (e.altKey) keys.push("alt");
    if (e.shiftKey) keys.push("shift");
    
    const key = e.key.toLowerCase();
    if (key !== "meta" && key !== "control" && key !== "alt" && key !== "shift") {
      keys.push(key);
    }

    const combo = keys.join("+");
    const action = SHORTCUTS[combo];

    if (!action) return;

    // Prevent default browser behavior
    e.preventDefault();

    switch (action) {
      case "tunnels":
        setNavTab("tunnels");
        break;
      case "settings":
        setNavTab("settings");
        break;
      case "logs":
        setNavTab("logs");
        break;
      case "about":
        setNavTab("about");
        break;
      case "newTunnel":
        handlers.onNewTunnel?.();
        break;
      case "connect":
        handlers.onConnect?.();
        break;
      case "disconnect":
        handlers.onDisconnect?.();
        break;
      case "refresh":
        handlers.onRefresh?.();
        break;
      case "help":
        handlers.onHelp?.();
        break;
    }
  }, [setNavTab, handlers]);

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleKeyDown]);
}

// Get shortcut display string for UI
export function getShortcutDisplay(shortcut: string): string {
  const isMac = typeof navigator !== "undefined" && navigator.platform.toUpperCase().indexOf("MAC") >= 0;
  const mod = isMac ? "⌘" : "Ctrl";
  
  return shortcut
    .replace("mod", mod)
    .replace("+", " ")
    .toUpperCase();
}

// List of all shortcuts for help display
export const SHORTCUT_LIST = [
  { keys: "⌘1", action: "Tunnels" },
  { keys: "⌘2", action: "Settings" },
  { keys: "⌘3", action: "Logs" },
  { keys: "⌘4", action: "About" },
  { keys: "⌘N", action: "New Tunnel" },
  { keys: "⌘C", action: "Connect" },
  { keys: "⌘D", action: "Disconnect" },
  { keys: "⌘R", action: "Refresh" },
  { keys: "⌘/", action: "Help" },
];
