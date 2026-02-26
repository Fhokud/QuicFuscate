import { useCallback } from "react";
import { useAtom, useAtomValue, useSetAtom } from "jotai";
import { motion } from "framer-motion";
import {
  LayoutDashboard,
  SlidersHorizontal,
  Terminal,
  Power,
  Info,
} from "lucide-react";
import { navTabAtom, authRequiredAtom, authErrorAtom, configDirtyAtom, logsDirtyAtom } from "@/stores/atoms";
import type { NavTab } from "@/stores/types";
import { cn } from "@/lib/cn";
import { useConfirmDialog } from "@/lib/use-confirm-dialog";
import { buildUnsavedConfirm } from "@/lib/unsaved-guard";
import { sanitizeErrorMessage, postJson } from "@/api";
import type { AdminResponse } from "@/stores/types";
import appLogo from "../../../../../assets/logo/QuicFuscate_clean.png";

const TABS: { id: NavTab; label: string; icon: React.ElementType }[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "configuration", label: "Configuration", icon: SlidersHorizontal },
  { id: "logs", label: "Logs", icon: Terminal },
  { id: "about", label: "About", icon: Info },
];

interface SidebarProps {
  lockToConfig?: boolean;
}

export function Sidebar({ lockToConfig = false }: SidebarProps) {
  const [active, setActive] = useAtom(navTabAtom);
  const configDirty = useAtomValue(configDirtyAtom);
  const logsDirty = useAtomValue(logsDirtyAtom);
  const setConfigDirty = useSetAtom(configDirtyAtom);
  const setLogsDirty = useSetAtom(logsDirtyAtom);
  const setAuthRequired = useSetAtom(authRequiredAtom);
  const setAuthError = useSetAtom(authErrorAtom);
  const confirmDialog = useConfirmDialog();

  const confirmUnsavedLeave = useCallback(async (): Promise<boolean> => {
    if (active === "configuration" && configDirty) {
      const proceed = await confirmDialog(buildUnsavedConfirm("configuration", "leave"));
      if (!proceed) return false;
      setConfigDirty(false);
      return true;
    }
    if (active === "logs" && logsDirty) {
      const proceed = await confirmDialog(buildUnsavedConfirm("logging", "leave"));
      if (!proceed) return false;
      setLogsDirty(false);
      return true;
    }
    return true;
  }, [active, configDirty, confirmDialog, logsDirty, setConfigDirty, setLogsDirty]);

  const handleLogout = useCallback(async () => {
    if (!(await confirmUnsavedLeave())) return;
    try {
      await postJson<AdminResponse<unknown>, Record<string, never>>("/api/logout", {});
      setAuthRequired(true);
    } catch (e: any) {
      const msg = sanitizeErrorMessage(e?.message ?? e, "Logout failed");
      setAuthError(msg);
      setAuthRequired(true);
    }
  }, [confirmUnsavedLeave, setAuthError, setAuthRequired]);

  return (
    <nav
      aria-label="Primary"
      data-ripple="off"
      className="w-[152px] shrink-0 glass-sidebar px-3 py-4 flex flex-col h-full rounded-b-[16px] overflow-hidden"
    >
      <div data-tauri-drag-region className="h-3 shrink-0" />

      <div className="px-2 pb-4 flex flex-col items-center justify-center gap-1">
        <img
          src={appLogo}
          alt="QuicFuscate logo"
          className="h-[44px] w-[44px] object-contain select-none"
          draggable={false}
        />
      </div>

      <div className="flex flex-col gap-1 relative flex-1">
        {TABS.map((t) => {
          const isActive = t.id === active;
          const disabled = lockToConfig && t.id !== "configuration";
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              data-ripple="off"
              disabled={disabled}
              aria-label={t.label}
              onClick={() => {
                if (disabled) return;
                void (async () => {
                  if (t.id !== active && !(await confirmUnsavedLeave())) return;
                  setActive(t.id);
                })();
              }}
              className={cn(
                "relative w-full px-3 py-2 rounded-md text-left text-[12px]",
                "cursor-pointer flex items-center gap-2 transition-colors",
                disabled && "opacity-45 cursor-not-allowed",
                isActive
                  ? "text-text-primary font-semibold"
                  : disabled
                    ? "text-text-secondary"
                    : "text-text-secondary",
              )}
            >
              {isActive && (
                <motion.div
                  layoutId="admin-sidebar-active"
                  className="absolute inset-0 rounded-lg pointer-events-none"
                  style={{
                    background: "rgba(255,255,255,0.65)",
                    backdropFilter: "blur(24px) saturate(200%)",
                    WebkitBackdropFilter: "blur(24px) saturate(200%)",
                    border: "1px solid rgba(255,255,255,0.60)",
                    boxShadow: "inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03)",
                    willChange: "transform, opacity",
                    transform: "translateZ(0)",
                  }}
                  transition={{ type: "spring", stiffness: 220, damping: 28, mass: 0.95 }}
                />
              )}
              <Icon className="relative z-10 h-[14px] w-[14px] opacity-80" strokeWidth={isActive ? 2 : 1.6} />
              <span className="relative z-10">{t.label}</span>
            </button>
          );
        })}

        <button
          data-ripple="off"
          onClick={() => {
            void handleLogout();
          }}
          className={cn(
            "relative w-full px-3 py-2 rounded-md text-left text-[12px]",
            "cursor-pointer flex items-center gap-2",
            "text-text-secondary transition-colors"
          )}
        >
          <Power className="h-[14px] w-[14px] opacity-80" />
          <span>Logout</span>
        </button>
      </div>
    </nav>
  );
}
