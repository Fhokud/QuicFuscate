import { useAtom } from "jotai";
import { motion } from "framer-motion";
import {
  Lock,
  SlidersHorizontal,
  Terminal,
  Info,
} from "lucide-react";
import { navTabAtom } from "@/stores/atoms";
import type { NavTab } from "@/stores/types";
import { cn } from "@/lib/utils";
import appLogo from "../../../../../assets/logo/QuicFuscate_clean.png";

const tabs: { id: NavTab; label: string; icon: React.ElementType }[] = [
  { id: "tunnels", label: "Tunnels", icon: Lock },
  { id: "settings", label: "Configuration", icon: SlidersHorizontal },
  { id: "logs", label: "Logs", icon: Terminal },
  { id: "about", label: "About", icon: Info },
];

export function Sidebar() {
  const [activeTab, setActiveTab] = useAtom(navTabAtom);

  return (
    <nav
      aria-label="Primary"
      data-ripple="off"
      className="w-[152px] shrink-0 glass-sidebar px-3 py-4 flex flex-col h-[calc(100%-13px)] self-start rounded-b-[16px] overflow-hidden"
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
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              data-ripple="off"
              aria-label={tab.label}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "relative w-full px-3 py-2 rounded-md text-left text-[12px]",
                "cursor-pointer flex items-center gap-2 transition-colors",
                isActive
                  ? "text-text-primary font-semibold"
                  : "text-text-secondary",
              )}
            >
              {isActive && (
                <motion.div
                  layoutId="sidebar-active"
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
              <span className="relative z-10">{tab.label}</span>
            </button>
          );
        })}
      </div>
    </nav>
  );
}
