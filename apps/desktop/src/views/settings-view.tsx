import { useState, useEffect, useCallback, useMemo } from "react";
import { useAtom } from "jotai";
import { settingsAtom } from "@/stores/atoms";
import { SettingRow, SettingSection } from "@/components/settings/setting-row";
import { Button } from "@/components/ui/button";
import { Select, SelectItem } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";
import {
  checkForUpdates,
  createTauriUpdaterDriver,
  downloadAndInstallUpdate,
  toTerminalUpdaterErrorState,
  updaterEnabledByPolicy,
  type UpdateUiState,
  type UpdaterHandle,
} from "@/lib/updater";
import type { SharedSelection } from "@heroui/react";

export function SettingsView() {
  const updaterUiLocked = true;
  const [settings, setSettings] = useAtom(settingsAtom);
  const [updaterRuntimeEnabled, setUpdaterRuntimeEnabled] = useState(false);
  const [updaterState, setUpdaterState] = useState<UpdateUiState>({
    status: "disabled",
    reason: "Updater is disabled by policy until signed binaries are published.",
  });
  const [pendingUpdate, setPendingUpdate] = useState<UpdaterHandle | null>(null);

  useEffect(() => {
    if (!window.__TAURI_INTERNALS__) return;
    let cancelled = false;
    (async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const enabled = await invoke<boolean>("updater_runtime_enabled");
        if (!cancelled) setUpdaterRuntimeEnabled(Boolean(enabled));
      } catch {
        if (!cancelled) setUpdaterRuntimeEnabled(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const setLogLevel = useCallback((level: string) => {
    const normalized =
      level === "error" || level === "warn" || level === "debug" || level === "trace" ? level : "info";
    setSettings((prev) => ({
      ...prev,
      general: {
        ...prev.general,
        logLevel: normalized as "error" | "warn" | "info" | "debug" | "trace",
      },
    }));
  }, [setSettings]);

  function selectionToValue(selection: SharedSelection): string | null {
    if (selection === "all") return null;
    const first = Array.from(selection)[0];
    if (first == null) return null;
    return typeof first === "string" ? first : String(first);
  }

  const updaterPolicy = useMemo(
    () =>
      updaterEnabledByPolicy(
        Boolean(window.__TAURI_INTERNALS__),
        updaterUiLocked ? false : settings.general.updaterEnabled,
        updaterRuntimeEnabled,
      ),
    [updaterUiLocked, settings.general.updaterEnabled, updaterRuntimeEnabled],
  );

  useEffect(() => {
    if (updaterPolicy.enabled) {
      if (updaterState.status === "disabled") {
        setUpdaterState({ status: "idle" });
      }
      return;
    }
    setPendingUpdate(null);
    setUpdaterState({ status: "disabled", reason: updaterPolicy.reason ?? "Updater disabled." });
  }, [updaterPolicy.enabled, updaterPolicy.reason]);

  const checkUpdates = useCallback(async () => {
    if (!updaterPolicy.enabled) {
      setUpdaterState({ status: "disabled", reason: updaterPolicy.reason ?? "Updater disabled." });
      return;
    }
    setPendingUpdate(null);
    setUpdaterState({ status: "checking" });
    try {
      const driver = await createTauriUpdaterDriver();
      const update = await driver.check();
      if (!update) {
        setUpdaterState({ status: "no-update" });
        return;
      }
      const availability = await checkForUpdates({ check: async () => update });
      if (availability.kind === "available") {
        setPendingUpdate(update);
        setUpdaterState({
          status: "available",
          version: availability.version,
          currentVersion: availability.currentVersion,
          date: availability.date,
          body: availability.body,
          mandatory: availability.mandatory,
        });
      } else {
        setUpdaterState({ status: "no-update" });
      }
    } catch (error) {
      setUpdaterState(toTerminalUpdaterErrorState(error));
    }
  }, [updaterPolicy.enabled, updaterPolicy.reason]);

  const installPendingUpdate = useCallback(async () => {
    if (!pendingUpdate) return;
    let totalBytes: number | undefined;
    try {
      setUpdaterState({ status: "downloading", progressBytes: 0 });
      await downloadAndInstallUpdate(pendingUpdate, (progress) => {
        if (progress.event === "started") {
          totalBytes = progress.contentLength;
          setUpdaterState({ status: "downloading", progressBytes: 0, totalBytes });
          return;
        }
        if (progress.event === "progress") {
          setUpdaterState({
            status: "downloading",
            progressBytes: progress.chunkLength,
            totalBytes,
          });
          return;
        }
        setUpdaterState({ status: "installing" });
      });
      setUpdaterState({ status: "ready" });
    } catch (error) {
      setUpdaterState(toTerminalUpdaterErrorState(error));
    }
  }, [pendingUpdate]);

  const updaterStatusText = (() => {
    switch (updaterState.status) {
      case "disabled":
        return updaterState.reason;
      case "idle":
        return "Idle";
      case "checking":
        return "Checking for updates";
      case "no-update":
        return "No update available";
      case "available":
        return `Update ${updaterState.version} available [current ${updaterState.currentVersion}]`;
      case "downloading": {
        const total = updaterState.totalBytes ? ` / ${updaterState.totalBytes}` : "";
        return `Downloading ${updaterState.progressBytes}${total} bytes`;
      }
      case "installing":
        return "Installing update package";
      case "ready":
        return "Update installed. Restart the app to apply it.";
      case "signature-failure":
        return `Signature failure: ${updaterState.message}`;
      case "error":
        return `Update error: ${updaterState.message}`;
      default:
        return "Updater status unavailable";
    }
  })();

  const selectClassNames = {
    base: "w-[156px]",
    trigger: cn(
      "h-8 min-h-8 px-2.5 rounded-md dashboard-heading-sans",
      "glass-nav-pill glass-select-edge",
      "data-[open=true]:border-edge-accent",
    ),
    innerWrapper: "bg-transparent border-0 shadow-none ring-0",
    value: "text-[11px] text-black dashboard-heading-sans",
    selectorIcon: "text-black",
    popoverContent: cn("glass-nav-pill rounded-lg animate-in fade-in-0 zoom-in-95 duration-200 dashboard-heading-sans"),
    listboxWrapper: "p-1",
    listbox: "text-[11px] text-black dashboard-heading-sans",
  } as const;
  const logLevelSelectClassNames = {
    ...selectClassNames,
    base: "w-[96px]",
  } as const;

  return (
    <div className="flex-1 h-full min-h-0 overflow-hidden">
      <div className="h-[calc(100%-13px)] w-full px-6 pt-4 pb-0 flex flex-col self-start">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-[14px] font-semibold text-text-primary dashboard-heading-sans">Configuration</div>
          </div>
        </div>

        <div className="mt-3 flex flex-1 min-h-0 flex-col gap-2.5">
          <SettingSection title="Logging" className="shrink-0">
            <SettingRow label="Log Level" description="Affects desktop engine logs">
              <Select
                aria-label="Log level"
                selectedKeys={new Set([settings.general.logLevel])}
                onSelectionChange={(keys) => {
                  const v = selectionToValue(keys);
                  if (v) setLogLevel(v);
                }}
                disallowEmptySelection
                classNames={logLevelSelectClassNames as any}
              >
                <SelectItem key="error">error</SelectItem>
                <SelectItem key="warn">warn</SelectItem>
                <SelectItem key="info">info</SelectItem>
                <SelectItem key="debug">debug</SelectItem>
                <SelectItem key="trace">trace</SelectItem>
              </Select>
            </SettingRow>
          </SettingSection>

          <SettingSection title="Startup" className="shrink-0">
            <SettingRow
              label="Auto-connect on launch"
              description="When enabled, the selected tunnel is connected when the app starts."
            >
              <Switch
                checked={settings.general.autoConnectOnLaunch}
                onCheckedChange={(checked) =>
                  setSettings((prev) => ({
                    ...prev,
                    general: { ...prev.general, autoConnectOnLaunch: checked },
                  }))
                }
              />
            </SettingRow>
            <SettingRow
              label="Start at login"
              description="Registers app autostart with the operating system."
            >
              <Switch
                checked={settings.general.startAtLogin}
                onCheckedChange={(checked) =>
                  setSettings((prev) => ({
                    ...prev,
                    general: { ...prev.general, startAtLogin: checked },
                  }))
                }
              />
            </SettingRow>
          </SettingSection>

          <SettingSection
            title="Updates"
            className={cn(updaterUiLocked ? "opacity-65" : undefined, "relative shrink-0")}
          >
            <span
              aria-hidden
              className="pointer-events-none absolute right-4 top-[11px] text-[11px] font-bold text-black"
            >
              Disabled in current source-first release
            </span>
            <SettingRow
              label="Updater enabled"
              description="Deferred until signed binaries and release signing are shipped."
            >
              <Switch
                checked={updaterUiLocked ? false : settings.general.updaterEnabled}
                disabled={updaterUiLocked}
                onCheckedChange={(checked) =>
                  updaterUiLocked
                    ? null
                    : setSettings((prev) => ({
                        ...prev,
                        general: { ...prev.general, updaterEnabled: checked },
                      }))
                }
              />
            </SettingRow>
            <SettingRow label="Updater status" description="No-update, available, download/install, and signature-failure states.">
              <span className="w-[300px] max-w-[300px] text-right text-[11px] text-black whitespace-nowrap overflow-hidden text-ellipsis">
                {updaterStatusText}
              </span>
            </SettingRow>
            <SettingRow label="Actions" description="Use check/install only when updater policy is enabled.">
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  className="action-neutral-btn"
                  onClick={() => void checkUpdates()}
                  disabled={updaterUiLocked || !updaterPolicy.enabled || updaterState.status === "checking"}
                >
                  Check now
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="action-neutral-btn"
                  onClick={() => void installPendingUpdate()}
                  disabled={
                    updaterUiLocked
                    || !pendingUpdate
                    || updaterState.status === "downloading"
                    || updaterState.status === "installing"
                  }
                >
                  Install
                </Button>
              </div>
            </SettingRow>
          </SettingSection>
        </div>

      </div>
    </div>
  );
}
