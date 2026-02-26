import { useEffect, useMemo } from "react";
import { useAtom, useAtomValue, useSetAtom } from "jotai";
import {
  adminRequiresPasswordChangeAtom,
  adminUserAtom,
  authErrorAtom,
  authRequiredAtom,
  configDirtyAtom,
  logsDirtyAtom,
  navTabAtom,
} from "@/stores/atoms";
import { Sidebar } from "@/components/layout/sidebar";
import { LoginModal } from "@/components/login-modal";
import { DashboardView } from "@/views/dashboard";
import { LogsView } from "@/views/logs";
import { ConfigurationView } from "@/views/configuration";
import { AboutView } from "@/views/about";
import { ToastContainer } from "@/components/ui/toast";
import { ConfirmDialogHost } from "@/components/ui/confirm-dialog";
import { useConfirmDialog } from "@/lib/use-confirm-dialog";
import { buildUnsavedConfirm, detectUnsavedScope } from "@/lib/unsaved-guard";
import { ApiError, getJson } from "@/api";
import type { AdminResponse } from "@/stores/types";

const views = {
  dashboard: DashboardView,
  configuration: ConfigurationView,
  logs: LogsView,
  about: AboutView,
} as const;

export function App() {
  const [activeTab, setActiveTab] = useAtom(navTabAtom);
  const authRequired = useAtomValue(authRequiredAtom);
  const authError = useAtomValue(authErrorAtom);
  const configDirty = useAtomValue(configDirtyAtom);
  const logsDirty = useAtomValue(logsDirtyAtom);
  const setAuthError = useSetAtom(authErrorAtom);
  const setAdminUser = useSetAtom(adminUserAtom);
  const [requiresPasswordChange, setRequiresPasswordChange] = useAtom(adminRequiresPasswordChangeAtom);
  const confirmDialog = useConfirmDialog();

  const effectiveTab = requiresPasswordChange ? "configuration" : activeTab;
  const View = useMemo(() => views[effectiveTab], [effectiveTab]);

  // On boot: let the dashboard fetch status; we only show login when a 401/403 happens.
  useEffect(() => {
    setAuthError(null);
  }, [setAuthError]);

  // Global auth status probe. If the server requires a password change, lock the UI to Settings.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await getJson<AdminResponse<{ user: string; requires_password_change: boolean }>>("/api/admin/auth");
        if (cancelled) return;
        if (!resp.success || !resp.data) return;
        setAdminUser(resp.data.user || "admin");
        const lock = Boolean(resp.data.requires_password_change);
        setRequiresPasswordChange(lock);
        if (lock) setActiveTab("configuration");
      } catch (e: any) {
        if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
          // Don't force the login modal here; other requests will trigger it.
          return;
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [setActiveTab, setAdminUser, setRequiresPasswordChange]);

  // If any API call returns 423, the server requires an admin password change.
  useEffect(() => {
    const onLock = () => {
      setRequiresPasswordChange(true);
      setActiveTab("configuration");
    };
    window.addEventListener("qf:admin-password-change-required", onLock as any);
    return () => {
      window.removeEventListener("qf:admin-password-change-required", onLock as any);
    };
  }, [setActiveTab, setRequiresPasswordChange]);

  useEffect(() => {
    const scope = detectUnsavedScope(configDirty, logsDirty);
    if (!scope) return;

    const onKeyDown = (event: KeyboardEvent) => {
      const key = event.key.toLowerCase();
      const isReload = event.key === "F5" || ((event.metaKey || event.ctrlKey) && key === "r");
      const isClose = (event.metaKey || event.ctrlKey) && key === "w";
      if (!isReload && !isClose) return;
      event.preventDefault();
      event.stopPropagation();

      void (async () => {
        const accepted = await confirmDialog(buildUnsavedConfirm(scope, isReload ? "reload" : "close"));
        if (!accepted) return;
        if (isReload) {
          window.location.reload();
          return;
        }
        // Works in desktop/webview environments that allow scripted close.
        window.close();
      })();
    };

    window.addEventListener("keydown", onKeyDown, true);
    return () => {
      window.removeEventListener("keydown", onKeyDown, true);
    };
  }, [configDirty, confirmDialog, logsDirty]);

  return (
    <div id="qf-app-stage" className="desktop-stage flex flex-col bg-transparent overflow-hidden">
      <LoginModal
        open={authRequired}
        error={authError}
        onClearError={() => setAuthError(null)}
      />
      <ToastContainer />
      <ConfirmDialogHost />

      <div className="flex flex-1 min-h-0">
        <Sidebar lockToConfig={requiresPasswordChange} />
        <main className="flex-1 flex flex-col min-h-0 bg-transparent">
          <div key={effectiveTab} className="flex flex-col flex-1 min-h-0 content-typography">
            <View />
          </div>
        </main>
      </div>
    </div>
  );
}
