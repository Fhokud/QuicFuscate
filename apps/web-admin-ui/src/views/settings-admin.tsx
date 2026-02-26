import { useCallback, useEffect, useRef, useState } from "react";
import { useSetAtom } from "jotai";
import { useDisclosure } from "@heroui/react";
import { ApiError, getJson, postJson, sanitizeErrorMessage } from "@/api";
import { authErrorAtom, authRequiredAtom } from "@/stores/atoms";
import type { AdminResponse } from "@/stores/types";
import { SkeletonText } from "@/components/ui/skeleton";
import { Btn, TextInput } from "@/components/ui/controls";
import { AppDialog, AppDialogBody, AppDialogContent, AppDialogFooter, AppDialogHeader } from "@/components/ui/app-dialog";
import { useNotify } from "@/lib/use-notify";
import { notifyErrorOverlay } from "@/lib/notify-error";

type AuthStatus = { user: string; requires_password_change: boolean };
type AuthUpdateBody =
  | { new_username: string; current_password: string; new_password?: never }
  | { current_password: string; new_password: string; new_username?: never }
  | { new_username: string; current_password: string; new_password: string };
const MAX_USERNAME_CHARS = 64;
const MAX_PASSWORD_CHARS = 256;
const RIPPLE_ACTION_DELAY_MS = 88;

function isAuthError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

/**
 * Embeddable admin settings panel (username + password management).
 * Rendered inside the Configuration view.
 * @param onRefresh - Optional callback ref setter: parent calls the function to re-fetch auth status.
 */
export function AdminSettingsPanel({ onRefresh }: { onRefresh?: (fn: () => Promise<void>) => void }) {
  const setAuthRequired = useSetAtom(authRequiredAtom);
  const setAuthError = useSetAtom(authErrorAtom);
  const notify = useNotify();

  const [loading, setLoading] = useState(false);
  const [authReady, setAuthReady] = useState(false);
  const [username, setUsername] = useState("admin");
  const [requiresChange, setRequiresChange] = useState(false);
  const [actionRowWidth, setActionRowWidth] = useState<number | null>(null);
  const actionRowRef = useRef<HTMLDivElement | null>(null);

  const usernameDialog = useDisclosure();
  const passwordDialog = useDisclosure();

  const [busy, setBusy] = useState(false);

  const [dlgNewUsername, setDlgNewUsername] = useState("");
  const [dlgCurrentPw, setDlgCurrentPw] = useState("");

  const [dlgNewPw, setDlgNewPw] = useState("");
  const [dlgConfirmPw, setDlgConfirmPw] = useState("");
  const passwordDialogOpen = requiresChange || passwordDialog.isOpen;

  const usernameError = (() => {
    const v = dlgNewUsername.trim();
    if (!v) return null;
    if (v.length > MAX_USERNAME_CHARS) return `Username too long [max ${MAX_USERNAME_CHARS} chars]`;
    if ([...v].some((ch) => /[\x00-\x1F\x7F]/.test(ch))) return "Username contains invalid characters";
    return null;
  })();

  const fetchAuth = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await getJson<AdminResponse<AuthStatus>>("/api/admin/auth");
      if (!resp.success || !resp.data) throw new Error(resp.message ?? "Auth status unavailable");
      setUsername(resp.data.user || "admin");
      setRequiresChange(Boolean(resp.data.requires_password_change));
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Failed to load admin settings");
        notifyErrorOverlay(notify, message, "settings-admin:load");
      }
    } finally {
      setLoading(false);
      setAuthReady(true);
    }
  }, [notify, setAuthError, setAuthRequired]);

  useEffect(() => {
    fetchAuth();
  }, [fetchAuth]);

  // Expose fetchAuth to parent for top-level Refresh
  useEffect(() => {
    onRefresh?.(fetchAuth);
  }, [fetchAuth, onRefresh]);

  useEffect(() => {
    const row = actionRowRef.current;
    if (!row) return;
    const sync = () => setActionRowWidth(Math.ceil(row.getBoundingClientRect().width));
    sync();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(sync);
    observer.observe(row);
    return () => observer.disconnect();
  }, [loading, requiresChange, username]);

  const submitUsername = useCallback(async () => {
    if (busy) return;
    const newU = dlgNewUsername.trim();
    if (!newU || !dlgCurrentPw || usernameError) return;
    setBusy(true);
    try {
      const body: AuthUpdateBody = { new_username: newU, current_password: dlgCurrentPw };
      const resp = await postJson<AdminResponse<unknown>, AuthUpdateBody>("/api/admin/auth", body);
      if (!resp.success) throw new Error(resp.message ?? "Username update failed");
      setUsername(newU);
      setDlgNewUsername("");
      setDlgCurrentPw("");
      usernameDialog.onClose();
      notify.success("Username updated. Please login again.");
      setAuthRequired(true);
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Username update failed");
        notifyErrorOverlay(notify, message, "settings-admin:username-update");
      }
    } finally {
      setBusy(false);
    }
  }, [busy, dlgCurrentPw, dlgNewUsername, notify, setAuthError, setAuthRequired, usernameDialog, usernameError]);

  const submitPassword = useCallback(async () => {
    if (busy) return;
    if (!dlgCurrentPw) return;
    if (dlgNewPw.length < 6) return;
    if (dlgNewPw.length > MAX_PASSWORD_CHARS) return;
    if (dlgNewPw !== dlgConfirmPw) return;
    setBusy(true);
    try {
      const body: AuthUpdateBody = {
        current_password: dlgCurrentPw,
        new_password: dlgNewPw,
      };
      const resp = await postJson<AdminResponse<unknown>, AuthUpdateBody>("/api/admin/auth", body);
      if (!resp.success) throw new Error(resp.message ?? "Password update failed");
      setDlgCurrentPw("");
      setDlgNewPw("");
      setDlgConfirmPw("");
      setRequiresChange(false);
      passwordDialog.onClose();
      notify.success("Password updated. Please login again.");
      setAuthRequired(true);
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Password update failed");
        notifyErrorOverlay(notify, message, "settings-admin:password-update");
      }
    } finally {
      setBusy(false);
    }
  }, [
    busy,
    dlgConfirmPw,
    dlgCurrentPw,
    dlgNewPw,
    notify,
    setAuthError,
    setAuthRequired,
    passwordDialog,
  ]);

  return (
    <>
      <section className="rounded-xl glass">
        <div className="pane-header border-b border-edge">
          <div className="text-[11px] font-semibold text-black dashboard-heading-sans">Admin</div>
        </div>

        <div className="pane-body pane-first-item-offset space-y-4">
          {!authReady && loading ? (
            <SkeletonText lines={4} />
          ) : (
            <>
              {requiresChange && (
                <div className="px-3 py-2 rounded-md bg-warning-muted border border-warning/20 text-[12px] text-warning">
                  Default credentials detected. Please change your password.
                </div>
              )}

              <div className="inline-flex flex-col items-stretch gap-3.5">
                <div
                  className="inline-flex items-center rounded-md border border-edge/70 glass-nav-pill px-2.5 py-1 text-[11px] font-medium text-black"
                  style={actionRowWidth ? { width: `${actionRowWidth}px` } : undefined}
                >
                  <span className="truncate">{username}</span>
                </div>
                <div ref={actionRowRef} className="inline-flex items-center gap-2 whitespace-nowrap">
                  {!requiresChange && (
                    <Btn
                      type="button"
                      variant="neutral"
                      onClick={() => {
                        window.setTimeout(() => {
                          setDlgNewUsername("");
                          setDlgCurrentPw("");
                          setDlgNewPw("");
                          usernameDialog.onOpen();
                        }, RIPPLE_ACTION_DELAY_MS);
                      }}
                    >
                      Change Username
                    </Btn>
                  )}
                  <Btn
                    type="button"
                    variant="accent"
                    onClick={() => {
                      window.setTimeout(() => {
                        setDlgCurrentPw("");
                        setDlgNewPw("");
                        passwordDialog.onOpen();
                      }, RIPPLE_ACTION_DELAY_MS);
                    }}
                  >
                    {requiresChange ? "Set Password Now" : "Change Password"}
                  </Btn>
                </div>
              </div>
            </>
          )}
        </div>
      </section>

      {/* Change Username Dialog */}
      <AppDialog
        isOpen={usernameDialog.isOpen}
        onOpenChange={usernameDialog.onOpenChange}
      >
        <AppDialogContent>
          <AppDialogHeader>Change Username</AppDialogHeader>
          <AppDialogBody className="space-y-3">
            <TextInput
              label="New Username"
              value={dlgNewUsername}
              onChange={setDlgNewUsername}
              maxLength={MAX_USERNAME_CHARS}
              error={usernameError}
              autoComplete="username"
              labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
            />
            <TextInput
              label="Current Password"
              type="password"
              value={dlgCurrentPw}
              onChange={setDlgCurrentPw}
              maxLength={MAX_PASSWORD_CHARS}
              autoComplete="current-password"
              labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
            />
            <div className="text-[11px] text-black">
              Username changes require the current password and will log out all sessions.
            </div>
          </AppDialogBody>
          <AppDialogFooter>
            <Btn
              variant="ghost"
              onClick={() => {
                window.setTimeout(usernameDialog.onClose, RIPPLE_ACTION_DELAY_MS);
              }}
              disabled={busy}
            >
              Cancel
            </Btn>
            <Btn
              variant="accent"
              loading={busy}
              disabled={!dlgNewUsername.trim() || Boolean(usernameError) || !dlgCurrentPw}
              onClick={submitUsername}
            >
              Save
            </Btn>
          </AppDialogFooter>
        </AppDialogContent>
      </AppDialog>

      {/* Change Password Dialog */}
      <AppDialog
        isOpen={passwordDialogOpen}
        onOpenChange={(open) => {
          if (requiresChange && !open) return;
          if (open) passwordDialog.onOpen();
          else passwordDialog.onClose();
        }}
        isDismissable={!requiresChange}
        isKeyboardDismissDisabled={requiresChange}
      >
        <AppDialogContent>
          <AppDialogHeader>Change Password</AppDialogHeader>
          <AppDialogBody className="space-y-3">
            <TextInput
              label="Current Password"
              type="password"
              name="admin-change-current-password"
              value={dlgCurrentPw}
              onChange={setDlgCurrentPw}
              maxLength={MAX_PASSWORD_CHARS}
              autoComplete="off"
              labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
            />
            <TextInput
              label="New Password"
              type="password"
              name="admin-change-new-password"
              value={dlgNewPw}
              onChange={setDlgNewPw}
              maxLength={MAX_PASSWORD_CHARS}
              autoComplete="off"
              labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
            />
            <TextInput
              label="Confirm Password"
              type="password"
              name="admin-change-confirm-password"
              value={dlgConfirmPw}
              onChange={setDlgConfirmPw}
              maxLength={MAX_PASSWORD_CHARS}
              autoComplete="off"
              labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
            />
            <div className="text-[11px] text-black">
              Minimum 6 characters. Updating password logs out all sessions.
            </div>
          </AppDialogBody>
          <AppDialogFooter>
            {!requiresChange && (
              <Btn
                variant="ghost"
                onClick={() => {
                  window.setTimeout(passwordDialog.onClose, RIPPLE_ACTION_DELAY_MS);
                }}
                disabled={busy}
              >
                Cancel
              </Btn>
            )}
            <Btn
              variant="accent"
              loading={busy}
              disabled={!dlgCurrentPw || dlgNewPw.length < 6 || dlgNewPw.length > MAX_PASSWORD_CHARS || dlgNewPw !== dlgConfirmPw}
              onClick={submitPassword}
            >
              Save
            </Btn>
          </AppDialogFooter>
        </AppDialogContent>
      </AppDialog>
    </>
  );
}
