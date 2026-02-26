import { useCallback, useEffect, useMemo, useState } from "react";
import { useSetAtom } from "jotai";
import { ApiError, postJson, sanitizeErrorMessage } from "@/api";
import { authRequiredAtom, authErrorAtom, navTabAtom } from "@/stores/atoms";
import type { AdminResponse } from "@/stores/types";
import { Btn, TextInput } from "@/components/ui/controls";
import { AppDialog, AppDialogBody, AppDialogContent, AppDialogFooter, AppDialogHeader } from "@/components/ui/app-dialog";

type LoginResponse = { user: string; requires_password_change?: boolean };
const MAX_USERNAME_CHARS = 64;
const MAX_PASSWORD_CHARS = 256;

export function LoginModal({
  open,
  error: _error,
  onClearError,
}: {
  open: boolean;
  error: string | null;
  onClearError: () => void;
}) {
  const setAuthRequired = useSetAtom(authRequiredAtom);
  const setAuthError = useSetAtom(authErrorAtom);
  const setNavTab = useSetAtom(navTabAtom);
  void _error;

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setUsername("admin");
    setPassword("admin");
  }, [open]);

  const usernameError = useMemo(() => {
    const u = username.trim();
    if (!u) return null;
    if (u.length > MAX_USERNAME_CHARS) return `Username too long [max ${MAX_USERNAME_CHARS} chars]`;
    if ([...u].some((ch) => /[\x00-\x1F\x7F]/.test(ch))) return "Username contains invalid characters";
    return null;
  }, [username]);

  const canSubmit = useMemo(() => {
    const u = username.trim();
    return u.length > 0 && u.length <= MAX_USERNAME_CHARS && password.length > 0 && !usernameError;
  }, [password.length, username, usernameError]);

  const submit = useCallback(async () => {
    if (!canSubmit || busy) return;
    setBusy(true);
    onClearError();
    try {
      const resp = await postJson<AdminResponse<LoginResponse>, { username: string; password: string }>(
        "/api/login",
        { username: username.trim(), password: password.slice(0, MAX_PASSWORD_CHARS) },
      );
      if (!resp.success) {
        setAuthError(sanitizeErrorMessage(resp.message, "Invalid credentials"));
        setBusy(false);
        return;
      }
      setUsername("");
      setPassword("");
      setAuthRequired(false);
      setAuthError(null);
      if (resp.data?.requires_password_change) {
        setNavTab("configuration");
      }
    } catch (e: any) {
      const msg = sanitizeErrorMessage(e?.message ?? e, "Login failed");
      const isServerError = e instanceof ApiError && typeof e.status === "number" && e.status >= 500;
      if (isServerError || msg.includes("fetch") || msg.includes("Failed") || msg.includes("NetworkError")) {
        setAuthError("Server unreachable. Check that backend is running and reachable.");
      } else {
        setAuthError(msg || "Login failed");
      }
    } finally {
      setBusy(false);
    }
  }, [busy, canSubmit, onClearError, password, setAuthError, setAuthRequired, setNavTab, username]);

  return (
    <AppDialog
      isOpen={open}
      isDismissable={false}
      hideCloseButton
    >
      <AppDialogContent>
        {() => (
          <form
            className="contents"
            autoComplete="on"
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <AppDialogHeader className="flex flex-col gap-1">
              <div className="text-[14px] font-semibold text-text-primary dashboard-heading-sans">Admin Login</div>
              <div className="text-[11px] text-black dashboard-heading-sans">
                Enter admin credentials to access server configuration.
              </div>
            </AppDialogHeader>
            <AppDialogBody className="gap-3">
              <TextInput
                label="Username"
                name="username"
                maxLength={MAX_USERNAME_CHARS}
                autoComplete="username"
                error={usernameError}
                value={username}
                onChange={(v) => { setUsername(v); onClearError(); }}
                labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
              />
              <TextInput
                label="Password"
                type="password"
                name="password"
                maxLength={MAX_PASSWORD_CHARS}
                autoComplete="current-password"
                value={password}
                onChange={(v) => { setPassword(v); onClearError(); }}
                labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    submit();
                  }
                }}
              />
            </AppDialogBody>
            <AppDialogFooter>
              <Btn
                type="submit"
                variant="accent"
                size="md"
                disabled={!canSubmit}
                loading={busy}
              >
                Login
              </Btn>
            </AppDialogFooter>
          </form>
        )}
      </AppDialogContent>
    </AppDialog>
  );
}
