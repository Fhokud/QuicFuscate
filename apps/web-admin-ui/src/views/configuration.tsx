import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAtom, useSetAtom } from "jotai";
import { Input, Select, SelectItem, useDisclosure } from "@heroui/react";
import { AnimatePresence, motion } from "framer-motion";
import { ApiError, getJson, postJson, sanitizeErrorMessage } from "@/api";
import { authErrorAtom, authRequiredAtom, configDirtyAtom, qkeyListAtom, qkeyListLoadingAtom, statusAtom, statusLoadingAtom } from "@/stores/atoms";
import type { AdminResponse, QKeyEntry, StatusData } from "@/stores/types";
import { cn } from "@/lib/cn";
import type { SharedSelection } from "@heroui/react";
import { Btn, TextInput, Toggle } from "@/components/ui/controls";
import { SkeletonCard } from "@/components/ui/skeleton";
import { useConfirmDialog } from "@/lib/use-confirm-dialog";
import { useTopStatusAnchor } from "@/lib/use-top-status-anchor";
import { useNotify } from "@/lib/use-notify";
import { notifyErrorOverlay } from "@/lib/notify-error";
import { buildUnsavedConfirm } from "@/lib/unsaved-guard";
import { AppDialog, AppDialogBody, AppDialogContent, AppDialogFooter, AppDialogHeader } from "@/components/ui/app-dialog";
import { Check } from "lucide-react";
import { AdminSettingsPanel } from "@/views/settings-admin";
import { setToastAnchorAtom } from "@/stores/toastAtom";

type ConfigResponse = { config: string };

type QKeyList = { keys: QKeyEntry[] };
type QKeyCreateResp = { qkey: string; created_at?: number | null; expires_at?: number | null };
const MAX_QKEY_NAME_CHARS = 64;
const MAX_QKEY_DISPLAY_CHARS = 60;
const MAX_PERSIST_ATTEMPTS = 2;
const RIPPLE_ACTION_DELAY_MS = 88;
const FRONTING_SNI_ALLOWLIST = [
  "cdn.cloudflare.com",
  "cloudflare-dns.com",
  "one.one.one.one",
  "warp.plus",
  "workers.dev",
  "cdn.fastly.net",
  "fastly.com",
  "fastlylb.net",
  "fsly.net",
  "akamaized.net",
  "akamai.net",
  "akamaihd.net",
  "akamaitechnologies.com",
  "edgesuite.net",
  "cloudfront.net",
  "amazonaws.com",
  "aws.amazon.com",
  "awsstatic.com",
  "googleapis.com",
  "googleusercontent.com",
  "googlevideo.com",
  "gstatic.com",
  "google.com",
  "azureedge.net",
  "azure.microsoft.com",
  "windows.net",
  "msecnd.net",
  "stackpathdns.com",
  "stackpathcdn.com",
  "bootstrapcdn.com",
  "kxcdn.com",
  "keycdn.com",
  "b-cdn.net",
  "bunnycdn.com",
  "incapdns.net",
  "imperva.com",
] as const;
type DomainFrontingSniSelection = "auto_rotating" | `fixed:${(typeof FRONTING_SNI_ALLOWLIST)[number]}`;

function isAuthError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

function normalizeQKey(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("QKey-")) return trimmed;
  if (trimmed.toLowerCase().startsWith("qkey-")) return `QKey-${trimmed.slice(5)}`;
  return `QKey-${trimmed}`;
}

function compactDisplayValue(value: string, maxLength: number): string {
  const normalized = value.trim();
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, maxLength)}…`;
}

function normalizeTomlTextForUi(raw: string): string {
  // Some environments have historically persisted TOML with literal "\\n" sequences.
  // If there are no real newlines, treat "\\n" as escaped newlines for display/editing.
  // Keep this conservative: do not mutate strings that likely contain intentional "\\n" literals.
  if (raw.includes("\\n")) {
    // If the content looks "mostly single-line" but contains escape sequences, normalize.
    // This keeps real multi-line TOML unchanged.
    const realNewlines = raw.split("\n").length - 1;
    const looksLikeLegacy =
      raw.includes("\\n[") || raw.includes("]\\n") || raw.includes("\\n#") || raw.includes("\\n\\n");
    const containsQuotedEscaped =
      raw.includes('"\\\\n"') || raw.includes("'\\\\n'");
    if (realNewlines <= 1 && looksLikeLegacy && !containsQuotedEscaped) {
      return raw.split("\\n").join("\n");
    }
  }
  return raw;
}

function parseSectionName(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith("[")) return null;
  const end = trimmed.indexOf("]");
  if (end < 0) return null;
  const name = trimmed.slice(1, end).trim();
  return name ? name : null;
}

function parseKvLine(line: string): { key: string; value: string } | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  const idx = trimmed.indexOf("=");
  if (idx < 0) return null;
  const key = trimmed.slice(0, idx).trim();
  const value = trimmed.slice(idx + 1).trim();
  if (!key) return null;
  return { key, value };
}

function setSectionValue(contents: string, section: string, key: string, value: string): string {
  const lines = contents.split("\n");
  let inSection = false;
  let sectionFound = false;
  let updated = false;
  let insertAt: number | null = null;
  let lastKeyLine: number | null = null;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    const sec = parseSectionName(trimmed);
    if (sec) {
      if (inSection && !updated && insertAt == null) insertAt = i;
      inSection = sec === section;
      if (inSection) sectionFound = true;
      continue;
    }
    if (!inSection) continue;
    const kv = parseKvLine(trimmed);
    if (!kv) continue;
    if (kv.key !== key) continue;
    // TOML commonly uses "last wins". Track the last occurrence and update that.
    lastKeyLine = i;
  }

  if (lastKeyLine != null) {
    const original = lines[lastKeyLine];
    const commentIdx = original.indexOf("#");
    const comment = commentIdx >= 0 ? original.slice(commentIdx).trimEnd() : "";
    const suffix = comment ? ` ${comment}` : "";
    lines[lastKeyLine] = `${key} = ${value}${suffix}`;
    updated = true;
  }

  if (!updated) {
    if (sectionFound) {
      const idx = insertAt ?? lines.length;
      lines.splice(idx, 0, `${key} = ${value}`);
    } else {
      if (lines.length && lines[lines.length - 1].trim() !== "") lines.push("");
      lines.push(`[${section}]`);
      lines.push(`${key} = ${value}`);
    }
  }

  return lines.join("\n");
}

function readSectionValue(contents: string, section: string, key: string): string | null {
  const lines = contents.split("\n");
  let inSection = false;
  let found: string | null = null;
  for (const line of lines) {
    const trimmed = line.trim();
    const sec = parseSectionName(trimmed);
    if (sec) {
      inSection = sec === section;
      continue;
    }
    if (!inSection) continue;
    const kv = parseKvLine(trimmed);
    if (!kv) continue;
    if (kv.key !== key) continue;
    const raw = (kv.value.split("#")[0] ?? "").trim();
    const unquoted = raw.replace(/^"|"$/g, "").trim();
    found = unquoted ? unquoted : null;
  }
  return found;
}

const CC_ALGORITHMS = ["reno", "cubic", "bbr", "bbr2", "bbr2_gcongestion"] as const;
type CcSelection = (typeof CC_ALGORITHMS)[number] | "__custom__";

function normalizeCcSelection(raw: string | null): CcSelection {
  const v = (raw ?? "").trim().toLowerCase();
  if (!v) return "cubic";
  return (CC_ALGORITHMS as readonly string[]).includes(v) ? (v as CcSelection) : "__custom__";
}

type StealthPresetUi = "auto" | "performance" | "stealth" | "antidpi" | "manual" | "off";

function stealthPresetFromMode(mode: string | null): StealthPresetUi {
  const m = (mode ?? "").toLowerCase();
  if (m === "off") return "off";
  if (m === "manual") return "manual";
  if (m === "performance" || m === "base") return "performance";
  if (m === "stealth") return "stealth";
  if (m === "anti-dpi" || m === "antidpi" || m === "max" || m === "stealthmax" || m === "stealth-max") return "antidpi";
  return "auto";
}

function fecPresetFromConfig(contents: string): "auto" | "off" {
  const mode = (readSectionValue(contents, "fec", "mode") ?? "").trim().toLowerCase();
  if (mode === "off" || mode === "zero") return "off";
  return "auto";
}

function parseBool(raw: string | null): boolean | null {
  const v = (raw ?? "").trim().toLowerCase();
  if (v === "true") return true;
  if (v === "false") return false;
  return null;
}

function parseU16(raw: string | null): number | null {
  const v = (raw ?? "").trim();
  if (!v) return null;
  if (!/^\d+$/.test(v)) return null;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return null;
  // Keep in sync with server-side validation.
  if (n < 1200 || n > 9000) return null;
  return n;
}

function parsePort(raw: string | null): number | null {
  const v = (raw ?? "").trim();
  if (!v) return null;
  if (!/^\d+$/.test(v)) return null;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return null;
  if (n < 1 || n > 65535) return null;
  return n;
}

type StealthManualSettings = {
  enable_domain_fronting: boolean;
  enable_http3_masquerading: boolean;
  enable_xor_obfuscation: boolean;
  use_tls_cover: boolean;
  use_qpack_headers: boolean;
  enable_traffic_padding: boolean;
  enable_timing_obfuscation: boolean;
  enable_protocol_mimicry: boolean;
  enable_doh: boolean;
};

const DEFAULT_STEALTH_MANUAL: StealthManualSettings = {
  enable_domain_fronting: true,
  enable_http3_masquerading: true,
  enable_xor_obfuscation: true,
  use_tls_cover: true,
  use_qpack_headers: true,
  enable_traffic_padding: false,
  enable_timing_obfuscation: false,
  enable_protocol_mimicry: true,
  enable_doh: true,
};

function readStealthFlag(contents: string, key: keyof StealthManualSettings): boolean {
  if (key === "enable_timing_obfuscation") {
    const primary = parseBool(readSectionValue(contents, "stealth", "enable_timing_obfuscation"));
    if (primary != null) return primary;
    const legacy = parseBool(readSectionValue(contents, "stealth", "enable_noble_timing_obfuscation"));
    if (legacy != null) return legacy;
  }
  const v = parseBool(readSectionValue(contents, "stealth", key));
  if (v != null) return v;
  return DEFAULT_STEALTH_MANUAL[key];
}

function selectionToValue(selection: SharedSelection): string | null {
  if (selection === "all") return null;
  const first = Array.from(selection)[0];
  if (first == null) return null;
  return typeof first === "string" ? first : String(first);
}

function canonicalizeConfigForCompare(raw: string): string {
  return normalizeTomlTextForUi(raw).replace(/\r\n/g, "\n").trimEnd();
}

function isRetriablePersistenceError(error: unknown): boolean {
  if (error instanceof ApiError) {
    const status = error.status;
    return status == null || status >= 500;
  }
  return true;
}

export function ConfigurationView() {
  const setAuthRequired = useSetAtom(authRequiredAtom);
  const setAuthError = useSetAtom(authErrorAtom);
  const setConfigDirty = useSetAtom(configDirtyAtom);
  const notify = useNotify();

  // QKey state
  const [qkeyEntries, setQkeyEntries] = useAtom(qkeyListAtom);
  const [qkeyLoading, setQkeyLoading] = useAtom(qkeyListLoadingAtom);
  const [qkeyReady, setQkeyReady] = useState(false);

  // Status state
  const [status, setStatus] = useAtom(statusAtom);
  const [, setStatusLoading] = useAtom(statusLoadingAtom);

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const actionsRef = useRef<HTMLDivElement | null>(null);
  const setToastAnchor = useSetAtom(setToastAnchorAtom);

  const [configText, setConfigText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [manualAnimationReady, setManualAnimationReady] = useState(false);
  const initialManualAnimationSyncRef = useRef(false);
  const manualAnimationFrameRef = useRef<number | null>(null);
  const manualAnimationFrameRef2 = useRef<number | null>(null);

  // QKey UI state
  const createDialog = useDisclosure();
  const [qkeyName, setQkeyName] = useState("");
  const [qkeyPortText, setQkeyPortText] = useState("");
  const [qkeySniSelection, setQkeySniSelection] = useState<DomainFrontingSniSelection>("auto_rotating");
  const [busyCreate, setBusyCreate] = useState(false);
  const [busyRevokeId, setBusyRevokeId] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [busyBulkRevoke, setBusyBulkRevoke] = useState(false);
  const [copiedQkeyId, setCopiedQkeyId] = useState<string | null>(null);
  const qkeyCopyFeedbackTimeoutRef = useRef<number | null>(null);
  const [qkeyAnimationReady, setQkeyAnimationReady] = useState(false);
  const qkeyAnimationFrameRef = useRef<number | null>(null);
  const adminRefreshRef = useRef<(() => Promise<void>) | null>(null);
  const qkeyNameError = (() => {
    const v = qkeyName.trim();
    if (!v) return null;
    if (v.length > MAX_QKEY_NAME_CHARS) return `Name too long [max ${MAX_QKEY_NAME_CHARS} chars]`;
    if ([...v].some((ch) => /[\x00-\x1F\x7F]/.test(ch))) return "Name contains invalid characters";
    return null;
  })();
  const qkeyPortError = (() => {
    const v = qkeyPortText.trim();
    if (!v) return null;
    if (parsePort(v) == null) return "Port must be between 1 and 65535";
    return null;
  })();
  useEffect(() => {
    if (!createDialog.isOpen) {
      setQkeySniSelection("auto_rotating");
    }
  }, [createDialog.isOpen]);

  const [stealthPreset, setStealthPreset] = useState<StealthPresetUi>("auto");
  const [fecPreset, setFecPreset] = useState<"auto" | "off">("auto");
  const [stealthManual, setStealthManual] = useState<StealthManualSettings>(DEFAULT_STEALTH_MANUAL);
  const fecPresetUi: "auto" | "off" = fecPreset === "off" ? "off" : "auto";

  const [transportCc, setTransportCc] = useState<CcSelection>("cubic");
  const [transportMtuText, setTransportMtuText] = useState<string>("1400");
  const confirmDialog = useConfirmDialog();
  useTopStatusAnchor(actionsRef);

  const syncToastAnchorToActions = useCallback(() => {
    const actionsRect = actionsRef.current?.getBoundingClientRect();
    if (!actionsRect) {
      return;
    }
    const main =
      actionsRef.current?.closest("main") instanceof HTMLElement
        ? (actionsRef.current.closest("main") as HTMLElement)
        : null;
    const mainRect = main?.getBoundingClientRect() ?? null;
    const x = mainRect
      ? Math.round(mainRect.left + mainRect.width / 2)
      : Math.round(actionsRect.left + actionsRect.width / 2);
    const y = Math.round(actionsRect.top + actionsRect.height / 2);
    setToastAnchor({ x, y });
  }, [setToastAnchor]);

  const selectClassNames = useMemo(() => ({
    base: "w-[156px]",
    trigger: cn(
      "h-8 min-h-8 px-2.5 rounded-md",
      "glass-nav-pill glass-select-edge",
      "data-[open=true]:border-edge-accent",
    ),
    innerWrapper: "bg-transparent border-0 shadow-none ring-0",
    value: "text-[11px] text-black",
    selectorIcon: "text-black",
    popoverContent: "glass-nav-pill rounded-lg animate-in fade-in-0 zoom-in-95 duration-200",
    listboxWrapper: "p-1",
    listbox: "text-[11px]",
  }) as const, []);
  const fecSelectClassNames = useMemo(() => ({
    ...selectClassNames,
    base: "w-[156px]",
  }), [selectClassNames]);

  const applyConfigToUi = useCallback((rawConfig: string) => {
    const text = normalizeTomlTextForUi(rawConfig);
    const normalizedText = setSectionValue(text, "transport", "enable_pacing", "true");
    setConfigText(normalizedText);
    const stealth = stealthPresetFromMode(readSectionValue(normalizedText, "stealth", "mode"));
    setStealthPreset(stealth);
    setStealthManual({
      enable_domain_fronting: readStealthFlag(normalizedText, "enable_domain_fronting"),
      enable_http3_masquerading: readStealthFlag(normalizedText, "enable_http3_masquerading"),
      enable_xor_obfuscation: readStealthFlag(normalizedText, "enable_xor_obfuscation"),
      use_tls_cover: readStealthFlag(normalizedText, "use_tls_cover"),
      use_qpack_headers: readStealthFlag(normalizedText, "use_qpack_headers"),
      enable_traffic_padding: readStealthFlag(normalizedText, "enable_traffic_padding"),
      enable_timing_obfuscation: readStealthFlag(normalizedText, "enable_timing_obfuscation"),
      enable_protocol_mimicry: readStealthFlag(normalizedText, "enable_protocol_mimicry"),
      enable_doh: readStealthFlag(normalizedText, "enable_doh"),
    });
    setFecPreset(fecPresetFromConfig(normalizedText));
    setTransportCc(normalizeCcSelection(readSectionValue(normalizedText, "transport", "cc_algorithm")));
    {
      const rawMtu = readSectionValue(normalizedText, "transport", "mtu");
      setTransportMtuText(rawMtu?.trim() ?? "");
    }
    setDirty(false);
    setConfigDirty(false);
  }, [setConfigDirty]);

  const fetchConfig = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await getJson<AdminResponse<ConfigResponse>>("/api/config");
      if (!resp.success || !resp.data) throw new Error(resp.message ?? "No config");
      applyConfigToUi(resp.data.config);
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Failed to load config");
        notifyErrorOverlay(notify, message, "configuration:load");
      }
    } finally {
      if (!initialManualAnimationSyncRef.current) {
        initialManualAnimationSyncRef.current = true;
        manualAnimationFrameRef.current = window.requestAnimationFrame(() => {
          manualAnimationFrameRef.current = null;
          manualAnimationFrameRef2.current = window.requestAnimationFrame(() => {
            manualAnimationFrameRef2.current = null;
            setManualAnimationReady(true);
          });
        });
      } else {
        setManualAnimationReady(true);
      }
      setLoading(false);
    }
  }, [applyConfigToUi, notify, setAuthError, setAuthRequired]);

  // QKey functions
  const fetchQKeyList = useCallback(async () => {
    setQkeyLoading(true);
    try {
      const resp = await getJson<AdminResponse<QKeyList>>("/api/qkeys");
      if (!resp.success) throw new Error(resp.message ?? "Failed to load QKeys");
      const list = resp.data?.keys ?? [];
      setQkeyEntries(list);
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        const msg = sanitizeErrorMessage(String(e?.message ?? e), "");
        notifyErrorOverlay(
          notify,
          msg || "Server unreachable. Check backend and login session.",
          "configuration:qkeys-load",
        );
      }
    } finally {
      setQkeyLoading(false);
      setQkeyReady(true);
    }
  }, [notify, setAuthError, setAuthRequired, setQkeyEntries, setQkeyLoading]);

  const copyQKey = useCallback(async (text: string, id?: string) => {
    try {
      await navigator.clipboard.writeText(text);
      if (id) {
        setCopiedQkeyId(id);
        if (qkeyCopyFeedbackTimeoutRef.current !== null) {
          window.clearTimeout(qkeyCopyFeedbackTimeoutRef.current);
        }
        qkeyCopyFeedbackTimeoutRef.current = window.setTimeout(() => {
          setCopiedQkeyId((prev) => (prev === id ? null : prev));
          qkeyCopyFeedbackTimeoutRef.current = null;
        }, 1100);
      }
    } catch {
      if (id) setCopiedQkeyId(null);
    }
  }, []);

  const toggleSelectQKey = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const selectAllQKeys = useCallback(() => {
    if (qkeyEntries.length === 0) {
      setSelectedIds(new Set());
      return;
    }
    const allSelected = qkeyEntries.every((e: QKeyEntry) => selectedIds.has(e.id));
    if (allSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(qkeyEntries.map((e: QKeyEntry) => e.id)));
    }
  }, [qkeyEntries, selectedIds]);

  useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const validIds = new Set(qkeyEntries.map((e: QKeyEntry) => e.id));
      const next = new Set(Array.from(prev).filter((id) => validIds.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [qkeyEntries]);


  useEffect(() => {
    if (!qkeyReady || qkeyAnimationReady) return;
    qkeyAnimationFrameRef.current = window.requestAnimationFrame(() => {
      qkeyAnimationFrameRef.current = null;
      setQkeyAnimationReady(true);
    });
    return () => {
      if (qkeyAnimationFrameRef.current !== null) {
        window.cancelAnimationFrame(qkeyAnimationFrameRef.current);
        qkeyAnimationFrameRef.current = null;
      }
    };
  }, [qkeyReady, qkeyAnimationReady]);

  const bulkRevokeQKeys = useCallback(async () => {
    if (selectedIds.size === 0) return;
    const selectedSet = new Set(selectedIds);
    setQkeyEntries((prev) => prev.filter((entry) => !selectedSet.has(entry.id)));
    setCopiedQkeyId((prev) => (prev && selectedSet.has(prev) ? null : prev));
    setSelectedIds(new Set());
    setBusyBulkRevoke(true);
    let successCount = 0;
    let failCount = 0;
    for (const id of selectedIds) {
      try {
        const resp = await postJson<AdminResponse<unknown>, { id: string }>("/api/qkeys/revoke", { id });
        if (resp.success) successCount++;
        else failCount++;
      } catch {
        failCount++;
      }
    }
    setBusyBulkRevoke(false);
    if (failCount === 0) {
      notify.success(`${successCount} QKey${successCount === 1 ? "" : "s"} revoked`);
    } else {
      notify.warning(`${successCount} revoked, ${failCount} failed`);
      setTimeout(() => { void fetchQKeyList(); }, 600);
    }
  }, [fetchQKeyList, notify, selectedIds]);

  const createQKey = useCallback(async () => {
    if (busyCreate || qkeyNameError || qkeyPortError) return;
    const name = qkeyName.trim();
    const port = parsePort(qkeyPortText);
    const fixedSelection = qkeySniSelection.startsWith("fixed:") ? qkeySniSelection.slice("fixed:".length) : null;
    const fixedDomain = fixedSelection && (FRONTING_SNI_ALLOWLIST as readonly string[]).includes(fixedSelection)
      ? fixedSelection
      : null;
    setBusyCreate(true);
    try {
      const payload: {
        name?: string;
        port?: number;
        sni_strategy: "auto_rotating" | "fixed";
        sni_domain?: string;
      } = {
        sni_strategy: fixedDomain ? "fixed" : "auto_rotating",
      };
      if (name) payload.name = name;
      if (port != null) payload.port = port;
      if (fixedDomain) payload.sni_domain = fixedDomain;
      const resp = await postJson<AdminResponse<QKeyCreateResp>, typeof payload>("/api/qkey", payload);
      if (!resp.success || !resp.data?.qkey) throw new Error(resp.message ?? "QKey create failed");
      const normalized = normalizeQKey(resp.data.qkey);
      notify.success(name ? `QKey created: ${name}` : "QKey created");
      createDialog.onClose();
      setQkeyName("");
      setQkeyPortText("");
      setQkeySniSelection("auto_rotating");
      await fetchQKeyList();
      await copyQKey(normalized);
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        const msg = sanitizeErrorMessage(String(e?.message ?? e), "");
        notifyErrorOverlay(
          notify,
          msg || "QKey create failed. Server unreachable or session expired.",
          "configuration:qkey-create",
        );
      }
    } finally {
      setBusyCreate(false);
    }
  }, [
    busyCreate,
    copyQKey,
    createDialog,
    fetchQKeyList,
    notify,
    qkeyName,
    qkeyNameError,
    qkeyPortError,
    qkeyPortText,
    qkeySniSelection,
    setAuthError,
    setAuthRequired,
  ]);

  const revokeQKey = useCallback(async (id: string) => {
    if (busyRevokeId) return;
    setBusyRevokeId(id);
    setQkeyEntries((prev) => prev.filter((entry) => entry.id !== id));
    setSelectedIds((prev) => {
      if (!prev.has(id)) return prev;
      const next = new Set(prev);
      next.delete(id);
      return next;
    });
    setCopiedQkeyId((prev) => (prev === id ? null : prev));
    try {
      const resp = await postJson<AdminResponse<unknown>, { id: string }>("/api/qkeys/revoke", { id });
      if (!resp.success) throw new Error(resp.message ?? "Revoke failed");
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        const msg = sanitizeErrorMessage(String(e?.message ?? e), "");
        notifyErrorOverlay(
          notify,
          msg || "Revoke failed. Server unreachable or session expired.",
          "configuration:qkey-revoke",
        );
      }
      setTimeout(() => { void fetchQKeyList(); }, 600);
    } finally {
      setBusyRevokeId(null);
    }
  }, [busyRevokeId, fetchQKeyList, notify, setAuthError, setAuthRequired, setQkeyEntries]);

  useEffect(() => {
    fetchConfig();
    fetchQKeyList();
  }, [fetchConfig, fetchQKeyList]);

  useEffect(() => {
    setConfigDirty(dirty);
    return () => setConfigDirty(false);
  }, [dirty, setConfigDirty]);

  useEffect(() => {
    return () => {
      if (manualAnimationFrameRef.current !== null) {
        window.cancelAnimationFrame(manualAnimationFrameRef.current);
        manualAnimationFrameRef.current = null;
      }
      if (manualAnimationFrameRef2.current !== null) {
        window.cancelAnimationFrame(manualAnimationFrameRef2.current);
        manualAnimationFrameRef2.current = null;
      }
      if (qkeyAnimationFrameRef.current !== null) {
        window.cancelAnimationFrame(qkeyAnimationFrameRef.current);
        qkeyAnimationFrameRef.current = null;
      }
      if (qkeyCopyFeedbackTimeoutRef.current !== null) {
        window.clearTimeout(qkeyCopyFeedbackTimeoutRef.current);
        qkeyCopyFeedbackTimeoutRef.current = null;
      }
    };
  }, []);

  const saveConfig = useCallback(async (text: string) => {
    syncToastAnchorToActions();
    setSaving(true);
    try {
      const normalized = normalizeTomlTextForUi(text);
      let persistedConfigText: string | null = null;
      for (let attempt = 1; attempt <= MAX_PERSIST_ATTEMPTS; attempt++) {
        try {
          const resp = await postJson<AdminResponse<unknown>, { config: string }>("/api/config", { config: normalized });
          if (!resp.success) throw new Error(resp.message ?? "Save failed");
          const verifyResp = await getJson<AdminResponse<ConfigResponse>>("/api/config");
          if (!verifyResp.success || !verifyResp.data) throw new Error(verifyResp.message ?? "Save verification failed");
          const savedCanonical = canonicalizeConfigForCompare(verifyResp.data.config);
          const expectedCanonical = canonicalizeConfigForCompare(normalized);
          if (savedCanonical !== expectedCanonical) {
            throw new Error("Save verification failed");
          }
          persistedConfigText = verifyResp.data.config;
          break;
        } catch (e) {
          if (attempt >= MAX_PERSIST_ATTEMPTS || !isRetriablePersistenceError(e)) {
            throw e;
          }
        }
      }
      applyConfigToUi(persistedConfigText ?? normalized);
      notify.success("Changes saved");
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        notifyErrorOverlay(notify, "Failed to save configuration", "configuration:save");
      }
    } finally {
      setSaving(false);
    }
  }, [applyConfigToUi, notify, setAuthError, setAuthRequired, syncToastAnchorToActions]);

  const applyStealthPreset = useCallback((preset: StealthPresetUi) => {
    const normalizedMode =
      preset === "performance"
        ? "performance"
        : preset === "stealth"
          ? "stealth"
          : preset === "antidpi"
            ? "anti-dpi"
            : preset === "manual"
              ? "manual"
              : preset === "off"
                ? "off"
                : "intelligent";
    setStealthPreset(preset);
    setConfigText((prev) => {
      const next = setSectionValue(prev, "stealth", "mode", `"${normalizedMode}"`);
      setDirty(true);
      setConfigDirty(true);
      return next;
    });
  }, [setConfigDirty]);

  const applyStealthManualFlag = useCallback((key: keyof StealthManualSettings, value: boolean) => {
    setStealthManual((prev) => ({ ...prev, [key]: value }));
    setConfigText((prev) => {
      let next = setSectionValue(prev, "stealth", key, value ? "true" : "false");
      if (key === "enable_timing_obfuscation") {
        next = setSectionValue(next, "stealth", "enable_noble_timing_obfuscation", value ? "true" : "false");
      }
      setDirty(true);
      setConfigDirty(true);
      return next;
    });
  }, [setConfigDirty]);

  const applyFecPreset = useCallback((preset: "auto" | "off") => {
    setFecPreset(preset);
    setConfigText((prev) => {
      let next = setSectionValue(prev, "fec", "mode", preset === "off" ? "\"off\"" : "\"auto\"");
      // Keep adaptive_fec consistent with the high-level mode.
      next = setSectionValue(next, "adaptive_fec", "initial_mode", "\"zero\"");
      next = setSectionValue(next, "adaptive_fec", "force_on", "false");
      setDirty(true);
      setConfigDirty(true);
      return next;
    });
  }, [setConfigDirty]);

  const applyTransportCc = useCallback((cc: Exclude<CcSelection, "__custom__">) => {
    setTransportCc(cc);
    setConfigText((prev) => {
      const next = setSectionValue(prev, "transport", "cc_algorithm", `"${cc}"`);
      setDirty(true);
      setConfigDirty(true);
      return next;
    });
  }, [setConfigDirty]);

  const applyTransportMtu = useCallback((mtu: number) => {
    setTransportMtuText(String(mtu));
    setConfigText((prev) => {
      const next = setSectionValue(prev, "transport", "mtu", String(mtu));
      setDirty(true);
      setConfigDirty(true);
      return next;
    });
  }, [setConfigDirty]);

  const fetchStatus = useCallback(async () => {
    setStatusLoading(true);
    try {
      const resp = await getJson<AdminResponse<StatusData>>("/api/status");
      if (!resp.success || !resp.data) throw new Error(resp.message ?? "No status");
      setStatus(resp.data);
    } catch (e: any) {
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Failed to load status");
        notifyErrorOverlay(notify, message, "configuration:status");
      }
    } finally { setStatusLoading(false); }
  }, [notify, setAuthError, setAuthRequired, setStatus, setStatusLoading]);

  useEffect(() => {
    fetchStatus(); fetchConfig();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [fetchConfig, fetchStatus]);

  const refreshAll = useCallback(async () => {
    await Promise.allSettled([fetchStatus(), fetchConfig(), fetchQKeyList(), adminRefreshRef.current?.()]);
  }, [fetchConfig, fetchQKeyList, fetchStatus]);

  const handleRefresh = useCallback(async () => {
    if (dirty) {
      const discard = await confirmDialog(buildUnsavedConfirm("configuration", "refresh"));
      if (!discard) return;
    }
    syncToastAnchorToActions();
    notify.info("Refreshed");
    void refreshAll();
  }, [confirmDialog, dirty, notify, refreshAll, syncToastAnchorToActions]);

  const saveDisabled = saving || !dirty || loading || (transportMtuText.trim().length > 0 && parseU16(transportMtuText) == null);
  const hasQKeys = qkeyEntries.length > 0;
  const allVisibleQKeysSelected = hasQKeys && qkeyEntries.every((e: QKeyEntry) => selectedIds.has(e.id));
  return (
    <div className="flex flex-1 h-full min-h-0 overflow-y-auto">
      <div className="w-full px-6 pt-6 pb-0 min-h-full flex flex-col gap-5 config-black-text">
          <div className="flex items-center justify-between">
          <div>
            <div className="text-[14px] font-bold text-text-primary">Configuration</div>
          </div>
          <div ref={actionsRef} className="relative flex items-center gap-2.5">
            <Btn
              type="button"
              disabled={saveDisabled}
              onClick={() => {
                void saveConfig(configText);
              }}
              variant="accent"
            >
              Save
            </Btn>
            <Btn
              type="button"
              onClick={() => {
                void handleRefresh();
              }}
              variant="secondary"
            >
              Refresh
            </Btn>
            <div
              className={cn(
                "status-chip dashboard-heading-sans",
                status ? "border-positive/35 text-positive" : "border-negative/35 text-negative",
              )}
            >
              <span className={cn("h-2 w-2 rounded-full", status ? "bg-positive shadow-[0_0_10px_rgba(22,163,74,0.55)]" : "bg-negative shadow-[0_0_10px_rgba(220,38,38,0.55)]")} />
              {status ? "Online" : "Offline"}
            </div>
          </div>
        </div>
        <AdminSettingsPanel onRefresh={(fn) => { adminRefreshRef.current = fn; }} />

        <section className="rounded-xl glass px-5 pt-4 pb-5">
          <div className="mb-3 text-[11px] font-semibold text-black dashboard-heading-sans">Connection Presets</div>
          <div className="grid grid-cols-2 gap-x-8 pane-first-item-offset">
            <div className="flex min-w-0 flex-col gap-3">
              <div className="grid grid-cols-[64px_156px] items-center gap-2">
                <div className="text-[11px] font-semibold text-black dashboard-heading-sans">Stealth</div>
              <Select
                aria-label="Stealth preset"
                selectedKeys={new Set([stealthPreset])}
                onSelectionChange={(keys) => {
                  const v = selectionToValue(keys);
                  if (
                    v === "auto" ||
                    v === "performance" ||
                    v === "stealth" ||
                    v === "antidpi" ||
                    v === "manual" ||
                    v === "off"
                  ) {
                    applyStealthPreset(v);
                  }
                }}
                disallowEmptySelection
                classNames={selectClassNames as any}
              >
                <SelectItem key="auto">Auto</SelectItem>
                <SelectItem key="performance">Performance</SelectItem>
                <SelectItem key="stealth">Stealth</SelectItem>
                <SelectItem key="antidpi">AntiDPI</SelectItem>
                <SelectItem key="manual">Manual</SelectItem>
                <SelectItem key="off">Off</SelectItem>
              </Select>
              </div>
              <div className="grid grid-cols-[64px_156px] items-center gap-2">
                <div className="text-[11px] font-semibold text-black dashboard-heading-sans">FEC</div>
                <Select
                  aria-label="FEC preset"
                  selectedKeys={new Set([fecPresetUi])}
                  onSelectionChange={(keys) => {
                    const v = selectionToValue(keys);
                    if (v === "auto" || v === "off") applyFecPreset(v);
                  }}
                  disallowEmptySelection
                  classNames={fecSelectClassNames as any}
                >
                  <SelectItem key="auto">Auto</SelectItem>
                  <SelectItem key="off">Off</SelectItem>
                </Select>
              </div>
            </div>

            <div className="flex min-w-0 flex-col gap-3">
              <div className="grid grid-cols-[64px_156px] items-center gap-2">
                <div className="text-[11px] font-semibold text-black whitespace-nowrap dashboard-heading-sans">Control</div>
                <Select
                  aria-label="Congestion control"
                  selectedKeys={new Set([transportCc])}
                  onSelectionChange={(keys) => {
                    const v = selectionToValue(keys);
                    if (v && (CC_ALGORITHMS as readonly string[]).includes(v)) {
                      applyTransportCc(v as Exclude<CcSelection, "__custom__">);
                    }
                  }}
                  disallowEmptySelection
                  classNames={selectClassNames as any}
                >
                  <SelectItem key="reno">Reno</SelectItem>
                  <SelectItem key="cubic">Cubic</SelectItem>
                  <SelectItem key="bbr">BBR</SelectItem>
                  <SelectItem key="bbr2">BBR2</SelectItem>
                  <SelectItem key="bbr2_gcongestion">BBR2 GC</SelectItem>
                  {transportCc === "__custom__" ? <SelectItem key="__custom__">Custom [from TOML]</SelectItem> : null}
                </Select>
              </div>
              <div className="grid grid-cols-[64px_156px] items-center gap-2">
                <div className="text-[11px] font-semibold text-black whitespace-nowrap dashboard-heading-sans">MTU</div>
                <Input
                  aria-label="MTU"
                  type="text"
                  inputMode="numeric"
                  value={transportMtuText}
                  onValueChange={(v) => {
                    const next = v.slice(0, 4);
                    setTransportMtuText(next);
                    const n = parseU16(next);
                    if (n != null) applyTransportMtu(n);
                  }}
                  maxLength={4}
                  classNames={{
                    base: "w-[156px]",
                    inputWrapper: cn(
                      "h-8 min-h-8 px-2.5 rounded-md",
                      "glass-nav-pill glass-select-edge",
                      "group-data-[focus=true]:border-edge-accent",
                    ),
                    input:
                      "text-[11px] text-black mono !border-0 !outline-none !shadow-none !ring-0 !bg-transparent",
                    innerWrapper: "border-0 outline-none shadow-none ring-0 bg-transparent",
                  } as any}
                />
              </div>
            </div>
          </div>

          <AnimatePresence initial={false}>
            {stealthPreset === "manual" ? (
              <motion.div
                key="stealth-manual"
                initial={manualAnimationReady ? { height: 0, opacity: 0 } : false}
                animate={{ height: "auto", opacity: 1 }}
                exit={manualAnimationReady
                  ? { height: 0, opacity: 0 }
                  : { height: 0, opacity: 0 }
                }
                transition={
                  manualAnimationReady
                    ? {
                        height: { duration: 0.42, ease: [0.25, 0.46, 0.45, 0.94] },
                        opacity: { duration: 0.28, ease: [0.25, 0.46, 0.45, 0.94] },
                      }
                    : { duration: 0 }
                }
                className="overflow-hidden border-t border-edge/60"
              >
                <div className="mt-3 pt-3 pb-3">
                  <div className="grid grid-cols-3 gap-2.5">
                    {([
                      ["enable_domain_fronting", "Domain Fronting"],
                      ["enable_http3_masquerading", "HTTP3 Masquerading"],
                      ["enable_xor_obfuscation", "XOR Obfuscation"],
                      ["use_tls_cover", "TLS Cover"],
                      ["use_qpack_headers", "QPACK Headers"],
                      ["enable_traffic_padding", "Traffic Padding"],
                      ["enable_timing_obfuscation", "Timing Obfuscation"],
                      ["enable_protocol_mimicry", "Protocol Mimicry"],
                      ["enable_doh", "DoH"],
                    ] as [keyof StealthManualSettings, string][]).map(([key, label], idx) => (
                      <motion.div
                        key={key}
                        initial={manualAnimationReady ? { opacity: 0, y: -4 } : false}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        transition={
                          manualAnimationReady
                            ? { duration: 0.24, ease: [0.25, 0.46, 0.45, 0.94], delay: 0.03 + idx * 0.018 }
                            : { duration: 0 }
                        }
                        className="flex w-full items-center justify-between rounded-lg glass-nav-pill px-2.5 py-1.5"
                      >
                        <div className="text-[11px] text-black">{label}</div>
                        <Toggle
                          checked={stealthManual[key]}
                          onChange={(v) => applyStealthManualFlag(key, Boolean(v))}
                          label={label}
                        />
                      </motion.div>
                    ))}
                  </div>
                </div>
              </motion.div>
            ) : null}
          </AnimatePresence>
        </section>

        {/* QKey Management Section */}
        <section className="rounded-xl glass">
          <div className="pane-header border-b border-edge flex items-center justify-between">
            <div className="text-[11px] font-semibold text-black dashboard-heading-sans">QKeys</div>
            <div className="flex items-center gap-2">
              {selectedIds.size > 0 && (
                <Btn
                  type="button"
                  variant="danger"
                  loading={busyBulkRevoke}
                  onClick={() => {
                    void bulkRevokeQKeys();
                  }}
                >
                  Revoke [{selectedIds.size}]
                </Btn>
              )}
              <Btn
                type="button"
                onClick={selectAllQKeys}
                disabled={!hasQKeys}
                variant="neutral"
                className={allVisibleQKeysSelected ? "border-edge-accent text-black" : "text-black"}
              >
                {allVisibleQKeysSelected ? "Deselect All" : "Select All"}
              </Btn>
              <Btn
                variant="accent"
                onClick={() => {
                  window.setTimeout(createDialog.onOpen, RIPPLE_ACTION_DELAY_MS);
                }}
              >
                Generate
              </Btn>
            </div>
          </div>
          <div className="pane-body">
            {qkeyLoading && !qkeyReady ? (
              <div className="space-y-2">
                <SkeletonCard />
                <SkeletonCard />
                <SkeletonCard />
              </div>
            ) : (
              <div style={{ minHeight: 40 }}>
                <AnimatePresence initial={false}>
                  {qkeyEntries.map((e: QKeyEntry) => {
                    const value = normalizeQKey(e.qkey || e.id);
                    const compact = compactDisplayValue(value, MAX_QKEY_DISPLAY_CHARS);
                    return (
                      <motion.div
                        key={e.id}
                        initial={qkeyAnimationReady ? { height: 0, opacity: 0 } : false}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={
                          qkeyAnimationReady
                            ? {
                                height: { duration: 0.38, ease: [0.25, 0.46, 0.45, 0.94] },
                                opacity: { duration: 0.26, ease: [0.25, 0.46, 0.45, 0.94] },
                              }
                            : { duration: 0 }
                        }
                        style={{ overflow: 'hidden' }}
                      >
                        <div className="pb-2">
                          <div
                            className={cn(
                              "rounded-lg px-3 py-2.5 space-y-1 cursor-pointer",
                              selectedIds.has(e.id) ? "bg-[rgba(232,226,246,0.7)]" : "",
                            )}
                            style={{
                              background: selectedIds.has(e.id) ? undefined : "rgba(255,255,255,0.65)",
                              backdropFilter: "blur(24px) saturate(200%)",
                              WebkitBackdropFilter: "blur(24px) saturate(200%)",
                              border: "1px solid rgba(255,255,255,0.60)",
                              boxShadow: "inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03)",
                            }}
                            onClick={() => toggleSelectQKey(e.id)}
                          >
                            {e.name ? <div className="text-[12px] font-bold text-accent">{e.name}</div> : null}
                            <div className="flex items-center justify-between gap-3">
                              <div className="text-[12px] font-normal text-accent min-w-0 flex-1 truncate" title={value}>
                                {compact}
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                <Btn
                                  variant="copy"
                                  disabled={!(e.qkey || e.id)}
                                  onClick={(ev) => {
                                    ev.stopPropagation();
                                    void copyQKey(value, e.id);
                                  }}
                                >
                                  <span className="relative z-10 inline-grid place-items-center">
                                    <span className="invisible">Copy</span>
                                    <AnimatePresence initial={false} mode="wait">
                                      {copiedQkeyId === e.id ? (
                                        <motion.span
                                          key="copied"
                                          initial={{ opacity: 0, y: 4, scale: 0.96 }}
                                          animate={{ opacity: 1, y: 0, scale: 1 }}
                                          exit={{ opacity: 0, y: -4, scale: 0.96 }}
                                          transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
                                          className="absolute inset-0 inline-flex items-center justify-center"
                                        >
                                          <Check className="h-3.5 w-3.5" />
                                        </motion.span>
                                      ) : (
                                        <motion.span
                                          key="copy"
                                          initial={{ opacity: 0, y: 4, scale: 0.96 }}
                                          animate={{ opacity: 1, y: 0, scale: 1 }}
                                          exit={{ opacity: 0, y: -4, scale: 0.96 }}
                                          transition={{ duration: 0.24, ease: [0.22, 1, 0.36, 1] }}
                                          className="absolute inset-0 inline-flex items-center justify-center"
                                        >
                                          Copy
                                        </motion.span>
                                      )}
                                    </AnimatePresence>
                                  </span>
                                </Btn>
                                <Btn
                                  variant="danger"
                                  loading={busyRevokeId === e.id}
                                  onClick={(ev) => {
                                    ev.stopPropagation();
                                    void revokeQKey(e.id);
                                  }}
                                >
                                  Revoke
                                </Btn>
                              </div>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    );
                  })}
                  {qkeyEntries.length === 0 && qkeyReady && (
                    <motion.div
                      key="qkey-empty"
                      initial={qkeyAnimationReady ? { height: 0, opacity: 0 } : false}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={
                        qkeyAnimationReady
                          ? {
                              height: { duration: 0.35, ease: [0.25, 0.46, 0.45, 0.94] },
                              opacity: { duration: 0.24, ease: [0.25, 0.46, 0.45, 0.94] },
                            }
                          : { duration: 0 }
                      }
                      style={{ overflow: 'hidden' }}
                    >
                      <div className="pb-2">
                        <div
                          className="rounded-lg px-3 py-2.5 text-[11px] font-semibold text-black dashboard-heading-sans"
                          style={{
                            background: "rgba(255,255,255,0.65)",
                            backdropFilter: "blur(24px) saturate(200%)",
                            WebkitBackdropFilter: "blur(24px) saturate(200%)",
                            border: "1px solid rgba(255,255,255,0.60)",
                            boxShadow: "inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03)",
                          }}
                        >
                          No Keys created
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            )}
          </div>
        </section>

        <div className="mt-auto pt-4">
          <section className="rounded-xl glass border border-edge/70">
            <div className="px-5 pt-4 pb-4 dashboard-heading-sans">
              <div className="flex items-center gap-2 mb-4">
                <div className="text-[11px] font-semibold text-black dashboard-heading-sans">Reference Guide</div>
                <div className="h-px flex-1 bg-edge/55" />
              </div>

              <div className="grid grid-cols-2 gap-0">
                {/* Left column: Stealth */}
                <div className="pr-5 border-r border-white/50">
                  {/* Stealth */}
                  <div>
                    <div className="text-[11px] font-bold tracking-[0.08em] text-accent/70 mb-1 dashboard-heading-sans">Stealth</div>
                    {([
                      ["Auto", "Intelligent adaptive behavior."],
                      ["Performance", "Domain fronting + HTTP3 masquerading + TLS Cover."],
                      ["Stealth", "Balanced masking with adaptive padding."],
                      ["AntiDPI", "Maximum anti-censorship & detection resistance."],
                      ["Manual", "Feature flags controlled explicitly."],
                      ["Off", "Disable stealth transformations."],
                    ] as const).map(([label, desc]) => (
                      <div key={label} className="flex items-baseline gap-1.5 py-[3px]">
                        <span className="text-[10px] font-semibold text-black/75 shrink-0 dashboard-heading-sans w-[72px]">{label}</span>
                        <span className="text-[10px] text-black/40 leading-[14px] dashboard-heading-sans">{desc}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Right column: Congestion Control */}
                <div className="pl-5 pt-0 border-t-0 border-white/50">
                  <div className="text-[11px] font-bold tracking-[0.08em] text-accent/70 mb-1 dashboard-heading-sans">Congestion Control</div>
                  {([
                    ["Reno", "Conservative AIMD recovery."],
                    ["Cubic", "General-purpose cubic growth."],
                    ["BBR", "Model-based throughput optimization."],
                    ["BBR2", "Improved fairness and loss response."],
                    ["BBR2 GC", "Maps to BBR2 transport path."],
                  ] as const).map(([label, desc]) => (
                    <div key={label} className="flex items-baseline gap-1.5 py-[3px]">
                      <span className="text-[10px] font-semibold text-black/75 shrink-0 dashboard-heading-sans w-[72px]">{label}</span>
                      <span className="text-[10px] text-black/40 leading-[14px] dashboard-heading-sans">{desc}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* FEC row aligned to same two-column grid as Stealth/Congestion */}
              <div className="grid grid-cols-2 gap-0 mt-3 pt-3 border-t border-white/50">
                <div className="pr-5 border-r border-white/50">
                  <div className="text-[11px] font-bold tracking-[0.08em] text-accent/70 mb-1 dashboard-heading-sans">FEC</div>
                  <div className="flex items-baseline gap-1.5 py-[3px] dashboard-heading-sans">
                    <span className="text-[10px] font-semibold text-black/75 shrink-0 w-[72px]">Auto</span>
                    <span className="text-[10px] text-black/40 leading-[14px]">Adaptive FEC tunes redundancy.</span>
                  </div>
                </div>
                <div className="pl-5">
                  <div className="h-[22px] mb-1" aria-hidden="true" />
                  <div className="flex items-baseline gap-1.5 py-[3px] dashboard-heading-sans">
                    <span className="text-[10px] font-semibold text-black/75 shrink-0 w-[72px]">Off</span>
                    <span className="text-[10px] text-black/40 leading-[14px]">FEC fully deactivated.</span>
                  </div>
                </div>
              </div>
            </div>
          </section>
        </div>

      </div>
      <AppDialog isOpen={createDialog.isOpen} onOpenChange={createDialog.onOpenChange}>
      <AppDialogContent>
        <form
          className="contents"
          onSubmit={(e) => {
            e.preventDefault();
            if (!busyCreate && !qkeyNameError && !qkeyPortError) void createQKey();
          }}
        >
        <AppDialogHeader className="text-text-primary">Generate QKey</AppDialogHeader>
        <AppDialogBody className="space-y-3">
          <TextInput
            label="Name of the Connection"
            value={qkeyName}
            onChange={setQkeyName}
            maxLength={MAX_QKEY_NAME_CHARS}
            autoFocus
            labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
          />
          <TextInput
            label="Port [1-65535]"
            value={qkeyPortText}
            onChange={setQkeyPortText}
            maxLength={5}
            labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans"
          />
          <div className="space-y-1.5">
            <div className="text-[11px] font-semibold text-black dashboard-heading-sans">Domain Fronting [SNI]</div>
            <Select
              aria-label="Domain Fronting [SNI]"
              items={[
                { id: "auto_rotating", label: "Auto [Rotating]" },
                ...FRONTING_SNI_ALLOWLIST.map((domain) => ({ id: domain, label: domain })),
              ]}
              selectedKeys={new Set([qkeySniSelection])}
              onSelectionChange={(keys) => {
                const v = selectionToValue(keys);
                if (!v) return;
                if (v === "auto_rotating") {
                  setQkeySniSelection("auto_rotating");
                  return;
                }
                if ((FRONTING_SNI_ALLOWLIST as readonly string[]).includes(v)) {
                  setQkeySniSelection(`fixed:${v}` as DomainFrontingSniSelection);
                }
              }}
              disallowEmptySelection
              classNames={{
                ...selectClassNames,
                base: "w-full",
              } as any}
            >
              {(item) => <SelectItem key={String(item.id)}>{String(item.label)}</SelectItem>}
            </Select>
            <p className="text-[10px] text-black leading-relaxed">
              Select one fixed allowlisted SNI or use automatic rotating policy.
            </p>
          </div>
        </AppDialogBody>
        <AppDialogFooter>
          <Btn
            variant="ghost"
            onClick={() => {
              window.setTimeout(createDialog.onClose, RIPPLE_ACTION_DELAY_MS);
            }}
            disabled={busyCreate}
          >
            Cancel
          </Btn>
          <Btn
            type="submit"
            variant="accent"
            loading={busyCreate}
            disabled={Boolean(qkeyNameError || qkeyPortError)}
            className="min-w-[108px] justify-center"
          >
            Generate
          </Btn>
        </AppDialogFooter>
        </form>
      </AppDialogContent>
    </AppDialog>
  </div>
  );
}
