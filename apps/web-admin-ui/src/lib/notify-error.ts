type ErrorNotifier = {
  error: (message: string, duration?: number) => void;
};

const ERROR_OVERLAY_COOLDOWN_MS = 4000;
const errorOverlayLedger = new Map<string, number>();

export function notifyErrorOverlay(
  notify: ErrorNotifier,
  message: string,
  key?: string,
  cooldownMs: number = ERROR_OVERLAY_COOLDOWN_MS,
) {
  const normalized = message.trim();
  if (!normalized) return;
  const dedupeKey = key ? `${key}:${normalized}` : normalized;
  const now = Date.now();
  const last = errorOverlayLedger.get(dedupeKey) ?? 0;
  if (now - last < cooldownMs) return;
  errorOverlayLedger.set(dedupeKey, now);
  notify.error(normalized);
}
