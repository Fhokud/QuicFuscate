import type { PendingIpAction } from "$lib/types";

export type BlockedResponse = { ips?: unknown; blocked?: unknown };

function normalizeIpList(values: readonly unknown[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    result.push(trimmed);
  }

  return result;
}

export function extractBlockedIps(data: BlockedResponse | null | undefined): string[] {
  if (!data) return [];
  const raw = data.ips ?? data.blocked;
  if (!Array.isArray(raw)) return [];
  return normalizeIpList(raw);
}

export function optimisticBlock(existing: readonly string[], ip: string): string[] {
  return normalizeIpList([...existing, ip]);
}

export function optimisticUnblock(existing: readonly string[], ip: string): string[] {
  const target = ip.trim();
  return normalizeIpList(existing.filter((entry) => entry.trim() !== target));
}

export function mergeBlockedIps(
  serverBlocked: readonly string[],
  pending: Record<string, PendingIpAction | undefined>,
): string[] {
  let merged = normalizeIpList(serverBlocked);

  for (const [ip, action] of Object.entries(pending)) {
    if (!action) continue;
    if (action === "block") {
      merged = optimisticBlock(merged, ip);
      continue;
    }
    merged = optimisticUnblock(merged, ip);
  }

  return merged;
}
