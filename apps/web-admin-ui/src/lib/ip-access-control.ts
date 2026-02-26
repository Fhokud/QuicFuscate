export type PendingIpAction = "block" | "unblock";
export type BlockedIpsPayload = {
  ips?: unknown;
  blocked?: unknown;
} | null | undefined;

export function optimisticBlock(ips: string[], ip: string): string[] {
  if (ips.includes(ip)) return ips;
  return [...ips, ip];
}

export function optimisticUnblock(ips: string[], ip: string): string[] {
  return ips.filter((value) => value !== ip);
}

export function extractBlockedIps(payload: BlockedIpsPayload): string[] {
  const raw = Array.isArray(payload?.ips)
    ? payload.ips
    : Array.isArray(payload?.blocked)
      ? payload.blocked
      : [];

  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of raw) {
    if (typeof value !== "string") continue;
    const ip = value.trim();
    if (!ip || seen.has(ip)) continue;
    seen.add(ip);
    out.push(ip);
  }
  return out;
}

export function mergeBlockedIps(serverBlocked: string[], pending: Record<string, PendingIpAction | undefined>): string[] {
  const merged: string[] = [];
  const seen = new Set<string>();
  for (const value of serverBlocked) {
    const ip = value.trim();
    if (!ip || seen.has(ip)) continue;
    seen.add(ip);
    merged.push(ip);
  }

  for (const [ip, action] of Object.entries(pending)) {
    if (!action) continue;
    if (!ip.trim()) continue;
    if (action === "block") {
      if (!seen.has(ip)) {
        seen.add(ip);
        merged.push(ip);
      }
    } else {
      const idx = merged.indexOf(ip);
      if (idx >= 0) {
        merged.splice(idx, 1);
        seen.delete(ip);
      }
    }
  }
  return merged;
}
