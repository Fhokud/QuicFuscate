import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAtom, useSetAtom } from "jotai";
import { LayoutGroup, motion } from "framer-motion";
import { ShieldAlert, ShieldCheck, Lock, Activity } from "lucide-react";
import { getJson, getText, postJson, ApiError, sanitizeErrorMessage } from "@/api";
import {
  authRequiredAtom,
  authErrorAtom,
  statusAtom,
  statusLoadingAtom,
  clientsAtom,
  clientsLoadingAtom,
  metricsAtom,
  metricsLoadingAtom,
} from "@/stores/atoms";
import type { AdminResponse, ClientInfo, MetricsMap, StatusData } from "@/stores/types";
import { cn } from "@/lib/cn";
import {
  extractBlockedIps,
  mergeBlockedIps,
  optimisticBlock,
  optimisticUnblock,
  type PendingIpAction,
} from "@/lib/ip-access-control";
import { Btn } from "@/components/ui/controls";
import { Skeleton, SkeletonText } from "@/components/ui/skeleton";
import { Sparkline } from "@/components/ui/sparkline";
import { useNotify } from "@/lib/use-notify";
import { useTopStatusAnchor } from "@/lib/use-top-status-anchor";
import { notifyErrorOverlay } from "@/lib/notify-error";

function isAuthError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

type BlockedResponse = { ips?: unknown; blocked?: unknown };
type MetricsResponse = { metrics?: MetricsMap | null };

function formatBitsPerSecond(bitsRaw: number): string {
  const bits = Math.max(0, Number.isFinite(bitsRaw) ? bitsRaw : 0);
  const units = [
    { factor: 1, unit: "bit/s" },
    { factor: 1_000, unit: "Kbit/s" },
    { factor: 1_000_000, unit: "Mbit/s" },
    { factor: 1_000_000_000, unit: "Gbit/s" },
    { factor: 1_000_000_000_000, unit: "Tbit/s" },
  ] as const;
  let selected: (typeof units)[number] = units[0];
  for (const u of units) {
    if (bits >= u.factor) selected = u;
  }
  const scaled = bits / selected.factor;
  const decimals = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(decimals)} ${selected.unit}`;
}

function easeOutCubic(t: number): number {
  return 1 - (1 - t) * (1 - t) * (1 - t);
}

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

function formatMetricCount(value: number): string {
  return Math.max(0, Math.round(value)).toLocaleString("en-US");
}

function formatMetricBytes(valueRaw: number): string {
  const value = Math.max(0, valueRaw);
  const units = ["B", "KB", "MB", "GB", "TB"] as const;
  let unitIndex = 0;
  let scaled = value;
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }
  const decimals = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(decimals)} ${units[unitIndex]}`;
}

function formatMetricValue(name: string, value: number): string {
  if (name === "quicfuscate_up") return value >= 1 ? "Online" : "Offline";
  if (name === "quicfuscate_uptime_seconds") return formatUptime(Math.max(0, Math.floor(value)));
  if (name === "quicfuscate_bytes_in_total" || name === "quicfuscate_bytes_out_total") return formatMetricBytes(value);
  if (name.endsWith("_active")) return value >= 1 ? "Enabled" : "Disabled";
  if (Number.isInteger(value)) return formatMetricCount(value);
  return value.toFixed(2);
}

function parsePrometheusTextToMetricsMap(raw: string): MetricsMap {
  const map: MetricsMap = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;
    const metricToken = parts[0];
    const valueToken = parts[1];
    const match = metricToken.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{.*\})?$/);
    if (!match) continue;
    const key = match[1];
    const value = Number(valueToken);
    if (!Number.isFinite(value)) continue;
    map[key] = (map[key] ?? 0) + value;
  }
  return map;
}

function SmoothTrafficValue({ bitsPerSecond }: { bitsPerSecond: number }) {
  const targetBits = Math.max(0, bitsPerSecond);
  const [displayBits, setDisplayBits] = useState(targetBits);
  const displayBitsRef = useRef(targetBits);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    displayBitsRef.current = displayBits;
  }, [displayBits]);

  useEffect(() => {
    const start = displayBitsRef.current;
    const delta = targetBits - start;
    if (Math.abs(delta) < 0.5) {
      displayBitsRef.current = targetBits;
      setDisplayBits(targetBits);
      return;
    }
    if (rafRef.current !== null) {
      window.cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    const durationMs = 560;
    const startedAt = performance.now();
    const step = (now: number) => {
      const t = Math.min(1, (now - startedAt) / durationMs);
      const eased = easeOutCubic(t);
      const next = start + delta * eased;
      displayBitsRef.current = next;
      setDisplayBits(next);
      if (t < 1) {
        rafRef.current = window.requestAnimationFrame(step);
      } else {
        rafRef.current = null;
      }
    };
    rafRef.current = window.requestAnimationFrame(step);
    return () => {
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [targetBits]);

  useEffect(() => {
    return () => {
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, []);

  return <>{formatBitsPerSecond(displayBits)}</>;
}

export function DashboardView() {
  const notify = useNotify();
  const [status, setStatus] = useAtom(statusAtom);
  const [, setStatusLoading] = useAtom(statusLoadingAtom);

  const [clients, setClients] = useAtom(clientsAtom);
  const [, setClientsLoading] = useAtom(clientsLoadingAtom);

  const [metrics, setMetrics] = useAtom(metricsAtom);
  const [, setMetricsLoading] = useAtom(metricsLoadingAtom);

  const [blockedIps, setBlockedIps] = useState<string[]>([]);
  const [, setBlockedLoading] = useState(false);
  const [ipActionPending, setIpActionPending] = useState<Record<string, PendingIpAction | undefined>>({});
  const ipActionPendingRef = useRef<Record<string, PendingIpAction | undefined>>({});
  const [statusReady, setStatusReady] = useState(false);
  const [clientsReady, setClientsReady] = useState(false);
  const [blockedReady, setBlockedReady] = useState(false);
  const [metricsReady, setMetricsReady] = useState(false);
  const [trafficBitsPerSecond, setTrafficBitsPerSecond] = useState<{ in: number; out: number }>({ in: 0, out: 0 });
  const previousTrafficSampleRef = useRef<{ bytesIn: number; bytesOut: number; tsMs: number } | null>(null);
  const [serverPanelCleared, setServerPanelCleared] = useState(false);

  // Metrics history for sparklines
  const [metricsHistory, setMetricsHistory] = useState<{
    bytesIn: number[];
    bytesOut: number[];
    clients: number[];
  }>({ bytesIn: [], bytesOut: [], clients: [] });

  const setAuthRequired = useSetAtom(authRequiredAtom);
  const setAuthError = useSetAtom(authErrorAtom);
  const actionsRef = useRef<HTMLDivElement | null>(null);
  useTopStatusAnchor(actionsRef);

  const beginIpAction = useCallback((ip: string, action: PendingIpAction): boolean => {
    const current = ipActionPendingRef.current[ip];
    if (current) return false;
    const next = { ...ipActionPendingRef.current, [ip]: action };
    ipActionPendingRef.current = next;
    setIpActionPending(next);
    return true;
  }, []);

  const endIpAction = useCallback((ip: string) => {
    const next = { ...ipActionPendingRef.current };
    delete next[ip];
    ipActionPendingRef.current = next;
    setIpActionPending(next);
  }, []);

  const fetchStatus = useCallback(async () => {
    setStatusLoading(true);
    try {
      const resp = await getJson<AdminResponse<StatusData>>("/api/status");
      if (!resp.success || !resp.data) throw new Error(resp.message ?? "No status");
      const data = resp.data;
      setStatus(data);

      const nowMs = performance.now();
      const prev = previousTrafficSampleRef.current;
      let inBitsPerSecond = 0;
      let outBitsPerSecond = 0;
      if (prev) {
        const dtSeconds = Math.max((nowMs - prev.tsMs) / 1000, 0.001);
        const deltaInBytes = Math.max(0, data.bytes_in - prev.bytesIn);
        const deltaOutBytes = Math.max(0, data.bytes_out - prev.bytesOut);
        inBitsPerSecond = (deltaInBytes * 8) / dtSeconds;
        outBitsPerSecond = (deltaOutBytes * 8) / dtSeconds;
      }
      previousTrafficSampleRef.current = {
        bytesIn: data.bytes_in,
        bytesOut: data.bytes_out,
        tsMs: nowMs,
      };
      setTrafficBitsPerSecond({ in: inBitsPerSecond, out: outBitsPerSecond });

      // Update metrics history for sparklines with throughput rates.
      setMetricsHistory(prevHistory => {
        const maxHistory = 20;
        const newBitsIn = [...prevHistory.bytesIn, inBitsPerSecond].slice(-maxHistory);
        const newBitsOut = [...prevHistory.bytesOut, outBitsPerSecond].slice(-maxHistory);
        const newClients = [...prevHistory.clients, data.clients_active].slice(-maxHistory);
        return { bytesIn: newBitsIn, bytesOut: newBitsOut, clients: newClients };
      });
    } catch (e: any) {
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Failed to load server status");
        notifyErrorOverlay(notify, message, "dashboard:status");
      }
    } finally { setStatusLoading(false); setStatusReady(true); }
  }, [notify, setAuthError, setAuthRequired, setStatus, setStatusLoading, setStatusReady]);

  const fetchClients = useCallback(async () => {
    setClientsLoading(true);
    try {
      const resp = await getJson<AdminResponse<ClientInfo[]>>("/api/clients");
      if (!resp.success) throw new Error(resp.message ?? "Failed to load clients");
      setClients(Array.isArray(resp.data) ? resp.data : []);
    } catch (e: any) {
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Failed to load clients");
        notifyErrorOverlay(notify, message, "dashboard:clients");
      }
    } finally { setClientsLoading(false); setClientsReady(true); }
  }, [notify, setAuthError, setAuthRequired, setClients, setClientsLoading, setClientsReady]);

  const fetchMetrics = useCallback(async () => {
    setMetricsLoading(true);
    try {
      const resp = await getJson<AdminResponse<MetricsResponse>>("/api/metrics/json");
      if (!resp.success) throw new Error(resp.message ?? "Failed to load metrics");
      const incoming = resp.data?.metrics;
      const sanitized: MetricsMap = {};
      if (incoming && typeof incoming === "object") {
        for (const [key, raw] of Object.entries(incoming)) {
          if (!key) continue;
          const value = Number(raw);
          if (!Number.isFinite(value)) continue;
          sanitized[key] = value;
        }
      }
      setMetrics(Object.keys(sanitized).length > 0 ? sanitized : null);
    } catch (e: any) {
      if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else if (e instanceof ApiError && e.status === 404) {
        // Backward compatibility: older server builds expose only /api/metrics (Prometheus text).
        try {
          const text = await getText("/api/metrics");
          const fallbackMap = parsePrometheusTextToMetricsMap(text);
          setMetrics(Object.keys(fallbackMap).length > 0 ? fallbackMap : null);
        } catch (fallbackErr: any) {
          if (isAuthError(fallbackErr)) {
            setAuthError(null);
            setAuthRequired(true);
          } else {
            const message = sanitizeErrorMessage(String(fallbackErr?.message ?? fallbackErr), "Failed to load metrics");
            notifyErrorOverlay(notify, message, "dashboard:metrics-fallback");
          }
        }
      } else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Failed to load metrics");
        notifyErrorOverlay(notify, message, "dashboard:metrics");
      }
    } finally { setMetricsLoading(false); setMetricsReady(true); }
  }, [notify, setAuthError, setAuthRequired, setMetrics, setMetricsLoading, setMetricsReady]);

  const fetchBlocked = useCallback(async () => {
    setBlockedLoading(true);
    try {
      const resp = await getJson<AdminResponse<BlockedResponse>>("/api/blocked");
      if (!resp.success) throw new Error(resp.message ?? "Failed to load blocked IPs");
      const serverBlocked = extractBlockedIps(resp.data);
      setBlockedIps(mergeBlockedIps(serverBlocked, ipActionPendingRef.current));
    } catch (e: any) {
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else {
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Failed to load blocked IPs");
        notifyErrorOverlay(notify, message, "dashboard:blocked-list");
      }
    } finally { setBlockedLoading(false); setBlockedReady(true); }
  }, [notify, setAuthError, setAuthRequired, setBlockedReady]);

  useEffect(() => {
    fetchStatus(); fetchClients(); fetchMetrics(); fetchBlocked();
    const statusTick = setInterval(() => { fetchStatus(); }, 1200);
    const fast = setInterval(() => { fetchClients(); fetchBlocked(); }, 5000);
    const slow = setInterval(() => { fetchMetrics(); }, 15000);
    return () => { clearInterval(statusTick); clearInterval(fast); clearInterval(slow); };
  }, [fetchBlocked, fetchClients, fetchMetrics, fetchStatus]);

  const blockIp = useCallback(async (ip: string) => {
    if (!beginIpAction(ip, "block")) return;
    setBlockedIps((prev) => optimisticBlock(prev, ip));
    try {
      const resp = await postJson<AdminResponse<unknown>, { ip: string }>("/api/block", { ip });
      if (!resp.success) throw new Error(resp.message ?? "Block failed");
      notify.success(`Blocked ${ip}`);
    } catch (e: any) {
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else {
        setBlockedIps((prev) => optimisticUnblock(prev, ip));
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Block failed");
        notifyErrorOverlay(notify, message, "dashboard:block");
      }
    } finally {
      endIpAction(ip);
      fetchBlocked();
    }
  }, [beginIpAction, endIpAction, fetchBlocked, notify, setAuthError, setAuthRequired]);

  const unblockIp = useCallback(async (ip: string) => {
    if (!beginIpAction(ip, "unblock")) return;
    setBlockedIps((prev) => optimisticUnblock(prev, ip));
    try {
      const resp = await postJson<AdminResponse<unknown>, { ip: string }>("/api/unblock", { ip });
      if (!resp.success) throw new Error(resp.message ?? "Unblock failed");
      notify.success(`Unblocked ${ip}`);
    } catch (e: any) {
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else {
        setBlockedIps((prev) => optimisticBlock(prev, ip));
        const message = sanitizeErrorMessage(String(e?.message ?? e), "Unblock failed");
        notifyErrorOverlay(notify, message, "dashboard:unblock");
      }
    } finally {
      endIpAction(ip);
      fetchBlocked();
    }
  }, [beginIpAction, endIpAction, fetchBlocked, notify, setAuthError, setAuthRequired]);
  const metricMap = useMemo(() => metrics ?? {}, [metrics]);
  const ipPanelInitialLoading = !(clientsReady && blockedReady);

  const refreshAllDashboardMetrics = useCallback(async () => {
    setServerPanelCleared(false);
    await Promise.allSettled([
      fetchStatus(),
      fetchClients(),
      fetchMetrics(),
      fetchBlocked(),
    ]);
  }, [fetchBlocked, fetchClients, fetchMetrics, fetchStatus]);

  const handleRefreshDashboard = useCallback(() => {
    notify.info("Refreshed");
    void refreshAllDashboardMetrics();
  }, [notify, refreshAllDashboardMetrics]);

  const clearServerPanel = useCallback(() => {
    setMetricsHistory({ bytesIn: [], bytesOut: [], clients: [] });
    setServerPanelCleared(true);
  }, []);

  const blockedSet = new Set(blockedIps);
  const realConnectedIps = clients.map((c) => c.ip).filter((ip) => !blockedSet.has(ip));
  const connectedIps = realConnectedIps;
  const blockedIpsDisplay = blockedIps;
  const serverListenValue = serverPanelCleared ? "-" : (status?.listen ?? "-");
  const serverUptimeValue = serverPanelCleared ? "-" : (status ? formatUptime(status.uptime_secs) : "-");
  const serverClientsValue = serverPanelCleared ? "-" : (status ? String(status.clients_active) : "-");
  const serverRejectedValue = serverPanelCleared
    ? "-"
    : (
      typeof metricMap.quicfuscate_connections_rejected === "number"
        ? formatMetricCount(metricMap.quicfuscate_connections_rejected)
        : "-"
    );
  const serverInboundValue = serverPanelCleared
    ? "-"
    : (() => {
      const raw = metricMap.quicfuscate_bytes_in_total;
      if (raw == null || raw <= 0) return "-";
      return formatMetricValue("quicfuscate_bytes_in_total", raw);
    })();
  const serverOutboundValue = serverPanelCleared
    ? "-"
    : (() => {
      const raw = metricMap.quicfuscate_bytes_out_total;
      if (raw == null || raw <= 0) return "-";
      return formatMetricValue("quicfuscate_bytes_out_total", raw);
    })();

  return (
    <div className="flex flex-1 min-h-0 overflow-y-auto">
      <div className="w-full px-6 py-6 space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="text-[14px] font-bold text-text-primary">Dashboard</div>
          <div ref={actionsRef} className="flex items-center gap-2.5">
            <Btn
              type="button"
              onClick={handleRefreshDashboard}
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
        {/* Server: KPI card with expandable clients */}
        <section className="rounded-xl glass border border-edge/70">
          <div className="pane-header flex items-start justify-between">
            <div className="text-[11px] text-black font-semibold dashboard-heading-sans">Server</div>
            <Btn
              type="button"
              onClick={clearServerPanel}
              variant="neutral"
            >
              Clear
            </Btn>
          </div>
          <div className="pane-body grid grid-cols-4 gap-y-5 gap-x-8">
            <KPI label="Listen" value={serverListenValue} loading={!serverPanelCleared && !statusReady} />
            <KPI label="Uptime" value={serverUptimeValue} loading={!serverPanelCleared && !statusReady} />
            <KPI
              label="Upstream"
              value={serverPanelCleared ? "-" : formatBitsPerSecond(trafficBitsPerSecond.in)}
              trafficBitsPerSecond={serverPanelCleared ? undefined : trafficBitsPerSecond.in}
              loading={!serverPanelCleared && !statusReady}
              sparkline={serverPanelCleared ? [] : metricsHistory.bytesIn}
            />
            <KPI
              label="Downstream"
              value={serverPanelCleared ? "-" : formatBitsPerSecond(trafficBitsPerSecond.out)}
              trafficBitsPerSecond={serverPanelCleared ? undefined : trafficBitsPerSecond.out}
              loading={!serverPanelCleared && !statusReady}
              sparkline={serverPanelCleared ? [] : metricsHistory.bytesOut}
            />
            <KPI label="Clients" value={serverClientsValue} loading={!serverPanelCleared && !statusReady} />
            <KPI
              label="Rejected"
              value={serverRejectedValue}
              loading={!serverPanelCleared && !metricsReady}
            />
            <KPI
              label="Inbound Total"
              value={serverInboundValue}
              loading={!serverPanelCleared && !metricsReady}
            />
            <KPI
              label="Outbound Total"
              value={serverOutboundValue}
              loading={!serverPanelCleared && !metricsReady}
            />
          </div>
        </section>

        {/* IP Access Control — Dual Column Threat Matrix */}
        <section className="rounded-xl glass border border-edge/70 flex flex-col">
          <div className="pane-header border-b border-edge flex items-center justify-between">
            <div className="text-[11px] text-black font-semibold dashboard-heading-sans">
              IP Access Control
            </div>
          </div>
          <div className="pane-body p-3">
            {ipPanelInitialLoading ? (
              <SkeletonText lines={6} />
            ) : connectedIps.length === 0 && blockedIpsDisplay.length === 0 ? (
              <div className="text-[12px] font-medium text-black text-center py-8 opacity-50 flex items-center justify-center gap-2">
                <Activity className="w-4 h-4" />
                No IP activity detected
              </div>
            ) : (
              <LayoutGroup>
                <div className="grid grid-cols-2 gap-4">
                  {/* Connected IPs (Left) */}
                  <div className="flex flex-col min-h-[60px] max-h-[320px]">
                    <div className="text-[9px] uppercase tracking-[0.08em] font-semibold text-black/40 dashboard-heading-sans px-1 pb-1.5 shrink-0">Connected</div>
                    <div className="flex flex-col gap-1.5 overflow-y-auto overflow-x-hidden ip-scroll-col flex-1">
                      {connectedIps.length === 0 ? (
                        <div className="text-[11px] text-black/40 text-center py-4">
                          No active connections
                        </div>
                      ) : (
                        connectedIps.map((ip) => (
                          <IpRow key={ip} ip={ip} isBlocked={false} onAction={() => blockIp(ip)} isPending={ipActionPending[ip] === "block"} />
                        ))
                      )}
                    </div>
                  </div>
                  {/* Blocked IPs (Right) */}
                  <div className="flex flex-col min-h-[60px] max-h-[320px]">
                    <div className="text-[9px] uppercase tracking-[0.08em] font-semibold text-black/40 dashboard-heading-sans px-1 pb-1.5 shrink-0">Blocked</div>
                    <div className="flex flex-col gap-1.5 overflow-y-auto overflow-x-hidden ip-scroll-col flex-1">
                      {blockedIpsDisplay.length === 0 ? (
                        <div className="text-[11px] text-black/40 text-center py-4">
                          No blocked IPs
                        </div>
                      ) : (
                        blockedIpsDisplay.map((ip) => (
                          <IpRow key={ip} ip={ip} isBlocked={true} onAction={() => unblockIp(ip)} isPending={ipActionPending[ip] === "unblock"} />
                        ))
                      )}
                    </div>
                  </div>
                </div>
              </LayoutGroup>
            )}
          </div>
        </section>

      </div>
    </div>
  );
}

function KPI({
  label,
  value,
  accent,
  color,
  loading,
  sparkline,
  trafficBitsPerSecond,
}: {
  label: string;
  value: string;
  accent?: boolean;
  color?: string;
  loading?: boolean;
  sparkline?: number[];
  trafficBitsPerSecond?: number;
}) {
  const showTrafficDash = typeof trafficBitsPerSecond === "number" && trafficBitsPerSecond <= 0;
  const valueClassName = cn(
    "text-[11px] font-semibold truncate text-center dashboard-heading-sans",
    color ? undefined : (accent ? "text-accent" : "!text-[#6366f1]"),
  );
  return (
    <div className="relative h-[68px] rounded-[10px] border border-[rgba(255,255,255,0.82)] bg-white/72 px-3 py-2.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.88),0_1px_3px_rgba(18,26,44,0.08)]">
      <div className="flex h-full flex-col min-w-0">
        <div className="h-[12px] leading-[12px] text-[10px] font-semibold text-black/54 tracking-[0.03em] truncate dashboard-heading-sans">
          {label}
        </div>
        {loading ? (
          <div className="mt-[12px] h-[15px] flex items-center justify-center">
            <Skeleton className="h-[10px] w-[64px] rounded" />
          </div>
        ) : showTrafficDash ? (
          <div className="mt-[11px] h-[16px] leading-[16px] text-[11px] font-semibold truncate text-center !text-[#6366f1] dashboard-heading-sans">
            -
          </div>
        ) : (
          <div className="relative mt-[11px] h-[16px] leading-[16px]">
            <div className={valueClassName} style={color ? { color } : undefined}>
              {typeof trafficBitsPerSecond === "number" ? <SmoothTrafficValue bitsPerSecond={trafficBitsPerSecond} /> : value}
            </div>
            {!(typeof trafficBitsPerSecond === "number") && sparkline && sparkline.length > 0 && (
              <div className="absolute right-0 bottom-0">
                <Sparkline data={sparkline} width={48} height={20} color={color || "var(--color-accent)"} />
              </div>
            )}
          </div>
        )}
        <div className="mt-auto h-[11px] leading-[11px] text-[9px] text-transparent" aria-hidden="true">
          &nbsp;
        </div>
      </div>
    </div>
  );
}

function IpRow({ ip, isBlocked, onAction, isPending }: { ip: string; isBlocked: boolean; onAction: () => void; isPending: boolean }) {
  return (
    <motion.div
      layout
      layoutId={`ip-row-${ip}`}
      initial={false}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, transition: { duration: 0.1 } }}
      transition={{ type: "spring", stiffness: 320, damping: 26, mass: 0.85 }}
      className="glass-firewall-row rounded-[10px] w-full px-3 py-[7px] flex items-center justify-between gap-2 group"
    >
      <div className="flex items-center gap-2 min-w-0">
        <div className="w-4 h-4 flex items-center justify-center shrink-0">
          {isBlocked ? (
            <Lock className="w-4 h-4 text-red-500/75" strokeWidth={2.5} />
          ) : (
            <div className="w-2 h-2 rounded-full bg-cyan-400 pulse-signal" />
          )}
        </div>
        <span
          className={cn(
            "text-[11.5px] font-semibold dashboard-heading-sans tracking-[0.01em] truncate",
            isBlocked ? "text-black/40" : "text-black",
          )}
          style={isBlocked ? { textDecoration: "line-through", textDecorationColor: "rgba(0,0,0,0.35)", textDecorationThickness: "1.5px" } : undefined}
        >
          {ip}
        </span>
      </div>
      <button
        onClick={onAction}
        disabled={isPending}
        className={cn(
          "w-8 h-8 rounded-[10px] flex items-center justify-center glass-pane-pill cursor-pointer overflow-hidden shrink-0",
          "transition-all duration-200 ease-[cubic-bezier(0.22,1,0.36,1)]",
          isBlocked
            ? "text-green-600/70 hover:text-green-600 hover:shadow-[0_0_12px_rgba(34,197,94,0.25)]"
            : "text-red-500/60 hover:text-red-500 hover:shadow-[0_0_12px_rgba(239,68,68,0.25)]",
          isPending && "opacity-40 cursor-not-allowed",
        )}
        aria-label={isBlocked ? "Unblock IP" : "Block IP"}
      >
        {isPending ? (
          <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
        ) : isBlocked ? (
          <ShieldCheck className="w-[18px] h-[18px]" strokeWidth={2} />
        ) : (
          <ShieldAlert className="w-[18px] h-[18px]" strokeWidth={2} />
        )}
      </button>
    </motion.div>
  );
}
