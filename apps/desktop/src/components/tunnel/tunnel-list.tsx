import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAtom, useAtomValue } from "jotai";
import { useSetAtom } from "jotai";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { SlidersHorizontal, Zap, Clock3, ArrowDownUp, Trash2 } from "lucide-react";
import { tunnelsAtom, selectedTunnelIdAtom, tunnelStatesAtom, tunnelStatsAtom, settingsAtom, errorAtom } from "@/stores/atoms";
import type { TunnelConfig } from "@/stores/types";
import { addToastAtom } from "@/stores/toastAtom";
import { cn, countryCodeToFlag, formatBytes, formatDuration, formatRate } from "@/lib/utils";
import { parseRemote } from "@/lib/tunnel-validators";
import { displayCcMode, displayFecMode, displayMtu, displayStealthMode } from "@/lib/policy-display";
import { resolveDomainFrontingSniDisplay } from "@/lib/domain-fronting-policy";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { CreateTunnelDialog } from "./add-tunnel-dialog";
import { ImportQKeyDialog } from "./add-tunnel-dialog";
import { TunnelConfigDialog } from "./tunnel-config-dialog";
import { ConnectButton } from "@/components/ui/connect-button";

type TunnelPolicyView = {
  stealth: string;
  fec: string;
  mtu: string;
  cc: string;
  sniDisplay: string;
  customDetails: string[];
  source: "server" | "qkey";
};

const DEFAULT_POLICY: TunnelPolicyView = {
  stealth: "auto",
  fec: "auto",
  mtu: "server",
  cc: "server",
  sniDisplay: "QKey Policy",
  customDetails: [],
  source: "server",
};
const BUTTON_RIPPLE_VISIBILITY_DELAY_MS = 88;

const policyValueSeparator = " | ";
const WHITE_PILL_CLASS = cn(
  "inline-flex items-center rounded-full border border-[rgba(255,255,255,0.60)]",
  "bg-[rgba(255,255,255,0.72)] px-2 py-0.5",
  "shadow-[inset_0_1px_0_0.5px_rgba(255,255,255,0.55),0_3px_10px_rgba(0,0,0,0.06),0_1px_2px_rgba(0,0,0,0.03)]",
);
const WHITE_PILL_BACKDROP_STYLE = {
  backdropFilter: "blur(24px) saturate(200%)",
  WebkitBackdropFilter: "blur(24px) saturate(200%)",
};
const SIDEBAR_PILL_STYLE = {
  background: "rgba(255,255,255,0.65)",
  backdropFilter: "blur(24px) saturate(200%)",
  WebkitBackdropFilter: "blur(24px) saturate(200%)",
  border: "1px solid rgba(255,255,255,0.60)",
  boxShadow: "inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03)",
};

function normalizeMode(raw: string | null | undefined, fallback = "auto"): string {
  const v = (raw ?? "").trim().toLowerCase();
  return v || fallback;
}

function isFecOff(raw: string | null | undefined): boolean {
  const v = normalizeMode(raw, "");
  return v === "off" || v === "zero";
}

function formatPercent(value: number, digits = 1): string {
  const clamped = Math.min(100, Math.max(0, Number.isFinite(value) ? value : 0));
  return `${clamped.toFixed(digits)}%`;
}

function formatRemoteAddress(remote: string): string {
  const parsed = parseRemote(remote);
  if (!parsed) return remote.trim();
  const host = parsed.server.includes(":") ? `[${parsed.server}]` : parsed.server;
  return `${host}:${parsed.port}`;
}

type ChartPoint = { x: number; y: number };
type IndexedValue = { index: number; value: number };

function chartPointsIndexed(
  values: IndexedValue[],
  maxValue: number,
  width: number,
  top: number,
  bottom: number,
  domainSteps: number,
): ChartPoint[] {
  const safeMax = Math.max(1, maxValue);
  const steps = Math.max(1, domainSteps);
  if (values.length === 0) return [];
  return values.map(({ index, value }) => ({
    x: (index / steps) * width,
    y: bottom - ((Math.max(0, value) / safeMax) * (bottom - top)),
  }));
}

function parseExtraPolicy(extra: string | null | undefined): {
  mtu: string;
  cc: string;
  customDetails: string[];
} {
  const out = { mtu: "server", cc: "server", customDetails: [] as string[] };
  const raw = (extra ?? "").trim();
  if (!raw) return out;

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const maybeMtu = parsed.mtu;
      const maybeCc = parsed.cc ?? parsed.congestion ?? parsed.congestionControl;
      if (typeof maybeMtu === "number" || typeof maybeMtu === "string") {
        const v = String(maybeMtu).trim();
        if (v) out.mtu = v;
      }
      if (typeof maybeCc === "string") {
        const v = maybeCc.trim();
        if (v) out.cc = v.toLowerCase();
      }

      const details: string[] = [];
      for (const [k, v] of Object.entries(parsed)) {
        if (k === "mtu" || k === "cc" || k === "congestion" || k === "congestionControl") continue;
        if (typeof v === "boolean" && v) {
          details.push(`${k}: enabled`);
          continue;
        }
        if (typeof v === "number") {
          details.push(`${k}: ${v}`);
          continue;
        }
        if (typeof v === "string" && v.trim().length > 0) {
          details.push(`${k}: ${v.trim()}`);
          continue;
        }
      }
      out.customDetails = details.slice(0, 4);
      return out;
    }
  } catch {
    // Not JSON, fall through to simple split.
  }

  out.customDetails = raw
    .split(/[,;]+/)
    .map((part) => part.trim())
    .filter(Boolean)
    .slice(0, 4);
  return out;
}

function SessionMetric({
  label,
  value,
  detail,
  badge,
  badgeClassName,
}: {
  label: string;
  value: string;
  detail?: string;
  badge?: React.ReactNode;
  badgeClassName?: string;
}) {
  return (
    <div className="relative h-[68px] rounded-[10px] border border-[rgba(255,255,255,0.82)] bg-white/72 px-3 py-2.5 shadow-[inset_0_1px_0_rgba(255,255,255,0.88),0_1px_3px_rgba(18,26,44,0.08)]">
      {badge ? <div className={cn("absolute right-1 top-0", badgeClassName)}>{badge}</div> : null}
      <div className="flex h-full flex-col min-w-0">
        <div className="h-[11px] leading-[11px] text-[9px] font-semibold text-black/54 tracking-[0.03em] truncate">{label}</div>
        <div className="mt-[12px] h-[15px] leading-[15px] text-[10px] font-semibold metric-value-accent truncate text-center !text-[#6366f1]">{value}</div>
        <div className={cn("mt-auto h-[11px] leading-[11px] text-[9px] truncate", detail ? "text-black/48" : "text-transparent")} aria-hidden={!detail}>
          {detail ?? "\u00A0"}
        </div>
      </div>
    </div>
  );
}

function ModeCornerBadge({
  label,
  tone = "neutral",
  compact = false,
}: {
  label: string;
  tone?: "neutral" | "positive";
  compact?: boolean;
}) {
    return (
    <span
      className={cn(
        "inline-flex h-[15px] items-center justify-center rounded-[5px] border text-[8px] font-semibold leading-none shadow-[inset_0_1px_0_rgba(255,255,255,0.86),0_1px_2px_rgba(18,26,44,0.12)]",
        compact ? "min-w-[15px] px-[2px]" : "min-w-[24px] px-1.5",
        tone === "positive"
          ? "border-[rgba(255,255,255,0.82)] bg-white/82 text-[rgb(22,163,74)] font-bold"
          : "border-[rgba(255,255,255,0.82)] bg-white/82 text-black/72",
      )}
      aria-hidden="true"
    >
      {label}
    </span>
  );
}

function IntelligentModeBadge() {
  return (
    <span className="relative inline-flex" title="Intelligent mode" aria-label="Intelligent mode">
      <ModeCornerBadge label="I" tone="positive" compact />
    </span>
  );
}

function GpuConnectionChart({
  downPoints,
  upPoints,
  downTail,
  upTail,
  gridColor,
  downColor,
  upColor,
  showSeries,
}: {
  downPoints: ChartPoint[];
  upPoints: ChartPoint[];
  downTail: ChartPoint;
  upTail: ChartPoint;
  gridColor: string;
  downColor: string;
  upColor: string;
  showSeries: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const gridLayerRef = useRef<HTMLCanvasElement | null>(null);
  const rafRef = useRef<number | null>(null);
  const gridDirtyRef = useRef(true);
  const sizeRef = useRef({ width: 0, height: 0, dpr: 1 });
  const previousGridColorRef = useRef(gridColor);
  const modelRef = useRef({
    downPoints,
    upPoints,
    downTail,
    upTail,
    gridColor,
    downColor,
    upColor,
    showSeries,
  });

  const syncCanvasSize = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return false;
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(1, rect.width);
    const height = Math.max(1, rect.height);
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const pixelWidth = Math.round(width * dpr);
    const pixelHeight = Math.round(height * dpr);
    if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
      canvas.width = pixelWidth;
      canvas.height = pixelHeight;
    }
    if (!gridLayerRef.current) {
      gridLayerRef.current = document.createElement("canvas");
    }
    if (gridLayerRef.current.width !== pixelWidth || gridLayerRef.current.height !== pixelHeight) {
      gridLayerRef.current.width = pixelWidth;
      gridLayerRef.current.height = pixelHeight;
      gridDirtyRef.current = true;
    }
    const previous = sizeRef.current;
    const changed = previous.width !== width || previous.height !== height || previous.dpr !== dpr;
    sizeRef.current = { width, height, dpr };
    if (changed) gridDirtyRef.current = true;
    return changed;
  }, []);

  const ensureGridLayer = useCallback(() => {
    const layer = gridLayerRef.current;
    if (!layer || !gridDirtyRef.current) return;
    const ctx = layer.getContext("2d", { alpha: true });
    if (!ctx) return;
    const { width, height, dpr } = sizeRef.current;
    if (width <= 0 || height <= 0) return;

    const toPxX = (x: number) => (x / 100) * width;
    const toPxY = (y: number) => (y / 28) * height;
    const scaleY = height / 28;
    const gridStrokeWidth = Math.max(0.3, 0.14 * scaleY);
    const { gridColor: nextGridColor } = modelRef.current;

    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, layer.width, layer.height);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.strokeStyle = nextGridColor;
    ctx.lineWidth = gridStrokeWidth;
    ctx.lineCap = "round";
    for (let idx = 0; idx < 6; idx += 1) {
      const y = (28 / 6) * (idx + 1);
      const py = toPxY(y);
      ctx.beginPath();
      ctx.moveTo(0, py);
      ctx.lineTo(width, py);
      ctx.stroke();
    }
    for (let idx = 0; idx < 8; idx += 1) {
      const x = (80 / 8) * (idx + 1);
      const px = toPxX(x);
      ctx.beginPath();
      ctx.moveTo(px, 0);
      ctx.lineTo(px, height);
      ctx.stroke();
    }

    gridDirtyRef.current = false;
  }, []);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: true, desynchronized: true });
    if (!ctx) return;
    const { width, height, dpr } = sizeRef.current;
    if (width <= 0 || height <= 0) return;
    const {
      downPoints: nextDownPoints,
      upPoints: nextUpPoints,
      downTail: nextDownTail,
      upTail: nextUpTail,
      downColor: nextDownColor,
      upColor: nextUpColor,
      showSeries: nextShowSeries,
    } = modelRef.current;

    const toPxX = (x: number) => (x / 100) * width;
    const toPxY = (y: number) => (y / 28) * height;
    const scaleY = height / 28;
    const traceStrokeWidth = Math.max(0.45, 0.44 * scaleY);

    ensureGridLayer();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (gridLayerRef.current) ctx.drawImage(gridLayerRef.current, 0, 0);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const drawTrace = (points: ChartPoint[], color: string, opacity = 1) => {
      if (points.length === 0) return;
      ctx.save();
      ctx.globalAlpha = opacity;
      ctx.strokeStyle = color;
      ctx.lineWidth = traceStrokeWidth;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      ctx.moveTo(toPxX(points[0].x), toPxY(points[0].y));
      for (let i = 1; i < points.length; i += 1) {
        ctx.lineTo(toPxX(points[i].x), toPxY(points[i].y));
      }
      ctx.stroke();
      ctx.restore();
    };

    if (nextShowSeries) {
      drawTrace(nextDownPoints, nextDownColor, 1);
      drawTrace(nextUpPoints, nextUpColor, 0.95);
    }

    const drawPoint = (
      point: ChartPoint,
      outerRadius: number,
      outerColor: string,
      innerRadius: number,
      innerColor: string,
      strokeColor: string,
      strokeWidth: number,
    ) => {
      const px = toPxX(point.x);
      const py = toPxY(point.y);
      const outerR = Math.max(1, outerRadius * scaleY);
      const innerR = Math.max(0.7, innerRadius * scaleY);
      const innerStroke = Math.max(0.2, strokeWidth * scaleY);

      ctx.beginPath();
      ctx.arc(px, py, outerR, 0, Math.PI * 2);
      ctx.fillStyle = outerColor;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(px, py, innerR, 0, Math.PI * 2);
      ctx.fillStyle = innerColor;
      ctx.fill();
      ctx.lineWidth = innerStroke;
      ctx.strokeStyle = strokeColor;
      ctx.stroke();
    };

    if (nextShowSeries) {
      drawPoint(nextDownTail, 1.65, "rgba(92,103,245,0.2)", 0.78, nextDownColor, "rgba(255,255,255,0.9)", 0.14);
      drawPoint(nextUpTail, 1.45, "rgba(131,103,245,0.18)", 0.66, nextUpColor, "rgba(255,255,255,0.88)", 0.12);
    }
  }, [ensureGridLayer]);

  const scheduleDraw = useCallback(() => {
    if (rafRef.current !== null) return;
    rafRef.current = window.requestAnimationFrame(() => {
      rafRef.current = null;
      draw();
    });
  }, [draw]);

  useEffect(() => {
    modelRef.current = {
      downPoints,
      upPoints,
      downTail,
      upTail,
      gridColor,
      downColor,
      upColor,
      showSeries,
    };
    if (previousGridColorRef.current !== gridColor) {
      previousGridColorRef.current = gridColor;
      gridDirtyRef.current = true;
    }
    scheduleDraw();
  }, [downColor, downPoints, downTail, gridColor, scheduleDraw, showSeries, upColor, upPoints, upTail]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    syncCanvasSize();
    scheduleDraw();

    const canvas = canvasRef.current;
    if (!canvas) return;

    const handleResize = () => {
      if (syncCanvasSize()) scheduleDraw();
    };

    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      resizeObserver = new ResizeObserver(handleResize);
      resizeObserver.observe(canvas);
    }
    window.addEventListener("resize", handleResize);

    return () => {
      if (resizeObserver) resizeObserver.disconnect();
      window.removeEventListener("resize", handleResize);
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [scheduleDraw, syncCanvasSize]);

  return <canvas ref={canvasRef} className="absolute inset-0 h-full w-full pointer-events-none" aria-hidden="true" />;
}

function ConnectionVisualizer({
  state,
  downBps,
  upBps,
  latencyLabel,
  downRate,
  upRate,
  downTotal,
  upTotal,
  uptime,
  className,
}: {
  state: "inactive" | "activating" | "active" | "deactivating";
  downBps: number;
  upBps: number;
  latencyLabel: string;
  downRate: string;
  upRate: string;
  downTotal: string;
  upTotal: string;
  uptime: string;
  className?: string;
}) {
  const isActive = state === "active";
  const isConnecting = state === "activating" || state === "deactivating";
  const showSeries = isActive;
  const HISTORY_SECONDS = 90;
  const UPDATES_PER_SECOND = 19;
  const SAMPLE_INTERVAL_MS = 1000 / UPDATES_PER_SECOND;
  const SAMPLE_COUNT = HISTORY_SECONDS * UPDATES_PER_SECOND; // 90s history at 19 updates/second
  const MINIMAL_SMOOTHING_ALPHA = 0.14;
  const MAX_RENDER_POINTS = 720;
  const DOWN_COLOR = "rgba(92,103,245,0.96)";
  const UP_COLOR = "rgba(131,103,245,0.94)";
  const GRID_COLOR = "rgba(42,46,68,0.14)";
  const initialSeed = { down: Math.max(0, downBps), up: Math.max(0, upBps) };
  const downBufferRef = useRef(new Float32Array(SAMPLE_COUNT));
  const upBufferRef = useRef(new Float32Array(SAMPLE_COUNT));
  const writeCursorRef = useRef(1 % SAMPLE_COUNT);
  const sampleSizeRef = useRef(1);
  const initializedRef = useRef(false);
  const [seriesVersion, setSeriesVersion] = useState(0);
  const wasLiveRef = useRef(false);
  const isTabVisibleRef = useRef(true);
  const liveInputRef = useRef({
    downBps: Math.max(0, downBps),
    upBps: Math.max(0, upBps),
    isActive,
    isConnecting,
  });

  if (!initializedRef.current) {
    downBufferRef.current[0] = initialSeed.down;
    upBufferRef.current[0] = initialSeed.up;
    initializedRef.current = true;
  }
  
  const appendSample = (targetDown: number, targetUp: number) => {
    const nextDown = Math.max(0, targetDown);
    const nextUp = Math.max(0, targetUp);
    const downBuffer = downBufferRef.current;
    const upBuffer = upBufferRef.current;
    const sampleSize = sampleSizeRef.current;
    const writeCursor = writeCursorRef.current;
    const prevCursor = sampleSize > 0 ? (writeCursor - 1 + SAMPLE_COUNT) % SAMPLE_COUNT : 0;
    const prevDown = sampleSize > 0 ? downBuffer[prevCursor] : nextDown;
    const prevUp = sampleSize > 0 ? upBuffer[prevCursor] : nextUp;
    const smoothDown = prevDown + (nextDown - prevDown) * MINIMAL_SMOOTHING_ALPHA;
    const smoothUp = prevUp + (nextUp - prevUp) * MINIMAL_SMOOTHING_ALPHA;

    downBuffer[writeCursor] = smoothDown;
    upBuffer[writeCursor] = smoothUp;
    writeCursorRef.current = (writeCursor + 1) % SAMPLE_COUNT;
    sampleSizeRef.current = Math.min(SAMPLE_COUNT, sampleSize + 1);
    setSeriesVersion((v) => (v + 1) % 1_000_000_000);
  };

  const resetTrace = (seedDown: number, seedUp: number) => {
    const down = Math.max(0, seedDown);
    const up = Math.max(0, seedUp);
    downBufferRef.current[0] = down;
    upBufferRef.current[0] = up;
    writeCursorRef.current = 1 % SAMPLE_COUNT;
    sampleSizeRef.current = 1;
    setSeriesVersion((v) => (v + 1) % 1_000_000_000);
  };

  useEffect(() => {
    const liveNow = isActive;
    if (liveNow && !wasLiveRef.current) {
      const seedDown = Math.max(0, downBps);
      const seedUp = Math.max(0, upBps);
      resetTrace(seedDown, seedUp);
    }
    if (!liveNow && wasLiveRef.current) {
      resetTrace(0, 0);
    }
    wasLiveRef.current = liveNow;
  }, [downBps, upBps, isActive]);

  useEffect(() => {
    if (typeof document === "undefined") return;
    const syncVisibility = () => {
      isTabVisibleRef.current = document.visibilityState === "visible";
    };
    syncVisibility();
    document.addEventListener("visibilitychange", syncVisibility);
    return () => {
      document.removeEventListener("visibilitychange", syncVisibility);
    };
  }, []);

  useEffect(() => {
    liveInputRef.current = {
      downBps: Math.max(0, downBps),
      upBps: Math.max(0, upBps),
      isActive,
      isConnecting,
    };
  }, [downBps, upBps, isActive, isConnecting]);

  useEffect(() => {
    const interval = setInterval(() => {
      if (!isTabVisibleRef.current) return;
      const current = liveInputRef.current;
      if (!current.isActive) {
        return;
      }
      const nextDown = current.isActive ? current.downBps : 0;
      const nextUp = current.isActive ? current.upBps : 0;
      appendSample(nextDown, nextUp);
    }, SAMPLE_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [MINIMAL_SMOOTHING_ALPHA, SAMPLE_INTERVAL_MS]);

  const scaleMaxRef = useRef(20 * 1e6);

  // Compute stable scale and chart geometry in one pass.
  const { downPoints, upPoints, downTail, upTail, scaleLabels } = useMemo(() => {
    const downBuffer = downBufferRef.current;
    const upBuffer = upBufferRef.current;
    const sampleSize = Math.max(1, sampleSizeRef.current);
    const oldestCursor = sampleSize < SAMPLE_COUNT ? 0 : writeCursorRef.current;
    let rawMax = 1;
    for (let i = 0; i < sampleSize; i += 1) {
      const cursor = (oldestCursor + i) % SAMPLE_COUNT;
      const down = downBuffer[cursor] ?? 0;
      const up = upBuffer[cursor] ?? 0;
      const peak = down > up ? down : up;
      if (peak > rawMax) rawMax = peak;
    }
    const paddedMax = rawMax * 1.08;
    const niceSteps = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000];

    const currentScale = Math.max(1, scaleMaxRef.current);
    let stableScale = currentScale;

    // Hysteresis: change scale only when we really leave the current band.
    if (paddedMax > currentScale * 0.92 || paddedMax < currentScale * 0.56) {
      const targetMbps = paddedMax / 1e6;
      let nextScale = niceSteps[niceSteps.length - 1] * 1e6;
      for (const step of niceSteps) {
        if (targetMbps <= step) {
          nextScale = step * 1e6;
          break;
        }
      }
      stableScale = nextScale;
      scaleMaxRef.current = nextScale;
    }

    const displayScale = Math.max(1, stableScale);
    const renderCount = Math.max(1, Math.min(MAX_RENDER_POINTS, sampleSize));
    const downSeries: IndexedValue[] = [];
    const upSeries: IndexedValue[] = [];

    if (renderCount === 1) {
      const logicalIndex = sampleSize - 1;
      const cursor = (oldestCursor + logicalIndex) % SAMPLE_COUNT;
      downSeries.push({ index: logicalIndex, value: downBuffer[cursor] ?? 0 });
      upSeries.push({ index: logicalIndex, value: upBuffer[cursor] ?? 0 });
    } else {
      for (let i = 0; i < renderCount; i += 1) {
        const logicalIndex = Math.round((i * (sampleSize - 1)) / (renderCount - 1));
        const cursor = (oldestCursor + logicalIndex) % SAMPLE_COUNT;
        downSeries.push({ index: logicalIndex, value: downBuffer[cursor] ?? 0 });
        upSeries.push({ index: logicalIndex, value: upBuffer[cursor] ?? 0 });
      }
    }

    const downPts = chartPointsIndexed(downSeries, displayScale, 80, 5, 28, SAMPLE_COUNT - 1);
    const upPts = chartPointsIndexed(upSeries, displayScale, 80, 9, 28, SAMPLE_COUNT - 1);
    const downTailPoint = downPts[downPts.length - 1] ?? { x: 80, y: 28 };
    const upTailPoint = upPts[upPts.length - 1] ?? { x: 80, y: 28 };

    const maxMbps = displayScale / 1e6;
    const labels = [maxMbps, maxMbps * 0.75, maxMbps * 0.5, maxMbps * 0.25, 0];

    return {
      downPoints: downPts,
      upPoints: upPts,
      downTail: downTailPoint,
      upTail: upTailPoint,
      scaleLabels: labels,
    };
  }, [MAX_RENDER_POINTS, SAMPLE_COUNT, seriesVersion]);

  const statusLedColor = isActive
    ? "#22c55e"
    : (state === "activating" || state === "deactivating")
      ? "#f59e0b"
      : "#ef4444";
  const statusLedGlowColor = isActive
    ? "rgba(34,197,94,0.52)"
    : (state === "activating" || state === "deactivating")
      ? "rgba(245,158,11,0.48)"
      : "rgba(239,68,68,0.44)";
  // Format scale label in Mbit/s with nice round numbers
  const formatScaleMbps = (mbps: number): string => {
    if (mbps === 0) return "0";
    if (mbps >= 1000) return `${(mbps / 1000).toFixed(mbps % 1000 === 0 ? 0 : 1)} Gbit/s`;
    if (mbps >= 1) return `${Number.isInteger(mbps) ? mbps : mbps.toFixed(1)} Mbit/s`;
    return `${(mbps * 1000).toFixed(0)} Kbit/s`;
  };

  return (
    <div className={cn(
      "w-full h-full flex flex-col rounded-[8px] border border-black/[0.06] bg-white/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_1px_2px_rgba(18,26,44,0.05)]",
      className,
    )}
    >
      {/* Header row: [uptime left]  [quality badge + LED right] */}
      <div className="flex items-center justify-between mb-1.5 h-[16px] px-[18px] pt-[9px]">
        <span className="flex items-center gap-1.5">
          <Clock3 className="w-[9px] h-[9px] text-black/75 shrink-0" strokeWidth={2.35} />
          <span className="text-[10px] font-semibold text-black/70 tabular-nums">{uptime}</span>
        </span>
        <div className="relative h-[18px] w-[24px] shrink-0">
          <span
            className="absolute right-[-2px] top-[3px] h-[8px] w-[8px] rounded-full"
            style={{
              backgroundColor: statusLedColor,
              boxShadow: `0 0 8px 2px ${statusLedGlowColor}`,
            }}
            aria-hidden="true"
          />
        </div>
      </div>

      {/* Chart area — subtle gradient background */}
      <div className="relative flex-1 min-h-[60px] overflow-hidden rounded-t-[6px] rounded-b-none border border-b-0 border-black/[0.04] bg-[linear-gradient(180deg,rgba(255,255,255,0.95)_0%,rgba(250,249,255,0.85)_50%,rgba(248,246,254,0.8)_100%)]">
        <GpuConnectionChart
          downPoints={downPoints}
          upPoints={upPoints}
          downTail={downTail}
          upTail={upTail}
          gridColor={GRID_COLOR}
          downColor={DOWN_COLOR}
          upColor={UP_COLOR}
          showSeries={showSeries}
        />
        
        {/* Y-axis scale labels — nice round numbers at each grid line */}
        {isActive && (
          <div className="absolute right-[4px] top-0 bottom-0 flex flex-col justify-between items-end pointer-events-none py-[2px]">
            {scaleLabels.map((mbps, idx) => (
              <span key={`scale-${idx}`} className="text-[8px] font-semibold text-black/40 tabular-nums leading-none">
                {formatScaleMbps(mbps)}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Metrics footer — 4 fixed-width columns, flush left */}
      <div className="rounded-b-[6px] border border-t-0 border-black/[0.04] bg-white/40 py-[7px] px-[18px] flex items-center justify-between">
        {/* ↓ Download speed — fixed 72px */}
        <div className="flex items-center gap-1.5 w-[80px] shrink-0 tabular-nums">
          <span className="font-bold text-[10px] leading-none text-[rgba(99,102,241,0.82)] shrink-0">↓</span>
          <span className="text-[9px] font-semibold text-[rgba(99,102,241,0.9)]">{downRate}</span>
        </div>
        {/* ↑ Upload speed — fixed 72px */}
        <div className="flex items-center gap-1.5 w-[80px] shrink-0 tabular-nums">
          <span className="font-bold text-[10px] leading-none text-[rgba(139,92,246,0.78)] shrink-0">↑</span>
          <span className="text-[9px] font-semibold text-[rgba(139,92,246,0.85)]">{upRate}</span>
        </div>
        {/* ⚡ Latency — fixed 66px */}
        <div className="flex items-center gap-1.5 w-[72px] shrink-0 tabular-nums">
          <Zap className="w-[9px] h-[9px] text-black fill-black shrink-0" strokeWidth={1.5} />
          <span className="text-[9px] font-semibold text-black/60">{latencyLabel}</span>
        </div>
        {/* ⇅ Total transferred — fills remaining space */}
        <div className="flex items-center gap-1.5 w-[104px] shrink-0 tabular-nums">
          <ArrowDownUp className="w-[9px] h-[9px] text-black shrink-0" strokeWidth={2.6} />
          <span className="text-[9px] font-semibold text-black/70 tabular-nums">{downTotal}</span>
          <span className="text-[8px] text-black/35 select-none">|</span>
          <span className="text-[9px] font-semibold text-black/70 tabular-nums">{upTotal}</span>
        </div>
      </div>
    </div>
  );
}

export function TunnelList() {
  const [tunnels, setTunnels] = useAtom(tunnelsAtom);
  const [selectedId, setSelectedId] = useAtom(selectedTunnelIdAtom);
  const [settings] = useAtom(settingsAtom);
  const tunnelStates = useAtomValue(tunnelStatesAtom);
  const tunnelStats = useAtomValue(tunnelStatsAtom);
  const setTunnelStates = useSetAtom(tunnelStatesAtom);
  const setError = useSetAtom(errorAtom);
  const addToast = useSetAtom(addToastAtom);
  const [createOpen, setCreateOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);
  const [pendingDisconnectId, setPendingDisconnectId] = useState<string | null>(null);
  const [pendingSwitchTargetId, setPendingSwitchTargetId] = useState<string | null>(null);
  const [switchingTunnelId, setSwitchingTunnelId] = useState<string | null>(null);
  const [configTunnelId, setConfigTunnelId] = useState<string | null>(null);
  const [qkeyPolicyById, setQkeyPolicyById] = useState<Record<string, TunnelPolicyView>>({});
  const [throughputById, setThroughputById] = useState<Record<string, { downBps: number; upBps: number }>>({});
  const throughputSampleRef = useRef<Record<string, { ts: number; rx: number; tx: number }>>({});
  const rippleDelayTimersRef = useRef<number[]>([]);

  const displayTunnels = tunnels;
  const qkeyFingerprint = useMemo(() => tunnels.map((t) => `${t.id}:${t.qkey}`).join("|"), [tunnels]);
  const pendingDelete = useMemo(
    () => tunnels.find((t) => t.id === pendingDeleteId) ?? null,
    [pendingDeleteId, tunnels],
  );
  const pendingDisconnect = useMemo(
    () => tunnels.find((t) => t.id === pendingDisconnectId) ?? null,
    [pendingDisconnectId, tunnels],
  );
  const pendingSwitchTarget = useMemo(
    () => tunnels.find((t) => t.id === pendingSwitchTargetId) ?? null,
    [pendingSwitchTargetId, tunnels],
  );
  const activeTunnelId = useMemo(
    () => Object.entries(tunnelStates).find(([, state]) => state === "active")?.[0] ?? null,
    [tunnelStates],
  );
  const activeTunnel = useMemo(
    () => (activeTunnelId ? tunnels.find((t) => t.id === activeTunnelId) ?? null : null),
    [activeTunnelId, tunnels],
  );
  const hasTransitioningTunnel = useMemo(
    () => Object.values(tunnelStates).some((state) => state === "activating" || state === "deactivating"),
    [tunnelStates],
  );
  const selectedCardId = selectedId;
  const selectedTunnel = useMemo(() => {
    if (displayTunnels.length === 0) return null;
    const found = displayTunnels.find((t) => t.id === selectedCardId) ?? null;
    return found;
  }, [displayTunnels, selectedCardId]);
  const selectedState = selectedTunnel ? (tunnelStates[selectedTunnel.id] ?? "inactive") : "inactive";
  const selectedStats = selectedTunnel ? (tunnelStats[selectedTunnel.id] ?? null) : null;
  const selectedThroughput = selectedTunnel ? (throughputById[selectedTunnel.id] ?? null) : null;
  const selectedHasQKey = Boolean(selectedTunnel?.qkey.trim());
  const selectedFlag = selectedTunnel ? countryCodeToFlag(selectedTunnel.countryCode) : "";
  const selectedStatus = selectedState === "active"
    ? { label: "Connected", textClass: "text-positive" }
    : selectedState === "activating"
      ? { label: "Connecting", textClass: "text-warning" }
      : selectedState === "deactivating"
        ? { label: "Stopping", textClass: "text-warning" }
        : { label: "Idle", textClass: "text-black/55" };
  const selectedPolicy = useMemo(() => {
    if (!selectedTunnel) return DEFAULT_POLICY;
    return qkeyPolicyById[selectedTunnel.id] ?? DEFAULT_POLICY;
  }, [qkeyPolicyById, selectedTunnel]);
  const selectedSniDisplay = useMemo(() => {
    if (!selectedTunnel) return "-";
    const runtimeSni = (selectedStats?.currentSni ?? "").trim();
    if (runtimeSni.length > 0) return runtimeSni;

    const overrideSni = (selectedTunnel?.debugSniOverride ?? "").trim();
    if (overrideSni.length > 0) return overrideSni;

    const configuredSni = (selectedTunnel?.sni ?? "").trim();
    if (configuredSni.length > 0) return configuredSni;

    const policySni = (selectedPolicy.sniDisplay ?? "").trim();
    return policySni.length > 0 ? policySni : "-";
  }, [
    selectedPolicy.sniDisplay,
    selectedStats?.currentSni,
    selectedTunnel?.debugSniOverride,
    selectedTunnel?.sni,
  ]);
  const selectedLatency = selectedStats ? `${selectedStats.latencyMs.toFixed(1)} ms` : "-";
  const selectedUptime = selectedStats ? formatDuration(selectedStats.uptimeSecs) : "-";
  const selectedDownRate = selectedThroughput ? formatRate(selectedThroughput.downBps) : "-";
  const selectedUpRate = selectedThroughput ? formatRate(selectedThroughput.upBps) : "-";
  const selectedDownTotal = selectedStats ? formatBytes(selectedStats.rxBytes) : "-";
  const selectedUpTotal = selectedStats ? formatBytes(selectedStats.txBytes) : "-";
  const selectedStealthPolicyRaw = normalizeMode(selectedPolicy.stealth);
  const selectedStealthRuntimeRaw = normalizeMode(selectedStats?.stealthMode, "");
  const selectedStealthIsIntelligent =
    selectedStealthPolicyRaw === "auto" || selectedStealthPolicyRaw === "intelligent";
  const selectedStealthLiveRaw = selectedStealthRuntimeRaw || selectedStealthPolicyRaw;
  const selectedStealthDisplayRaw =
    selectedStealthIsIntelligent &&
      (selectedStealthLiveRaw === "auto" || selectedStealthLiveRaw === "intelligent" || !selectedStealthLiveRaw)
      ? "performance"
      : selectedStealthLiveRaw;
  const selectedStealthMode = selectedTunnel ? displayStealthMode(selectedStealthDisplayRaw) : "-";
  const selectedFecRuntimeRaw = normalizeMode(selectedStats?.fecMode, "");
  const selectedFecPolicyRaw = normalizeMode(selectedPolicy.fec);
  const selectedFecIsOff = isFecOff(selectedFecRuntimeRaw) || isFecOff(selectedFecPolicyRaw);
  const selectedFecBadgeLabel = selectedFecIsOff ? "Off" : "Auto";
  const selectedFecActivity = !selectedTunnel
    ? "-"
    : selectedFecIsOff
      ? "-"
      : formatPercent(selectedStats?.fecActivityPercent ?? 0, 1);
  const selectedCanToggle = Boolean(selectedHasQKey);
  const selectedActionDisabled =
    selectedState === "activating" || selectedState === "deactivating" || !selectedCanToggle || Boolean(switchingTunnelId);

  const runAfterRipple = useCallback((action: () => void) => {
    const timerId = window.setTimeout(() => {
      rippleDelayTimersRef.current = rippleDelayTimersRef.current.filter((id) => id !== timerId);
      action();
    }, BUTTON_RIPPLE_VISIBILITY_DELAY_MS);
    rippleDelayTimersRef.current.push(timerId);
  }, []);

  useEffect(() => {
    return () => {
      for (const timerId of rippleDelayTimersRef.current) window.clearTimeout(timerId);
      rippleDelayTimersRef.current = [];
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const parseable = tunnels.filter((t) => t.qkey.trim().length > 0);
    if (!window.__TAURI_INTERNALS__ || parseable.length === 0) {
      setQkeyPolicyById({});
      return;
    }

    (async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const entries = await Promise.all(
          parseable.map(async (tunnel) => {
            try {
              const parsed = await invoke<{
                stealth?: string | null;
                fec?: string | null;
                sni?: string | null;
                extra?: string | null;
              }>("qkey_parse", {
                qkey_data: tunnel.qkey,
              });
              const stealth = normalizeMode(parsed.stealth);
              const fec = normalizeMode(parsed.fec);
              const extraPolicy = parseExtraPolicy(parsed.extra);
              const sniDisplay = resolveDomainFrontingSniDisplay(
                parsed.extra,
                typeof parsed.sni === "string" ? parsed.sni : "",
              );
              const isManual = stealth === "manual" || fec === "manual";
              const customDetails =
                extraPolicy.customDetails.length > 0
                  ? extraPolicy.customDetails
                  : isManual
                    ? ["Custom config [server-managed]"]
                    : [];

              return [
                tunnel.id,
                {
                  stealth,
                  fec,
                  mtu: extraPolicy.mtu,
                  cc: extraPolicy.cc,
                  sniDisplay,
                  customDetails,
                  source: "qkey" as const,
                },
              ] as const;
            } catch {
              return [tunnel.id, DEFAULT_POLICY] as const;
            }
          }),
        );
        if (cancelled) return;
        setQkeyPolicyById(Object.fromEntries(entries));
      } catch {
        if (cancelled) return;
        setQkeyPolicyById({});
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [qkeyFingerprint, tunnels]);

  useEffect(() => {
    const now = Date.now();
    setThroughputById((prev) => {
      const next = { ...prev };
      const samples = { ...throughputSampleRef.current };

      for (const [id, stats] of Object.entries(tunnelStats)) {
        if (!stats) {
          delete next[id];
          delete samples[id];
          continue;
        }
        const previous = samples[id];
        if (previous) {
          const dtMs = now - previous.ts;
          const downBytes = stats.rxBytes - previous.rx;
          const upBytes = stats.txBytes - previous.tx;
          if (dtMs > 0 && downBytes >= 0 && upBytes >= 0) {
            next[id] = {
              downBps: Math.max(0, Math.round((downBytes * 8 * 1000) / dtMs)),
              upBps: Math.max(0, Math.round((upBytes * 8 * 1000) / dtMs)),
            };
          }
        }
        samples[id] = { ts: now, rx: stats.rxBytes, tx: stats.txBytes };
      }

      for (const id of Object.keys(next)) {
        if (!(id in tunnelStats) || !tunnelStats[id]) delete next[id];
      }
      for (const id of Object.keys(samples)) {
        if (!(id in tunnelStats) || !tunnelStats[id]) delete samples[id];
      }

      throughputSampleRef.current = samples;
      return next;
    });
  }, [tunnelStats]);

  function requestDelete(tunnel: TunnelConfig, state: string) {
    if (state === "active" || state === "activating" || state === "deactivating") {
      addToast({ type: "warning", message: "Disconnect tunnel before deleting it" });
      return;
    }
    setPendingDeleteId(tunnel.id);
  }

  function confirmDelete() {
    if (!pendingDelete) return;
    const id = pendingDelete.id;
    setTunnels((prev) => prev.filter((t) => t.id !== id));
    if (selectedId === id) setSelectedId(null);
    setPendingDeleteId(null);
  }

  async function confirmDisconnect() {
    if (!pendingDisconnect) return;
    const tunnel = pendingDisconnect;
    setPendingDisconnectId(null);
    setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "deactivating" }));
    setError(null);
    if (!window.__TAURI_INTERNALS__) {
      setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
      return;
    }
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("engine_disconnect");
      addToast({ type: "success", message: "Disconnected from tunnel" });
    } catch (e: any) {
      setError(String(e ?? "Disconnect failed"));
      addToast({ type: "error", message: "Disconnect failed" });
    } finally {
      setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
    }
  }

  function requestSelectTunnel(tunnel: TunnelConfig) {
    if (switchingTunnelId) return;
    if (hasTransitioningTunnel) {
      addToast({ type: "warning", message: "Please wait until tunnel transition finishes" });
      return;
    }
    if (activeTunnelId && activeTunnelId !== tunnel.id) {
      setPendingSwitchTargetId(tunnel.id);
      return;
    }
    setSelectedId(tunnel.id);
  }

  async function confirmSwitchTunnel() {
    if (!pendingSwitchTarget) return;
    const target = pendingSwitchTarget;
    setPendingSwitchTargetId(null);

    const sourceId = activeTunnelId;
    if (!sourceId || sourceId === target.id) {
      setSelectedId(target.id);
      return;
    }

    const qkey = target.qkey.trim();
    if (!qkey) {
      addToast({ type: "warning", message: "QKey missing on target tunnel. Use top Import QKey." });
      return;
    }

    setSwitchingTunnelId(target.id);
    setSelectedId(target.id);
    setError(null);
    setTunnelStates((prev) => ({ ...prev, [sourceId]: "deactivating", [target.id]: "activating" }));

    if (!window.__TAURI_INTERNALS__) {
      setTunnelStates((prev) => ({ ...prev, [sourceId]: "inactive", [target.id]: "inactive" }));
      setError("Tunnel switch requires the desktop app runtime");
      addToast({ type: "error", message: "Tunnel switch requires the desktop app runtime" });
      setSwitchingTunnelId(null);
      return;
    }

    let disconnected = false;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("engine_disconnect");
      disconnected = true;

      const sniOverride = (target.debugSniOverride ?? "").trim();
      await invoke("engine_connect", {
        tunnel_id: target.id,
        qkey_data: qkey,
        sni_override: sniOverride.length > 0 ? sniOverride : null,
        settings,
      });

      setTunnelStates((prev) => {
        const next: Record<string, "inactive" | "activating" | "active" | "deactivating"> = {};
        for (const key of Object.keys(prev)) next[key] = "inactive";
        next[target.id] = "active";
        return next;
      });
      addToast({ type: "success", message: `Switched connection to "${target.name}"` });
    } catch (e: any) {
      setError(String(e ?? "Tunnel switch failed"));
      if (!disconnected) {
        setTunnelStates((prev) => ({ ...prev, [sourceId]: "active", [target.id]: "inactive" }));
      } else {
        setTunnelStates((prev) => ({ ...prev, [sourceId]: "inactive", [target.id]: "inactive" }));
      }
      addToast({ type: "error", message: String(e ?? "Tunnel switch failed") });
    } finally {
      setSwitchingTunnelId(null);
    }
  }

  async function handleToggleConnection(tunnel: TunnelConfig, state: string) {
    if (state === "activating" || state === "deactivating") return;

    if (state === "active") {
      setPendingDisconnectId(tunnel.id);
      return;
    }

    const qkey = tunnel.qkey.trim();
    if (!qkey) {
      setSelectedId(tunnel.id);
      addToast({ type: "warning", message: "QKey missing. Use top Import QKey." });
      return;
    }

    setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "activating" }));
    setError(null);
    if (!window.__TAURI_INTERNALS__) {
      setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
      setError("Connect requires the desktop app runtime");
      addToast({ type: "error", message: "Connect requires the desktop app runtime" });
      return;
    }
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const sniOverride = (tunnel.debugSniOverride ?? "").trim();
      await invoke("engine_connect", {
        tunnel_id: tunnel.id,
        qkey_data: qkey,
        sni_override: sniOverride.length > 0 ? sniOverride : null,
        settings,
      });
      setTunnelStates((prev) => {
        const next: Record<string, "inactive" | "activating" | "active" | "deactivating"> = {};
        for (const key of Object.keys(prev)) next[key] = "inactive";
        next[tunnel.id] = "active";
        return next;
      });
      setSelectedId(tunnel.id);
      addToast({ type: "success", message: "Connected to tunnel" });
    } catch (e: any) {
      setTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
      setError(String(e ?? "Connect failed"));
      addToast({ type: "error", message: String(e ?? "Connect failed") });
    }
  }

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <CreateTunnelDialog open={createOpen} onOpenChange={setCreateOpen} />
      <ImportQKeyDialog open={importOpen} onOpenChange={setImportOpen} />
      {configTunnelId && tunnels.find(t => t.id === configTunnelId) && (
        <TunnelConfigDialog
          open={Boolean(configTunnelId)}
          onOpenChange={(open) => { if (!open) setConfigTunnelId(null); }}
          tunnel={tunnels.find(t => t.id === configTunnelId)!}
        />
      )}
      <ConfirmDialog
        open={Boolean(pendingDelete)}
        title="Delete Tunnel"
        message={
          pendingDelete
            ? `Delete tunnel "${pendingDelete.name}" permanently?`
            : "Delete tunnel permanently?"
        }
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={confirmDelete}
        onCancel={() => setPendingDeleteId(null)}
      />
      <ConfirmDialog
        open={Boolean(pendingDisconnect)}
        title="Disconnect Tunnel"
        message={
          pendingDisconnect
            ? `Disconnect "${pendingDisconnect.name}" now?`
            : "Disconnect selected tunnel now?"
        }
        confirmLabel="Disconnect"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={() => { void confirmDisconnect(); }}
        onCancel={() => setPendingDisconnectId(null)}
      />
      <ConfirmDialog
        open={Boolean(pendingSwitchTarget)}
        title="Switch Tunnel Connection"
        message={
          pendingSwitchTarget && activeTunnel
            ? `Switch from "${activeTunnel.name}" to "${pendingSwitchTarget.name}"? Current connection will disconnect and reconnect to the selected tunnel.`
            : "Switch to selected tunnel now?"
        }
        confirmLabel="Switch"
        cancelLabel="Cancel"
        variant="default"
        loading={Boolean(switchingTunnelId)}
        onConfirm={() => { void confirmSwitchTunnel(); }}
        onCancel={() => {
          if (!switchingTunnelId) setPendingSwitchTargetId(null);
        }}
      />

      {/* Toolbar */}
      <div className="px-5 pt-6 pb-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-lg font-bold text-black dashboard-heading-sans tracking-tight">
            Tunnels
          </span>
          <span
            className="text-[10px] font-semibold text-black/75 tabular-nums inline-flex items-center rounded-md border px-2 py-[1px] leading-none"
            style={SIDEBAR_PILL_STYLE}
          >
            {displayTunnels.length}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            type="button"
            onClick={() => runAfterRipple(() => setCreateOpen(true))}
            className="inline-flex items-center rounded-lg px-3 h-[30px] border text-[11px] font-semibold transition-all action-save-btn h-auto min-w-0"
            size="sm"
          >
            Create
          </Button>
          <Button
            type="button"
            onClick={() => runAfterRipple(() => setImportOpen(true))}
            className="relative isolate overflow-hidden inline-flex items-center justify-center rounded-lg px-3 h-[30px] border text-[11px] font-semibold transition-all action-copy-btn h-auto min-w-0"
            size="sm"
          >
            Import QKey
          </Button>
        </div>
      </div>

      <div className="flex-1 min-h-0 px-5 pb-[13px] flex flex-col gap-3">
        <div className="flex-1 min-h-0 overflow-y-auto overflow-x-hidden pr-1">
          {displayTunnels.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center gap-1 px-4">
              <span className="text-[32px] font-light text-text-ghost/30 leading-none tabular-nums">
                0
              </span>
              <span className="text-[11px] font-semibold text-text-ghost dashboard-heading-sans">
                Tunnels
              </span>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-3 auto-rows-[1fr]">
              <AnimatePresence initial={false}>
                {displayTunnels.map((tunnel, i) => {
                  const isSelected = selectedCardId === tunnel.id && selectedTunnel?.id === tunnel.id;
                  const state = tunnelStates[tunnel.id] ?? "inactive";
                  const flag = countryCodeToFlag(tunnel.countryCode);
                  const policy = qkeyPolicyById[tunnel.id] ?? DEFAULT_POLICY;
                  const policySummary = `${displayStealthMode(policy.stealth)}${policyValueSeparator}${displayFecMode(policy.fec)}${policyValueSeparator}${displayCcMode(policy.cc)}${policyValueSeparator}${displayMtu(policy.mtu)}`;

                  return (
                    <motion.div
                      key={tunnel.id}
                      layout
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, x: -16 }}
                      transition={{
                        layout: { type: "spring", stiffness: 240, damping: 30, mass: 0.95 },
                        duration: 0.18,
                        delay: i * 0.02,
                      }}
                      onClick={() => {
                        requestSelectTunnel(tunnel);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          requestSelectTunnel(tunnel);
                        }
                      }}
                      role="button"
                      tabIndex={0}
                      aria-current={isSelected ? "true" : undefined}
                      className="relative h-full cursor-pointer text-left group tunnel-card-shell"
                    >
                      <div
                        className={cn(
                          "relative z-10 flex h-full w-full flex-col overflow-hidden rounded-[12px] tunnel-card-surface",
                          "glass-pane-pill border px-3 py-3 transition-[border-color,background,box-shadow] duration-200",
                          "border-[rgba(240,238,246,0.98)] bg-[rgba(255,255,255,0.8)] shadow-[0_6px_14px_rgba(25,30,48,0.08),0_1px_2px_rgba(0,0,0,0.04)]",
                        )}
                      >
                        <div className="pointer-events-none absolute right-3 top-2 z-30 inline-flex h-[24px] w-[24px] items-center justify-center">
                          <span className="relative inline-flex h-[24px] w-[24px] shrink-0 pointer-events-none items-center justify-center">
                            <AnimatePresence initial={false}>
                              {isSelected && (
                                <motion.span
                                  key={`${tunnel.id}-pin`}
                                  className="absolute inset-0 flex items-center justify-center"
                                  initial={{ opacity: 0, scale: 0.32, y: -0.6 }}
                                  animate={{ opacity: [0, 1, 1], scale: [0.32, 1.14, 1], y: [-0.6, 0.15, 0] }}
                                  exit={{ opacity: [1, 0], scale: [1, 0.34], y: [0, -0.4] }}
                                  transition={{ duration: 0.34, ease: [0.2, 0.8, 0.2, 1], times: [0, 0.68, 1] }}
                                >
                                  <motion.span
                                    className="absolute h-[18px] w-[18px] rounded-[7px] bg-[rgba(95,103,246,0.22)] blur-[1px]"
                                    initial={{ opacity: 0, scale: 0.5 }}
                                    animate={{ opacity: [0, 0.46, 0.22], scale: [0.5, 1.2, 1] }}
                                    exit={{ opacity: 0, scale: 0.5 }}
                                    transition={{ duration: 0.34, ease: [0.2, 0.8, 0.2, 1], times: [0, 0.62, 1] }}
                                  />
                                  <motion.span
                                    className="h-[14px] w-[14px] rounded-[4px] bg-[#5f67f6] shadow-[0_1px_2px_rgba(67,56,202,0.26)]"
                                    initial={{ opacity: 0, scale: 0.16 }}
                                    animate={{ opacity: [0, 1, 1], scale: [0.16, 1.2, 1] }}
                                    exit={{ opacity: [1, 0], scale: [1, 0.2] }}
                                    transition={{ duration: 0.34, ease: [0.2, 0.8, 0.2, 1], times: [0, 0.7, 1] }}
                                  />
                                </motion.span>
                              )}
                            </AnimatePresence>
                           </span>
                        </div>
                        <div className="min-w-0 w-full flex h-full flex-col justify-between">
                          <div className="flex items-start justify-between gap-2">
                            <div className="min-w-0 pr-6">
                              <div className="text-[12px] font-semibold text-black dashboard-heading-sans truncate pl-1">
                                {tunnel.name}
                              </div>
                              <div className="mt-1 flex items-center gap-1.5 min-w-0">
                                <span
                                  className={cn(WHITE_PILL_CLASS, "shrink-0 gap-1")}
                                  style={WHITE_PILL_BACKDROP_STYLE}
                                >
                                  <span className="text-[10px] leading-none">{flag || "🌐"}</span>
                                  <span className="text-[8px] font-semibold tracking-[0.08em] dashboard-heading-sans text-black/75">
                                    {tunnel.countryCode ?? "XX"}
                                  </span>
                                </span>
                                <span className="min-w-0 truncate text-[10px] text-black/68">{tunnel.remote}</span>
                              </div>
                            </div>
                            <Button
                              type="button"
                              onClick={() => runAfterRipple(() => requestDelete(tunnel, state))}
                              aria-label="Remove tunnel"
                              title="Remove tunnel"
                              className="action-settings-icon-btn h-[22px] w-[22px] rounded-md inline-grid place-items-center opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0 min-w-0 p-0"
                              size="sm"
                              isIconOnly
                            >
                              <Trash2 className="h-3 w-3 text-text-ghost/80 pointer-events-none" />
                            </Button>
                          </div>
                          <div className="flex items-end justify-between gap-2 pt-1">
                          <div className="pb-0.5 flex items-center gap-1.5 min-w-0 flex-wrap">
                              <span
                                className={cn(
                                  WHITE_PILL_CLASS,
                                  "max-w-[220px] text-[9px] font-medium text-black/66",
                                )}
                                style={WHITE_PILL_BACKDROP_STYLE}
                              >
                                <span className="truncate">{policySummary}</span>
                              </span>
                            </div>
                            <Button
                              type="button"
                              onPointerDown={(e) => {
                                e.stopPropagation();
                              }}
                              onClick={(e) => {
                                e.stopPropagation();
                                e.preventDefault();
                                runAfterRipple(() => setConfigTunnelId(tunnel.id));
                              }}
                              aria-label="Open configuration"
                              title="Configuration"
                              variant="ghost"
                              isIconOnly
                              size="icon-sm"
                              className="action-settings-icon-btn relative z-40 shrink-0 inline-flex h-[24px] w-[24px] items-center justify-center rounded-[7px] cursor-pointer !min-w-0 !px-0 !py-0"
                            >
                              <SlidersHorizontal className="h-[10px] w-[10px] text-black" strokeWidth={2} />
                            </Button>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          )}
        </div>

        <section className="relative z-10 flex-none shrink-0 basis-[272px] h-[272px] max-h-[272px] min-h-[272px] overflow-hidden rounded-[14px] border border-[rgba(255,255,255,0.86)] glass-pane-pill px-3.5 py-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_10px_24px_rgba(34,38,62,0.11),0_2px_6px_rgba(0,0,0,0.05)]">
          <div className="flex h-full flex-col gap-2.5 overflow-hidden">
              <div className="shrink-0 flex items-center justify-between gap-2 pb-2 border-b border-black/7 min-w-0">
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className={cn(WHITE_PILL_CLASS, "shrink-0 gap-1")}
                    style={WHITE_PILL_BACKDROP_STYLE}
                  >
                    <span className="text-[10px] leading-none">{selectedFlag || "🌐"}</span>
                    {selectedTunnel ? (
                      <span className="text-[8px] font-semibold tracking-[0.08em] dashboard-heading-sans text-black/75">
                        {selectedTunnel.countryCode ?? "XX"}
                      </span>
                    ) : null}
                  </span>
                  {selectedTunnel ? (
                    <span className="text-[11px] font-semibold text-black truncate max-w-[220px] pl-1">
                      {selectedTunnel.name}
                    </span>
                  ) : null}
                </div>
                {selectedState !== "inactive" && (
                  <span className={cn("shrink-0 text-[10px] font-semibold", selectedStatus.textClass)}>
                    {selectedStatus.label}
                  </span>
                )}
              </div>

              <div className="grid flex-1 min-h-0 grid-cols-[minmax(240px,0.7fr)_minmax(0,1.3fr)] items-stretch gap-2.5 pb-1">
                <div className="min-w-0 min-h-0 flex h-full flex-col">
                  {selectedTunnel ? (
                    <div className="shrink-0 pt-1">
                      <div className="w-full">
                        <span
                          className={cn(WHITE_PILL_CLASS, "max-w-full !px-2.5 !py-[3px]")}
                          style={WHITE_PILL_BACKDROP_STYLE}
                        >
                          <span className="max-w-full truncate text-[10px] font-semibold text-black/82 tabular-nums">
                            {formatRemoteAddress(selectedTunnel.remote)}
                          </span>
                        </span>
                      </div>
                    </div>
                  ) : null}
                  <div className="mt-auto">
                    {selectedTunnel ? (
                      <div className="flex flex-col gap-[6px]">
                        <div className="w-full">
                          <span
                            title={selectedSniDisplay}
                            className={cn(WHITE_PILL_CLASS, "max-w-full !px-3 !py-[3px]")}
                            style={WHITE_PILL_BACKDROP_STYLE}
                          >
                            <span className="text-[8px] font-bold text-black/58 mr-1">SNI</span>
                            <span className="max-w-full truncate text-[10px] font-normal text-black/74">
                              {selectedSniDisplay}
                            </span>
                          </span>
                        </div>
                        <div className="w-full">
                          <span
                            className={cn(
                              WHITE_PILL_CLASS,
                              "min-w-0 overflow-hidden text-[10px] font-medium text-black/68 !px-3 !py-[3px]",
                            )}
                            style={WHITE_PILL_BACKDROP_STYLE}
                          >
                            <span className="truncate">
                              {displayStealthMode(selectedPolicy.stealth)}{policyValueSeparator}
                              {displayFecMode(selectedPolicy.fec)}{policyValueSeparator}
                              {displayCcMode(selectedPolicy.cc)}{policyValueSeparator}
                              {displayMtu(selectedPolicy.mtu)}
                            </span>
                          </span>
                        </div>
                      </div>
                    ) : null}
                    <div className="mt-[10px]">
                      <ConnectButton
                        state={selectedState === "active" ? "connected" : selectedState === "activating" ? "connecting" : selectedState === "deactivating" ? "disconnecting" : "idle"}
                        onClick={() => {
                          if (!selectedTunnel) return;
                          void handleToggleConnection(selectedTunnel, selectedState);
                        }}
                        disabled={selectedActionDisabled}
                        hasQKey={selectedHasQKey}
                        className="w-full"
                        buttonClassName="w-full min-w-[176px]"
                      />
                    </div>
                    <div className="mt-[10px] grid grid-cols-2 gap-2 shrink-0">
                      <SessionMetric
                        label="Stealth Mode"
                        value={selectedStealthMode}
                        badge={selectedTunnel && selectedStealthIsIntelligent ? <IntelligentModeBadge /> : undefined}
                      />
                      <SessionMetric
                        label="FEC"
                        value={selectedFecActivity}
                        badge={selectedTunnel ? <ModeCornerBadge label={selectedFecBadgeLabel} /> : undefined}
                      />
                    </div>
                  </div>
                </div>
                <ConnectionVisualizer
                  key={selectedTunnel?.id ?? "__no_tunnel__"}
                  state={selectedState}
                  downBps={selectedThroughput?.downBps ?? 0}
                  upBps={selectedThroughput?.upBps ?? 0}
                  latencyLabel={selectedLatency}
                  downRate={selectedDownRate}
                  upRate={selectedUpRate}
                  downTotal={selectedDownTotal}
                  upTotal={selectedUpTotal}
                  uptime={selectedUptime}
                  className="min-w-0 h-full"
                />
              </div>
          </div>
        </section>
      </div>
    </div>
  );
}
