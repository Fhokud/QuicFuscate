import { cn } from "@/lib/cn";

interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
  fillColor?: string;
  className?: string;
}

export function Sparkline({
  data,
  width = 120,
  height = 32,
  color = "var(--color-accent)",
  fillColor = "var(--color-accent-dim)",
  className,
}: SparklineProps) {
  if (data.length < 2) {
    return (
      <div 
        className={cn("bg-surface-2 rounded", className)} 
        style={{ width, height }} 
      />
    );
  }

  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  
  const padding = 2;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;
  
  const points = data.map((value, index) => {
    const x = padding + (index / (data.length - 1)) * chartWidth;
    const y = padding + chartHeight - ((value - min) / range) * chartHeight;
    return `${x},${y}`;
  });
  
  const pathD = `M ${points.join(" L ")}`;
  const areaD = `${pathD} L ${width - padding},${height - padding} L ${padding},${height - padding} Z`;

  return (
    <svg
      width={width}
      height={height}
      className={cn("overflow-visible", className)}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
    >
      <defs>
        <linearGradient id="sparkline-gradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={fillColor} stopOpacity="0.45" />
          <stop offset="100%" stopColor={fillColor} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path
        d={areaD}
        fill="url(#sparkline-gradient)"
      />
      <path
        d={pathD}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

interface MetricCardProps {
  label: string;
  value: string;
  sparklineData?: number[];
  trend?: "up" | "down" | "stable";
  color?: string;
}

export function MetricCard({ 
  label, 
  value, 
  sparklineData, 
  trend,
  color 
}: MetricCardProps) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[10px] tracking-wider text-text-ghost">{label}</span>
      <div className="flex items-end justify-between">
        <span 
          className="text-[16px] font-semibold" 
          style={{ color: color || "inherit" }}
        >
          {value}
        </span>
        {sparklineData && sparklineData.length > 0 && (
          <Sparkline 
            data={sparklineData} 
            width={60} 
            height={20}
            color={color || "var(--color-accent)"}
          />
        )}
      </div>
      {trend && (
        <span className={cn(
          "text-[10px]",
          trend === "up" && "text-positive",
          trend === "down" && "text-negative",
          trend === "stable" && "text-text-tertiary"
        )}>
          {trend === "up" && "↑"}
          {trend === "down" && "↓"}
          {trend === "stable" && "→"}
        </span>
      )}
    </div>
  );
}
