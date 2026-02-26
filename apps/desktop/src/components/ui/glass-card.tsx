import LiquidGlass from "liquid-glass-react";
import type { ReactNode, CSSProperties } from "react";

interface GlassCardProps {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
  cornerRadius?: number;
  padding?: string;
}

export function GlassCard({
  children,
  className = "",
  style,
  cornerRadius = 14,
  padding = "0px",
}: GlassCardProps) {
  return (
    <LiquidGlass
      cornerRadius={cornerRadius}
      padding={padding}
      displacementScale={40}
      blurAmount={0.04}
      saturation={120}
      aberrationIntensity={1}
      elasticity={0.12}
      overLight={false}
      className={className}
      style={style}
    >
      {children}
    </LiquidGlass>
  );
}

export function GlassPanel({
  children,
  className = "",
  style,
}: {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <LiquidGlass
      cornerRadius={0}
      padding="0px"
      displacementScale={30}
      blurAmount={0.03}
      saturation={110}
      aberrationIntensity={0.5}
      elasticity={0.08}
      overLight={false}
      className={className}
      style={style}
    >
      {children}
    </LiquidGlass>
  );
}
