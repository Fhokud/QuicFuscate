function normalize(raw: string | null | undefined): string {
  return (raw ?? "").trim().toLowerCase();
}

export function displayStealthMode(raw: string | null | undefined): string {
  const v = normalize(raw);
  if (!v) return "Auto";
  if (v === "off") return "Off";
  if (v === "manual") return "Manual";
  if (v === "performance" || v === "base") return "Performance";
  if (v === "stealth") return "Stealth";
  if (v === "anti-dpi" || v === "antidpi" || v === "max" || v === "stealthmax" || v === "stealth-max") {
    return "AntiDPI";
  }
  if (v === "auto" || v === "intelligent") return "Auto";
  return "Auto";
}

export function displayFecMode(raw: string | null | undefined): string {
  const v = normalize(raw);
  if (v === "off" || v === "zero") return "Off";
  return "On";
}

export function displayCcMode(raw: string | null | undefined): string {
  const v = normalize(raw);
  if (!v || v === "server") return "Server";
  if (v === "reno") return "RENO";
  if (v === "cubic") return "CUBIC";
  if (v === "bbr") return "BBR";
  if (v === "bbr2") return "BBR2";
  if (v === "bbr2 gc" || v === "bbr2_gc" || v === "bbr2-gc" || v === "bbr2_gcongestion" || v === "bbr2gcongestion") {
    return "BBR2 GC";
  }
  return "Custom";
}

export function displayMtu(raw: string | null | undefined): string {
  const v = (raw ?? "").trim();
  if (!v || v.toLowerCase() === "server") return "Server";
  if (/^\d+$/.test(v)) return v;
  return "Server";
}
