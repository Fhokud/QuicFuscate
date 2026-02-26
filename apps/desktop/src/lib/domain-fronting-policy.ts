export function resolveDomainFrontingSniDisplay(
  extra: string | null | undefined,
  fallbackSni: string,
): string {
  const fallback = fallbackSni.trim() || "QKey Policy";
  const raw = (extra ?? "").trim();
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return fallback;
    const mode = typeof parsed.df_sni_mode === "string" ? parsed.df_sni_mode.trim().toLowerCase() : "";
    if (mode === "auto_rotating") return "Auto [Rotating]";
    if (mode === "fixed") {
      const fixed = typeof parsed.df_sni_domain === "string" ? parsed.df_sni_domain.trim() : "";
      return fixed || fallback;
    }
    return fallback;
  } catch {
    return fallback;
  }
}
