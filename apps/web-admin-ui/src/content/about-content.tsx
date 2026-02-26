import { motion } from "framer-motion";
import appLogo from "../../../../assets/logo/QuicFuscate_clean.png";

type SpecLine = { key: string; value: string };

export const ABOUT_PAGE_CONTENT = {
  title: "QuicFuscate",
  tagline: "Open-source obfuscated QUIC tunnel",
  specs: [
    { key: "Engine", value: "Rust + Tokio" },
    { key: "Protocol", value: "Custom QUIC v1 [RFC 9000]" },
    { key: "Cipher", value: "AEGIS-128" },
    { key: "FEC", value: "Reed-Solomon | Fountain" },
    { key: "Stealth", value: "Real TLS | Adaptive Stealth Stack" },
    { key: "UI", value: "React | Tauri [App]" },
  ] as const satisfies readonly SpecLine[],
  footer: ["Censorship-resistant VPN tunneling", "over obfuscated QUIC transport"],
  defaultVersion: "v0.1.0",
  defaultVersionLoading: "Loading...",
  defaultVersionUnavailable: "Unknown",
} as const;

type AboutSharedProps = {
  version: string;
  cpuFeatures?: string[];
  error?: string | null;
};

export function AboutPageLayout({ version, cpuFeatures, error }: AboutSharedProps) {
  return (
    <div className="flex flex-col items-center justify-center flex-1 h-full px-6">
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="flex flex-col items-center gap-6 w-full max-w-[340px]"
      >
        <AboutPageContent version={version} cpuFeatures={cpuFeatures} error={error} />
      </motion.div>
    </div>
  );
}

export function AboutPageContent({ version, cpuFeatures, error }: AboutSharedProps) {
  const showCpuFeatures = cpuFeatures && cpuFeatures.length > 0;

  return (
    <section className="w-full rounded-2xl glass border border-edge/70 px-5 py-5 dashboard-heading-sans">
      <div className="flex flex-col items-center gap-2">
        <div className="flex flex-col items-center gap-1">
          <img
            src={appLogo}
            alt="QuicFuscate logo"
            className="h-[82px] w-[82px] object-contain select-none"
            draggable={false}
          />
          <h1 className="text-[18px] font-semibold text-text-primary tracking-tight">
            {ABOUT_PAGE_CONTENT.title}
          </h1>
        </div>
        <p className="text-[11px] text-text-tertiary text-center leading-relaxed">
          {ABOUT_PAGE_CONTENT.tagline}
        </p>
      </div>

      <div className="flex items-center justify-center gap-2 mt-3">
        <span className="px-2 py-0.5 rounded glass-subtle text-[10px] text-text-secondary">
          {version}
        </span>
        <span className="px-2 py-0.5 rounded bg-accent-muted border border-edge-accent text-[10px] text-accent">
          OSS
        </span>
      </div>

      <div className="w-full h-px bg-edge mt-4" />

      <div className="mt-3 space-y-0">
        {error ? (
          <p className="text-[11px] text-text-tertiary text-center">{error}</p>
        ) : (
          ABOUT_PAGE_CONTENT.specs.map(({ key, value }, index: number) => (
            <motion.div
              key={key}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.2, delay: 0.15 + index * 0.04 }}
              className="flex items-center justify-between py-1.5 gap-4"
            >
              <span className="text-[11px] text-text-ghost">{key}</span>
              <span className="text-[11px] text-text-tertiary">{value}</span>
            </motion.div>
          ))
        )}
      </div>

      {showCpuFeatures ? (
        <>
          <div className="w-full h-px bg-edge mt-4" />
          <div className="w-full mt-3">
            <p className="text-[10px] font-medium tracking-widest text-text-ghost mb-2">
              CPU Features
            </p>
            <div className="flex flex-wrap gap-1">
              {cpuFeatures.map((feature: string) => (
                <span
                  key={feature}
                  className="px-1.5 py-0.5 rounded glass-subtle text-[9px] text-text-tertiary"
                >
                  {feature}
                </span>
              ))}
            </div>
          </div>
        </>
      ) : null}

      <div className="w-full h-px bg-edge mt-4" />

      <p className="text-[10px] text-text-ghost/60 text-center leading-relaxed mt-3">
        {ABOUT_PAGE_CONTENT.footer[0]}
        <br />
        {ABOUT_PAGE_CONTENT.footer[1]}
      </p>
    </section>
  );
}
