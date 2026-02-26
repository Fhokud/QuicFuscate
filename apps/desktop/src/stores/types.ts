/** Per-tunnel activation state */
export type TunnelState = "inactive" | "activating" | "active" | "deactivating";

/**
 * Tunnel configuration - imported via QKey or manual entry.
 *
 * Desktop App is a client. Server-side behavior is configured in the web-admin
 * and baked into QKeys where applicable.
 */
export interface TunnelConfig {
  id: string;
  name: string;

  /** Remote server address (host:port) */
  remote: string;
  /** TLS SNI host */
  sni: string;
  /** Optional desktop-only debug override for TLS SNI (default off). */
  debugSniOverride?: string;

  /** Metadata */
  countryCode?: string;
  location?: string;
  createdAt: number;
  hasToken: boolean;

  /** Canonical credential */
  qkey: string;
}

/** Live tunnel statistics (while active) */
export interface TunnelStats {
  latencyMs: number;
  lossPercent: number;
  rxBytes: number;
  txBytes: number;
  rxPackets: number;
  txPackets: number;
  uptimeSecs: number;
  fecMode: string;
  stealthMode: string;
  fecActivityPercent: number;
  fecRecoveredPackets: number;
  currentSni?: string;
}

/** Client-level application settings */
export interface AppSettings {
  general: GeneralSettings;
  hardware: HardwareSettings;
}

export interface GeneralSettings {
  /**
   * Rust `RUST_LOG` style levels understood by the engine logger.
   * We keep this simple client-side; server/admin decides file logging etc.
   */
  logLevel: "error" | "warn" | "info" | "debug" | "trace";
  /**
   * Try to connect the selected tunnel on app startup.
   */
  autoConnectOnLaunch: boolean;
  /**
   * User preference for OS start-at-login integration.
   * This flag is synchronized with OS autostart registration.
   */
  startAtLogin: boolean;
  /**
   * Updater transport is prepared but remains disabled until signed binaries exist.
   */
  updaterEnabled: boolean;
  updaterChannel: "stable" | "beta";
}

export interface HardwareSettings {
  detectedFeatures: string[];
}

/** Log entry from engine */
export interface LogEntry {
  timestamp: number;
  level: "trace" | "debug" | "info" | "warn" | "error";
  message: string;
  target?: string;
}

/** Navigation tabs */
export type NavTab = "tunnels" | "settings" | "logs" | "about";
