export type NavTab = "dashboard" | "configuration" | "logs" | "about";

export interface AdminResponse<T> {
  success: boolean;
  message?: string | null;
  data?: T | null;
}

export type MetricsMap = Record<string, number>;

export interface StatusData {
  version: string;
  uptime_secs: number;
  clients_active: number;
  clients_total?: number;
  bytes_in: number;
  bytes_out: number;
  listen: string;
  config_writable?: boolean | null;
}

export interface ClientInfo {
  id: string;
  ip: string;
  bytes_in: number;
  bytes_out: number;
  connected_secs?: number | null;
  stealth_mode?: string | null;
}

export interface QKeyEntry {
  id: string;
  name?: string | null;
  qkey?: string | null;
  created_at: number;
  expires_at?: number | null;
  stealth?: string | null;
  fec?: string | null;
}

export interface LogEntry {
  ts: number;
  level: string;
  msg: string;
}

export type LogMode = "verbose" | "normal" | "minimal" | "no-log";

export type PendingIpAction = "block" | "unblock";

export type StealthPresetUi = "auto" | "performance" | "stealth" | "antidpi" | "manual" | "off";

export type CcSelection = "reno" | "bbr2" | "bbr3" | "__custom__";

export interface StealthManualSettings {
  enable_domain_fronting: boolean;
  enable_http3_masquerading: boolean;
  use_tls_cover: boolean;
  use_qpack_headers: boolean;
  enable_traffic_padding: boolean;
  enable_timing_obfuscation: boolean;
  enable_protocol_mimicry: boolean;
  enable_doh: boolean;
}

export interface ConfirmDialogRequest {
  title: string;
  message: string;
  confirmLabel: string;
  cancelLabel: string;
}
