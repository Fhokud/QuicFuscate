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
