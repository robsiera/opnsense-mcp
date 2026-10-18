export type HttpMethod = "GET" | "POST";

export interface ApiRequest {
  module: string;
  controller: string;
  command: string;
  parameters?: string[];
  query?: Record<string, string | number | boolean>;
  body?: unknown;
  method?: HttpMethod;
}

export type RiskLevel = "read" | "write" | "activate" | "disruptive" | "catastrophic" | "unknown";

export interface RiskAssessment {
  level: RiskLevel;
  reason: string;
}

export interface ApiResponse {
  status: number;
  contentType: string;
  data: unknown;
}

export type WriteMode = "disabled" | "plan" | "enabled";

/** Connection settings for one OPNsense firewall. Credentials never leave this process. */
export interface OpnsenseTarget {
  name: string;
  baseUrl: URL;
  apiKey: string;
  apiSecret: string;
  writeMode: WriteMode;
  tlsVerify: boolean;
  ca?: string;
  timeoutMs: number;
  maxResponseBytes: number;
}
