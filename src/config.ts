import { readFileSync } from "node:fs";
import { z } from "zod";
import type { OpnsenseTarget, WriteMode } from "./types.js";

const booleanString = z
  .enum(["true", "false"])
  .default("false")
  .transform((value) => value === "true");

const optionalBooleanString = z
  .enum(["true", "false"])
  .optional()
  .transform((value) => value === "true");

const instanceName = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/, "Instance names must be alphanumeric with optional _ or -");

function csv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

const envSchema = z.object({
  OPNSENSE_URL: z.string().url().optional(),
  OPNSENSE_API_KEY: z.string().min(1).optional(),
  OPNSENSE_API_SECRET: z.string().min(1).optional(),
  OPNSENSE_INSTANCE_NAME: instanceName.optional(),
  OPNSENSE_DEFAULT_INSTANCE: instanceName.optional(),
  OPNSENSE_CONFIG_PATH: z.string().min(1).optional(),
  OPNSENSE_WRITE_MODE: z.enum(["disabled", "plan", "enabled"]).default("disabled"),
  OPNSENSE_TLS_VERIFY: z
    .enum(["true", "false"])
    .default("true")
    .transform((value) => value === "true"),
  OPNSENSE_ALLOW_HTTP: booleanString,
  OPNSENSE_CA_FILE: z.string().min(1).optional(),
  OPNSENSE_TIMEOUT_MS: z.coerce.number().int().positive().max(300_000).default(30_000),
  OPNSENSE_MAX_RESPONSE_BYTES: z.coerce.number().int().positive().max(50 * 1024 * 1024).default(2 * 1024 * 1024),
  MCP_TRANSPORT: z.enum(["http", "stdio"]).default("http"),
  MCP_HOST: z.string().min(1).default("127.0.0.1"),
  MCP_PORT: z.coerce.number().int().min(0).max(65_535).default(3000),
  MCP_PATH: z.string().regex(/^\/[A-Za-z0-9/_-]*[A-Za-z0-9_-]$/).default("/mcp"),
  MCP_AUTH_TOKEN: z.string().min(32).optional(),
  MCP_ALLOW_UNAUTHENTICATED: optionalBooleanString,
  MCP_ALLOWED_HOSTS: z.string().optional(),
  MCP_ALLOWED_ORIGINS: z.string().optional(),
  MCP_MAX_SESSIONS: z.coerce.number().int().min(1).max(10_000).default(100),
  MCP_SESSION_TTL_MS: z.coerce.number().int().min(60_000).max(86_400_000).default(3_600_000),
  MCP_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).max(100_000).default(120),
});

const fileInstanceSchema = z.object({
  name: instanceName,
  url: z.string().url(),
  api_key: z.string().min(1),
  api_secret: z.string().min(1),
  write_mode: z.enum(["disabled", "plan", "enabled"]).optional(),
  tls_verify: z.boolean().optional(),
  allow_http: z.boolean().optional(),
  ca_file: z.string().min(1).optional(),
  timeout_ms: z.number().int().positive().max(300_000).optional(),
  max_response_bytes: z.number().int().positive().max(50 * 1024 * 1024).optional(),
});

const fileConfigSchema = z.object({
  default: instanceName.optional(),
  instances: z.array(fileInstanceSchema).min(1),
});

export type Config = {
  instances: OpnsenseTarget[];
  defaultInstance: string;
  transport: "http" | "stdio";
  http: {
    host: string;
    port: number;
    path: string;
    authToken: string | undefined;
    allowUnauthenticated: boolean | undefined;
    allowedHosts: string[];
    allowedOrigins: string[];
    maxSessions: number;
    sessionTtlMs: number;
    rateLimitPerMinute: number;
  };
};

function buildTarget(input: {
  name: string;
  url: string;
  apiKey: string;
  apiSecret: string;
  writeMode: WriteMode;
  tlsVerify: boolean;
  allowHttp: boolean;
  caFile?: string;
  timeoutMs: number;
  maxResponseBytes: number;
}): OpnsenseTarget {
  const baseUrl = new URL(input.url);
  if (baseUrl.protocol !== "https:" && !input.allowHttp) {
    throw new Error(`Instance "${input.name}": URL must use HTTPS unless allow_http/OPNSENSE_ALLOW_HTTP=true`);
  }
  baseUrl.pathname = baseUrl.pathname.replace(/\/$/, "");
  return {
    name: input.name,
    baseUrl,
    apiKey: input.apiKey,
    apiSecret: input.apiSecret,
    writeMode: input.writeMode,
    tlsVerify: input.tlsVerify,
    ...(input.caFile ? { ca: readFileSync(input.caFile, "utf8") } : {}),
    timeoutMs: input.timeoutMs,
    maxResponseBytes: input.maxResponseBytes,
  };
}

function loadInstancesFromFile(
  path: string,
  defaults: {
    writeMode: WriteMode;
    tlsVerify: boolean;
    allowHttp: boolean;
    caFile?: string;
    timeoutMs: number;
    maxResponseBytes: number;
    defaultOverride?: string;
  },
): { instances: OpnsenseTarget[]; defaultInstance: string } {
  const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
  const file = fileConfigSchema.parse(raw);
  const names = new Set<string>();
  const instances = file.instances.map((entry) => {
    if (names.has(entry.name)) {
      throw new Error(`Duplicate OPNsense instance name "${entry.name}" in ${path}`);
    }
    names.add(entry.name);
    return buildTarget({
      name: entry.name,
      url: entry.url,
      apiKey: entry.api_key,
      apiSecret: entry.api_secret,
      writeMode: entry.write_mode ?? defaults.writeMode,
      tlsVerify: entry.tls_verify ?? defaults.tlsVerify,
      allowHttp: entry.allow_http ?? defaults.allowHttp,
      ...(entry.ca_file ? { caFile: entry.ca_file } : defaults.caFile ? { caFile: defaults.caFile } : {}),
      timeoutMs: entry.timeout_ms ?? defaults.timeoutMs,
      maxResponseBytes: entry.max_response_bytes ?? defaults.maxResponseBytes,
    });
  });

  const defaultInstance = defaults.defaultOverride ?? file.default ?? instances[0]!.name;
  if (!names.has(defaultInstance)) {
    throw new Error(`Default instance "${defaultInstance}" is not defined in ${path}`);
  }
  return { instances, defaultInstance };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = envSchema.parse(env);
  const loopbackHosts = ["127.0.0.1", "localhost", "::1"];
  const allowedHosts = csv(parsed.MCP_ALLOWED_HOSTS);

  if (parsed.MCP_TRANSPORT === "http") {
    if (!parsed.MCP_AUTH_TOKEN && !parsed.MCP_ALLOW_UNAUTHENTICATED) {
      throw new Error("MCP_AUTH_TOKEN (at least 32 characters) is required for HTTP transport");
    }
    if (!loopbackHosts.includes(parsed.MCP_HOST) && allowedHosts.length === 0) {
      throw new Error("MCP_ALLOWED_HOSTS is required when MCP_HOST is not a loopback address");
    }
  }

  const defaults = {
    writeMode: parsed.OPNSENSE_WRITE_MODE,
    tlsVerify: parsed.OPNSENSE_TLS_VERIFY,
    allowHttp: parsed.OPNSENSE_ALLOW_HTTP,
    ...(parsed.OPNSENSE_CA_FILE ? { caFile: parsed.OPNSENSE_CA_FILE } : {}),
    timeoutMs: parsed.OPNSENSE_TIMEOUT_MS,
    maxResponseBytes: parsed.OPNSENSE_MAX_RESPONSE_BYTES,
    ...(parsed.OPNSENSE_DEFAULT_INSTANCE ? { defaultOverride: parsed.OPNSENSE_DEFAULT_INSTANCE } : {}),
  };

  let instances: OpnsenseTarget[];
  let defaultInstance: string;

  if (parsed.OPNSENSE_CONFIG_PATH) {
    ({ instances, defaultInstance } = loadInstancesFromFile(parsed.OPNSENSE_CONFIG_PATH, defaults));
  } else if (parsed.OPNSENSE_URL && parsed.OPNSENSE_API_KEY && parsed.OPNSENSE_API_SECRET) {
    const name = parsed.OPNSENSE_INSTANCE_NAME ?? "default";
    instances = [
      buildTarget({
        name,
        url: parsed.OPNSENSE_URL,
        apiKey: parsed.OPNSENSE_API_KEY,
        apiSecret: parsed.OPNSENSE_API_SECRET,
        writeMode: defaults.writeMode,
        tlsVerify: defaults.tlsVerify,
        allowHttp: defaults.allowHttp,
        ...(defaults.caFile ? { caFile: defaults.caFile } : {}),
        timeoutMs: defaults.timeoutMs,
        maxResponseBytes: defaults.maxResponseBytes,
      }),
    ];
    defaultInstance = parsed.OPNSENSE_DEFAULT_INSTANCE ?? name;
    if (defaultInstance !== name) {
      throw new Error(`OPNSENSE_DEFAULT_INSTANCE="${defaultInstance}" does not match the single env instance "${name}"`);
    }
  } else {
    throw new Error(
      "Configure either OPNSENSE_CONFIG_PATH (multi-instance JSON) or OPNSENSE_URL + OPNSENSE_API_KEY + OPNSENSE_API_SECRET",
    );
  }

  return {
    instances,
    defaultInstance,
    transport: parsed.MCP_TRANSPORT,
    http: {
      host: parsed.MCP_HOST,
      port: parsed.MCP_PORT,
      path: parsed.MCP_PATH,
      authToken: parsed.MCP_AUTH_TOKEN,
      allowUnauthenticated: parsed.MCP_ALLOW_UNAUTHENTICATED,
      allowedHosts: allowedHosts.length > 0 ? allowedHosts : ["127.0.0.1", "localhost", "[::1]"],
      allowedOrigins: csv(parsed.MCP_ALLOWED_ORIGINS),
      maxSessions: parsed.MCP_MAX_SESSIONS,
      sessionTtlMs: parsed.MCP_SESSION_TTL_MS,
      rateLimitPerMinute: parsed.MCP_RATE_LIMIT_PER_MINUTE,
    },
  };
}

export function resolveTarget(config: Config, instance?: string | undefined): OpnsenseTarget {
  const name = instance ?? config.defaultInstance;
  const target = config.instances.find((entry) => entry.name === name);
  if (!target) {
    const known = config.instances.map((entry) => entry.name).join(", ");
    throw new Error(`Unknown OPNsense instance "${name}". Known instances: ${known}`);
  }
  return target;
}
