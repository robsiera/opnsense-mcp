import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Config } from "./config.js";
import { InstanceRegistry } from "./instances.js";
import { PlanStore } from "./plans.js";
import { registerDiagnostics } from "./diagnostics.js";
import { assessRisk } from "./policy.js";
import {
  firewallLogsRequest,
  firewallRulesRequest,
  LOG_SCOPES,
  LOG_SEVERITIES,
  natRulesRequest,
  NAT_TYPES,
  routeTableRequest,
  systemLogsRequest,
} from "./read-only.js";
import { apiRequestShape, optionalInstanceShape } from "./schema.js";
import type { ApiRequest } from "./types.js";

function toolResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    ...(isError ? { isError: true } : {}),
  };
}

function formatError(error: unknown) {
  if (!(error instanceof Error)) return { error: "Unknown error" };
  const enriched = error as Error & { status?: number; response?: unknown };
  return {
    error: enriched.message,
    ...(enriched.status !== undefined ? { status: enriched.status } : {}),
    ...(enriched.response !== undefined ? { response: enriched.response } : {}),
  };
}

export function createServer(config: Config, registry = new InstanceRegistry(config)): McpServer {
  const server = new McpServer({ name: "opnsense-mcp", version: "0.2.0" });
  const plans = new PlanStore();
  registerDiagnostics(server, registry);

  server.registerTool(
    "opnsense_list_instances",
    {
      description:
        "List configured OPNsense instances (name, target origin, write mode). Credentials are never returned.",
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () =>
      toolResult({
        defaultInstance: registry.defaultInstance,
        instances: registry.list(),
      }),
  );

  server.registerTool(
    "opnsense_connection_info",
    {
      description:
        "Show the configured OPNsense target and local safety policy for one instance (or the default). Credentials are never returned.",
      inputSchema: optionalInstanceShape,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async (input) => {
      try {
        const resolved = registry.resolve(input.instance);
        return toolResult({
          instance: resolved.name,
          target: resolved.target.baseUrl.origin,
          writeMode: resolved.target.writeMode,
          tlsVerification: resolved.target.tlsVerify,
          customCaConfigured: resolved.target.ca !== undefined,
          timeoutMs: resolved.target.timeoutMs,
          maxResponseBytes: resolved.target.maxResponseBytes,
          defaultInstance: registry.defaultInstance,
          instanceCount: config.instances.length,
        });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  server.registerTool(
    "opnsense_request",
    {
      description:
        "Call a read-classified OPNsense API endpoint. Unknown or mutating commands are rejected even when they use GET; use opnsense_plan_change for those.",
      inputSchema: apiRequestShape,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async (input) => {
      try {
        const { instance, ...requestFields } = input;
        const resolved = registry.resolve(instance);
        const request = requestFields as ApiRequest;
        const risk = assessRisk(request);
        if (risk.level !== "read") {
          return toolResult({ instance: resolved.name, error: "Endpoint is not classified as read-only", risk }, true);
        }
        return toolResult({ instance: resolved.name, ...(await resolved.client.call(request)) });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  const pageShape = {
    page: z.number().int().min(1).default(1).describe("One-based result page"),
    pageSize: z.number().int().min(1).max(1000).default(100).describe("Maximum rows to return"),
    search: z.string().max(512).default("").describe("Case-insensitive search phrase"),
  };

  server.registerTool(
    "opnsense_get_firewall_logs",
    {
      description: "Read structured packet-filter log entries. This cannot stream or clear logs.",
      inputSchema: {
        ...optionalInstanceShape,
        limit: z.number().int().min(1).max(5000).default(1000),
        digest: z.string().max(256).optional().describe("Optional digest returned by an earlier request for incremental reads"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async (input) => {
      try {
        const { instance, ...fields } = input;
        const resolved = registry.resolve(instance);
        return toolResult({ instance: resolved.name, ...(await resolved.client.call(firewallLogsRequest(fields))) });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  server.registerTool(
    "opnsense_get_logs",
    {
      description:
        "Read a bounded page from an OPNsense system or service log. The endpoint is fixed to query mode and cannot clear, export, or stream logs.",
      inputSchema: {
        ...optionalInstanceShape,
        scope: z.enum(LOG_SCOPES).describe("Log source"),
        ...pageShape,
        severities: z.array(z.enum(LOG_SEVERITIES)).max(LOG_SEVERITIES.length).optional(),
        sinceMinutes: z.number().int().min(1).max(525_600).optional().describe("Only return entries this many minutes old or newer"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async (input) => {
      try {
        const { instance, ...fields } = input;
        const resolved = registry.resolve(instance);
        return toolResult({ instance: resolved.name, ...(await resolved.client.call(systemLogsRequest(fields))) });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  server.registerTool(
    "opnsense_list_firewall_rules",
    {
      description: "List firewall filter rules visible to the OPNsense automation API. This cannot add, alter, toggle, move, or apply rules.",
      inputSchema: {
        ...optionalInstanceShape,
        ...pageShape,
        category: z.string().uuid().optional().describe("Optional firewall category UUID"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async (input) => {
      try {
        const { instance, ...fields } = input;
        const resolved = registry.resolve(instance);
        return toolResult({ instance: resolved.name, ...(await resolved.client.call(firewallRulesRequest(fields))) });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  server.registerTool(
    "opnsense_list_nat_rules",
    {
      description:
        "List destination NAT, source NAT, one-to-one NAT, or IPv6 NPT rules. Automatic rules are included where OPNsense supplies them.",
      inputSchema: {
        ...optionalInstanceShape,
        type: z.enum(NAT_TYPES),
        ...pageShape,
        category: z.string().uuid().optional().describe("Optional firewall category UUID"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async (input) => {
      try {
        const { instance, ...fields } = input;
        const resolved = registry.resolve(instance);
        return toolResult({ instance: resolved.name, ...(await resolved.client.call(natRulesRequest(fields))) });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  server.registerTool(
    "opnsense_get_route_table",
    {
      description:
        "Read either the active kernel route table or configured static routes. Name resolution is disabled by default for predictable output.",
      inputSchema: {
        ...optionalInstanceShape,
        source: z.enum(["active", "configured"]).default("active"),
        resolve: z.boolean().default(false).describe("Resolve active route addresses; ignored for configured routes"),
        ...pageShape,
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async (input) => {
      try {
        const { instance, ...fields } = input;
        const resolved = registry.resolve(instance);
        return toolResult({ instance: resolved.name, ...(await resolved.client.call(routeTableRequest(fields))) });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  server.registerTool(
    "opnsense_plan_change",
    {
      description:
        "Assess a non-read OPNsense request and create a short-lived, one-time token bound to that instance. This tool does not contact or change OPNsense.",
      inputSchema: apiRequestShape,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async (input) => {
      try {
        const { instance, ...requestFields } = input;
        const resolved = registry.resolve(instance);
        const request = requestFields as ApiRequest;
        const risk = assessRisk(request);
        if (risk.level === "read") {
          return toolResult(
            { instance: resolved.name, error: "This endpoint is read-classified; use opnsense_request instead", risk },
            true,
          );
        }
        if (resolved.target.writeMode === "disabled") {
          return toolResult(
            { instance: resolved.name, error: "Mutations are disabled by write_mode/OPNSENSE_WRITE_MODE=disabled", risk, request },
            true,
          );
        }
        if (resolved.target.writeMode === "plan") {
          return toolResult({
            instance: resolved.name,
            executable: false,
            risk,
            request,
            reason: "write_mode/OPNSENSE_WRITE_MODE=plan never issues execution tokens",
          });
        }
        const plan = plans.create(resolved.name, request, risk);
        return toolResult({ instance: resolved.name, executable: true, risk, request, ...plan });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  server.registerTool(
    "opnsense_execute_change",
    {
      description:
        "Execute the exact OPNsense mutation previously assessed by opnsense_plan_change on the same instance. Tokens expire after five minutes and can be used only once.",
      inputSchema: { ...apiRequestShape, planToken: z.string().min(1).describe("One-time token from opnsense_plan_change") },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    async (input) => {
      try {
        const { instance, planToken, ...requestFields } = input;
        const resolved = registry.resolve(instance);
        if (resolved.target.writeMode !== "enabled") {
          return toolResult({ instance: resolved.name, error: "Execution requires write_mode/OPNSENSE_WRITE_MODE=enabled" }, true);
        }
        const request = requestFields as ApiRequest;
        const plan = plans.consume(planToken, resolved.name, request);
        const response = await resolved.client.call(request);
        return toolResult({ instance: resolved.name, risk: plan.risk, response });
      } catch (error) {
        return toolResult(formatError(error), true);
      }
    },
  );

  return server;
}
