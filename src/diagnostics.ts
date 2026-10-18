import { isIP } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { optionalInstanceShape } from "./schema.js";
import type { ApiRequest, ApiResponse } from "./types.js";

type Caller = { call: (request: ApiRequest) => Promise<ApiResponse> };
type DiagnosticsRegistry = {
  resolve(instance?: string | undefined): { name: string; diagnostics: Diagnostics };
};
const hostname = z.string().min(1).max(253).refine(
  (value) => isIP(value) !== 0 || value.replace(/\.$/, "").split(".").every(
    (label) => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label),
  ), "Expected an IP address or hostname (not a URL or command)",
);
const sourceAddress = z.string().refine((value) => isIP(value) !== 0, "Expected an IP address").optional();
const common = {
  ...optionalInstanceShape,
  host: hostname,
  family: z.enum(["ipv4", "ipv6"]).default("ipv4"),
  sourceAddress,
};
export const pingSchema = z.object({
  ...common,
  durationSeconds: z.number().int().min(1).max(10).default(3),
  packetSize: z.number().int().min(1).max(1400).default(56),
});
export const tracerouteSchema = z.object({ ...common, protocol: z.enum(["udp", "icmp"]).default("udp") });
export const portProbeSchema = z.object({ ...common, port: z.number().int().min(1).max(65535) });

function request(controller: string, command: string, body?: unknown, parameters?: string[]): ApiRequest {
  return {
    module: "diagnostics", controller, command, method: "POST",
    ...(body === undefined ? {} : { body }),
    ...(parameters === undefined ? {} : { parameters }),
  };
}

function successful(response: ApiResponse): Record<string, unknown> {
  const data = response.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Unexpected diagnostics response");
  const result = data as Record<string, unknown>;
  if (result.result === "failed" || result.status === "failed" || result.status === "error" || result.validations) {
    throw new Error(`OPNsense diagnostic rejected: ${JSON.stringify(result)}`);
  }
  if (result.result !== "ok" && result.result !== "saved" && result.status !== "ok" && !Array.isArray(result.rows)) {
    throw new Error(`Unrecognized diagnostics result: ${JSON.stringify(result)}`);
  }
  return result;
}

export class Diagnostics {
  #busy = false;
  constructor(private readonly client: Caller, private readonly wait = (ms: number) => delay(ms)) {}

  async #run<T>(action: () => Promise<T>): Promise<T> {
    if (this.#busy) throw new Error("A diagnostic is already running; retry after it completes");
    this.#busy = true;
    try { return await action(); } finally { this.#busy = false; }
  }

  ping(input: z.input<typeof pingSchema>) {
    const args = pingSchema.parse(input);
    return this.#run(async () => {
      const created = successful(await this.client.call(request("ping", "set", {
        ping: { settings: {
          hostname: args.host, fam: args.family === "ipv4" ? "ip" : "ip6",
          source_address: args.sourceAddress ?? "", packetsize: String(args.packetSize),
          interval: "1", disable_frag: "0", description: "MCP bounded diagnostic",
        } },
      })));
      const job = z.string().uuid().parse(created.uuid);
      const cleanupErrors: string[] = [];
      let result: Record<string, unknown> | undefined;
      let failure: unknown;
      try {
        successful(await this.client.call(request("ping", "start", {}, [job])));
        await this.wait(args.durationSeconds * 1000);
        // OPNsense's list action sends SIGINFO to running pings to emit stats.
        // Stopping first kills the process before it can report. The signal/log
        // write is asynchronous, so allow up to one extra second for a snapshot.
        for (let attempt = 0; attempt < 5; attempt++) {
          if (attempt > 0) await this.wait(250);
          const jobs = successful(await this.client.call(request("ping", "search_jobs", {
            current: 1, rowCount: 1000, searchPhrase: job, sort: {},
          })));
          // Older revisions may ignore searchPhrase. Never return other jobs.
          const row: unknown = Array.isArray(jobs.rows) ? jobs.rows.find((row) => row?.id === job) : undefined;
          if (row && typeof row === "object" && !Array.isArray(row)) result = row as Record<string, unknown>;
          if (result?.last_error) throw new Error(`OPNsense ping failed: ${String(result.last_error)}`);
          if (typeof result?.send === "number" && result.send > 0 &&
              typeof result.received === "number" && result.received >= 0) break;
        }
        if (!result) throw new Error("Ping job result was not returned by OPNsense");
        if (typeof result.send !== "number" || result.send <= 0 ||
            typeof result.received !== "number" || result.received < 0) {
          throw new Error("OPNsense returned no ping statistics within the collection window; this is not evidence of packet loss or DNS failure");
        }
      } catch (error) { failure = error; }
      finally {
        for (const command of ["stop", "remove"]) {
          try { successful(await this.client.call(request("ping", command, {}, [job]))); }
          catch (error) { cleanupErrors.push(`${command}: ${error instanceof Error ? error.message : String(error)}`); }
        }
      }
      return {
        jobId: job, result,
        ...(failure ? { error: failure instanceof Error ? failure.message : String(failure) } : {}),
        ...(cleanupErrors.length ? { cleanupErrors, warning: "Temporary ping job may still exist or run on OPNsense" } : {}),
      };
    });
  }

  traceroute(input: z.input<typeof tracerouteSchema>) {
    const args = tracerouteSchema.parse(input);
    return this.#run(async () => successful(await this.client.call(request("traceroute", "set", {
      traceroute: { settings: {
        hostname: args.host, ipproto: args.family === "ipv4" ? "inet" : "inet6",
        source_address: args.sourceAddress ?? "", protocol: args.protocol,
      } },
    }))));
  }

  portProbe(input: z.input<typeof portProbeSchema>) {
    const args = portProbeSchema.parse(input);
    return this.#run(async () => successful(await this.client.call(request("portprobe", "set", {
      portprobe: { settings: {
        hostname: args.host, port: String(args.port), ipproto: args.family === "ipv4" ? "inet" : "inet6",
        source_address: args.sourceAddress ?? "", source_port: "", showtext: "0",
      } },
    }))));
  }
}

export function registerDiagnostics(server: McpServer, registry: DiagnosticsRegistry): void {
  const annotations = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true };
  const output = async (instance: string | undefined, action: (diagnostics: Diagnostics) => Promise<unknown>) => {
    try {
      const resolved = registry.resolve(instance);
      const result = await action(resolved.diagnostics);
      const failed = result && typeof result === "object" && ("error" in result || "cleanupErrors" in result);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ instance: resolved.name, ...(result as object) }, null, 2) }],
        ...(failed ? { isError: true } : {}),
      };
    } catch (error) {
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: error instanceof Error ? error.message : String(error) }) }], isError: true };
    }
  };
  server.registerTool("opnsense_ping", {
    description: "Run a short ping from OPNsense, collect its statistics, and stop/remove only the job created by this call. Available with configuration writes disabled; requires diagnostic ACL privileges. Concurrent diagnostics are limited per instance.",
    inputSchema: pingSchema.shape, annotations,
  }, (args) => output(args.instance, (diagnostics) => diagnostics.ping(args)));
  server.registerTool("opnsense_traceroute", {
    description: "Run an IPv4/IPv6 UDP or ICMP traceroute from OPNsense without saving configuration. Available with configuration writes disabled. OPNsense controls probe limits; HTTP timeout does not cancel backend execution.",
    inputSchema: tracerouteSchema.shape, annotations,
  }, (args) => output(args.instance, (diagnostics) => diagnostics.traceroute(args)));
  server.registerTool("opnsense_probe_port", {
    description: "Test one TCP port from OPNsense without saving configuration or reading remote banners. Available with configuration writes disabled; not a port-range scanner.",
    inputSchema: portProbeSchema.shape, annotations,
  }, (args) => output(args.instance, (diagnostics) => diagnostics.portProbe(args)));
}
