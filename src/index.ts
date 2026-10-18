#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { InstanceRegistry } from "./instances.js";
import { startHttpServer } from "./http.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  const config = loadConfig();
  if (config.transport === "http") {
    const running = await startHttpServer(config);
    process.stderr.write(`opnsense-mcp: listening on ${running.url}\n`);
    process.stderr.write(
      `opnsense-mcp: ${config.instances.length} instance(s), default="${config.defaultInstance}"\n`,
    );
    const shutdown = () => void running.close().finally(() => process.exit(0));
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } else {
    const registry = new InstanceRegistry(config);
    const server = createServer(config, registry);
    const transport = new StdioServerTransport();
    process.stderr.write(
      `opnsense-mcp: stdio ready (${config.instances.length} instance(s), default="${config.defaultInstance}")\n`,
    );
    await server.connect(transport);
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`opnsense-mcp: ${message}\n`);
  process.exitCode = 1;
});
