import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import { isAuthorized, isOriginAllowed, startHttpServer, type RunningHttpServer } from "./http.js";

const token = "remote-test-token-that-is-at-least-32-characters";
let running: RunningHttpServer | undefined;

afterEach(async () => {
  await running?.close();
  running = undefined;
});

function testConfig() {
  return loadConfig({
    OPNSENSE_URL: "https://firewall.example",
    OPNSENSE_API_KEY: "key",
    OPNSENSE_API_SECRET: "secret",
    MCP_TRANSPORT: "http",
    MCP_HOST: "127.0.0.1",
    MCP_PORT: "0",
    MCP_AUTH_TOKEN: token,
    MCP_ALLOWED_ORIGINS: "https://agents.example.com",
  });
}

describe("HTTP security helpers", () => {
  it("checks bearer tokens without prefix or length ambiguity", () => {
    expect(isAuthorized(`Bearer ${token}`, token)).toBe(true);
    expect(isAuthorized(`Basic ${token}`, token)).toBe(false);
    expect(isAuthorized("Bearer wrong", token)).toBe(false);
  });

  it("allows non-browser clients and validates browser origins", () => {
    expect(isOriginAllowed(undefined, [])).toBe(true);
    expect(isOriginAllowed("https://agents.example.com", ["https://agents.example.com"])).toBe(true);
    expect(isOriginAllowed("https://evil.example", ["https://agents.example.com"])).toBe(false);
  });
});

describe("Streamable HTTP MCP server", () => {
  it("rejects unauthenticated and unapproved-origin requests", async () => {
    running = await startHttpServer(testConfig());
    const unauthenticated = await fetch(running.url, { method: "POST", body: "{}", headers: { "content-type": "application/json" } });
    expect(unauthenticated.status).toBe(401);

    const wrongOrigin = await fetch(running.url, {
      method: "POST",
      body: "{}",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", origin: "https://evil.example" },
    });
    expect(wrongOrigin.status).toBe(403);
  });

  it("establishes an authenticated stateful session and lists tools", async () => {
    running = await startHttpServer(testConfig());
    const transport = new StreamableHTTPClientTransport(new URL(running.url), {
      requestInit: { headers: { authorization: `Bearer ${token}` } },
    });
    const client = new Client({ name: "http-test", version: "1.0.0" });
    await client.connect(transport as Transport);
    const tools = await client.listTools();
    expect(transport.sessionId).toBeTruthy();
    expect(tools.tools.map((tool) => tool.name)).toEqual(
      expect.arrayContaining(["opnsense_get_firewall_logs", "opnsense_list_instances"]),
    );
    // Write-disabled deployments still expose scoped active diagnostics.
    expect(tools.tools.map((tool) => tool.name)).toEqual(expect.arrayContaining([
      "opnsense_ping", "opnsense_traceroute", "opnsense_probe_port",
    ]));
    const blocked = await client.callTool({ name: "opnsense_request", arguments: {
      module: "diagnostics", controller: "ping", command: "start", parameters: ["other-job"], method: "POST",
    } });
    expect(blocked.isError).toBe(true);
    await client.close();
  });
});
