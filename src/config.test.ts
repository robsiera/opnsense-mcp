import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig, resolveTarget } from "./config.js";

const base = {
  OPNSENSE_URL: "https://firewall.example",
  OPNSENSE_API_KEY: "key",
  OPNSENSE_API_SECRET: "secret",
};

describe("remote transport configuration", () => {
  it("requires authentication for HTTP by default", () => {
    expect(() => loadConfig(base)).toThrow("MCP_AUTH_TOKEN");
  });

  it("allows stdio without an MCP bearer token", () => {
    expect(loadConfig({ ...base, MCP_TRANSPORT: "stdio" }).transport).toBe("stdio");
  });

  it("requires allowed hosts on non-loopback bindings", () => {
    expect(() =>
      loadConfig({ ...base, MCP_AUTH_TOKEN: "x".repeat(32), MCP_HOST: "0.0.0.0" }),
    ).toThrow("MCP_ALLOWED_HOSTS");
  });

  it("parses remote security settings", () => {
    const config = loadConfig({
      ...base,
      MCP_AUTH_TOKEN: "x".repeat(32),
      MCP_HOST: "0.0.0.0",
      MCP_PORT: "8080",
      MCP_ALLOWED_HOSTS: "mcp.example.com, localhost",
      MCP_ALLOWED_ORIGINS: "https://agents.example.com",
    });
    expect(config.http).toMatchObject({
      host: "0.0.0.0",
      port: 8080,
      allowedHosts: ["mcp.example.com", "localhost"],
      allowedOrigins: ["https://agents.example.com"],
    });
  });

  it("loads a single env instance named default", () => {
    const config = loadConfig({ ...base, MCP_TRANSPORT: "stdio" });
    expect(config.defaultInstance).toBe("default");
    expect(config.instances).toHaveLength(1);
    expect(config.instances[0]?.baseUrl.origin).toBe("https://firewall.example");
  });

  it("loads multiple instances from a config file", () => {
    const dir = mkdtempSync(join(tmpdir(), "opnsense-mcp-"));
    const path = join(dir, "instances.json");
    writeFileSync(
      path,
      JSON.stringify({
        default: "gra",
        instances: [
          {
            name: "bxl",
            url: "https://bxl.example",
            api_key: "k1",
            api_secret: "s1",
            write_mode: "plan",
          },
          {
            name: "gra",
            url: "https://gra.example",
            api_key: "k2",
            api_secret: "s2",
            allow_http: false,
          },
        ],
      }),
    );

    const config = loadConfig({
      OPNSENSE_CONFIG_PATH: path,
      MCP_TRANSPORT: "stdio",
      OPNSENSE_WRITE_MODE: "disabled",
    });

    expect(config.defaultInstance).toBe("gra");
    expect(config.instances.map((entry) => entry.name)).toEqual(["bxl", "gra"]);
    expect(resolveTarget(config, "bxl").writeMode).toBe("plan");
    expect(resolveTarget(config).writeMode).toBe("disabled");
    expect(resolveTarget(config).baseUrl.origin).toBe("https://gra.example");
  });

  it("rejects unknown instance names", () => {
    const config = loadConfig({ ...base, MCP_TRANSPORT: "stdio" });
    expect(() => resolveTarget(config, "missing")).toThrow('Unknown OPNsense instance "missing"');
  });
});
