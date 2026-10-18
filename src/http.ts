import { randomUUID, timingSafeEqual } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { NextFunction, Request, Response } from "express";
import { rateLimit } from "express-rate-limit";
import type { Config } from "./config.js";
import { InstanceRegistry } from "./instances.js";
import { createServer } from "./server.js";

interface Session {
  server: McpServer;
  transport: StreamableHTTPServerTransport;
  lastSeen: number;
}

export function isAuthorized(authorization: string | undefined, expectedToken: string | undefined): boolean {
  if (!expectedToken) return true;
  if (!authorization?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(authorization.slice(7), "utf8");
  const expected = Buffer.from(expectedToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export function isOriginAllowed(origin: string | undefined, allowedOrigins: readonly string[]): boolean {
  if (!origin) return true;
  return allowedOrigins.includes(origin);
}

function jsonRpcError(res: Response, status: number, message: string): void {
  res.status(status).json({ jsonrpc: "2.0", error: { code: -32000, message }, id: null });
}

export interface RunningHttpServer {
  url: string;
  close: () => Promise<void>;
}

export async function startHttpServer(config: Config): Promise<RunningHttpServer> {
  const { http } = config;
  const app = createMcpExpressApp({ host: http.host, allowedHosts: http.allowedHosts });
  const registry = new InstanceRegistry(config);
  const sessions = new Map<string, Session>();

  app.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok", transport: "streamable-http" });
  });

  app.use(http.path, (req: Request, res: Response, next: NextFunction) => {
    if (!isOriginAllowed(req.header("origin"), http.allowedOrigins)) {
      jsonRpcError(res, 403, "Origin is not allowed");
      return;
    }
    if (!http.allowUnauthenticated && !isAuthorized(req.header("authorization"), http.authToken)) {
      res.setHeader("WWW-Authenticate", 'Bearer realm="opnsense-mcp"');
      jsonRpcError(res, 401, "Authentication required");
      return;
    }
    next();
  });

  app.use(
    http.path,
    rateLimit({
      windowMs: 60_000,
      limit: http.rateLimitPerMinute,
      standardHeaders: "draft-8",
      legacyHeaders: false,
      message: { jsonrpc: "2.0", error: { code: -32000, message: "Rate limit exceeded" }, id: null },
    }),
  );

  async function closeSession(sessionId: string): Promise<void> {
    const session = sessions.get(sessionId);
    if (!session) return;
    sessions.delete(sessionId);
    await session.server.close().catch(() => undefined);
  }

  async function handleMcp(req: Request, res: Response): Promise<void> {
    const sessionId = req.header("mcp-session-id");
    let session = sessionId ? sessions.get(sessionId) : undefined;

    try {
      if (!session && req.method === "POST" && !sessionId && isInitializeRequest(req.body)) {
        if (sessions.size >= http.maxSessions) {
          jsonRpcError(res, 503, "Session capacity reached");
          return;
        }

        const server = createServer(config, registry);
        let transport: StreamableHTTPServerTransport;
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: randomUUID,
          enableJsonResponse: true,
          onsessioninitialized: (initializedId) => {
            sessions.set(initializedId, { server, transport, lastSeen: Date.now() });
          },
          onsessionclosed: async (closedId) => closeSession(closedId),
        });
        transport.onclose = () => {
          const id = transport.sessionId;
          if (id) sessions.delete(id);
        };
        // SDK 1.30's transport declarations conflict under exactOptionalPropertyTypes.
        await server.connect(transport as Transport);
        await transport.handleRequest(req, res, req.body);
        return;
      }

      if (!session) {
        jsonRpcError(res, sessionId ? 404 : 400, "Invalid or missing MCP session");
        return;
      }

      session.lastSeen = Date.now();
      await session.transport.handleRequest(req, res, req.body);
    } catch (error) {
      process.stderr.write(`opnsense-mcp: HTTP request failed: ${error instanceof Error ? error.message : String(error)}\n`);
      if (!res.headersSent) jsonRpcError(res, 500, "Internal server error");
    }
  }

  app.all(http.path, (req, res) => void handleMcp(req, res));

  const cleanupTimer = setInterval(() => {
    const cutoff = Date.now() - http.sessionTtlMs;
    for (const [sessionId, session] of sessions) {
      if (session.lastSeen < cutoff) void closeSession(sessionId);
    }
  }, Math.min(60_000, http.sessionTtlMs));
  cleanupTimer.unref();

  const httpServer = await new Promise<HttpServer>((resolve, reject) => {
    const listener = app.listen(http.port, http.host, () => resolve(listener));
    listener.once("error", reject);
  });
  const address = httpServer.address() as AddressInfo;

  return {
    url: `http://${http.host}:${address.port}${http.path}`,
    close: async () => {
      clearInterval(cleanupTimer);
      await Promise.all([...sessions.keys()].map(closeSession));
      await registry.close();
      await new Promise<void>((resolve, reject) => {
        httpServer.close((error) => (error ? reject(error) : resolve()));
      });
    },
  };
}
