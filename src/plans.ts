import { createHash, randomBytes } from "node:crypto";
import type { ApiRequest, RiskAssessment } from "./types.js";

interface Plan {
  instance: string;
  digest: string;
  expiresAt: number;
  request: ApiRequest;
  risk: RiskAssessment;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}

function digest(request: ApiRequest): string {
  return createHash("sha256").update(JSON.stringify(canonicalize(request))).digest("hex");
}

export class PlanStore {
  readonly #plans = new Map<string, Plan>();
  readonly #ttlMs: number;

  constructor(ttlMs = 5 * 60 * 1000) {
    this.#ttlMs = ttlMs;
  }

  create(instance: string, request: ApiRequest, risk: RiskAssessment): { token: string; expiresAt: string } {
    this.#purge();
    const token = randomBytes(24).toString("base64url");
    const expiresAt = Date.now() + this.#ttlMs;
    this.#plans.set(token, { instance, digest: digest(request), expiresAt, request, risk });
    return { token, expiresAt: new Date(expiresAt).toISOString() };
  }

  consume(token: string, instance: string, request: ApiRequest): Plan {
    this.#purge();
    const plan = this.#plans.get(token);
    this.#plans.delete(token);
    if (!plan) throw new Error("The plan token is invalid, expired, or already used");
    if (plan.instance !== instance) {
      throw new Error(`The plan token belongs to instance "${plan.instance}", not "${instance}"`);
    }
    if (plan.digest !== digest(request)) throw new Error("The request does not exactly match the approved plan");
    return plan;
  }

  #purge(): void {
    const now = Date.now();
    for (const [token, plan] of this.#plans) {
      if (plan.expiresAt <= now) this.#plans.delete(token);
    }
  }
}
