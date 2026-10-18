import { describe, expect, it } from "vitest";
import { PlanStore } from "./plans.js";
import type { ApiRequest, RiskAssessment } from "./types.js";

describe("PlanStore", () => {
  const request: ApiRequest = {
    module: "firewall",
    controller: "filter",
    command: "set_rule",
    parameters: ["b81da63b-84d7-4ad9-8eae-e11495851cbd"],
    body: { rule: { description: "allow web", enabled: "1" } },
  };
  const risk: RiskAssessment = { level: "write", reason: "test" };

  it("accepts the exact request once on the same instance", () => {
    const plans = new PlanStore();
    const { token } = plans.create("bxl", request, risk);
    expect(plans.consume(token, "bxl", request).risk).toEqual(risk);
    expect(() => plans.consume(token, "bxl", request)).toThrow("invalid, expired, or already used");
  });

  it("rejects a changed body and consumes the token", () => {
    const plans = new PlanStore();
    const { token } = plans.create("bxl", request, risk);
    expect(() =>
      plans.consume(token, "bxl", { ...request, body: { rule: { description: "allow all", enabled: "1" } } }),
    ).toThrow("does not exactly match");
    expect(() => plans.consume(token, "bxl", request)).toThrow("invalid, expired, or already used");
  });

  it("rejects using a plan token against another instance", () => {
    const plans = new PlanStore();
    const { token } = plans.create("bxl", request, risk);
    expect(() => plans.consume(token, "gra", request)).toThrow('belongs to instance "bxl"');
  });
});
