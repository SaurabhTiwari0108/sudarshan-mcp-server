import { describe, it, expect } from "vitest";
import { loadPolicyConfig, loadGatewayConfig } from "../src/config/load.js";
import { PolicyEngine } from "../src/policy/engine.js";
import { SecurityPipeline } from "../src/proxy/pipeline.js";
import { DownstreamManager } from "../src/proxy/downstream.js";

describe("Phase 6 Hardening: Fail-Closed Guarantees", () => {
  it("gateway config loading fails closed on missing file", () => {
    expect(() => loadGatewayConfig("non_existent_config.yaml")).toThrow();
  });

  it("policy loading fails closed on missing file", () => {
    expect(() => loadPolicyConfig("non_existent_policy.yaml")).toThrow();
  });

  it("policy engine fails closed to block on internal exception", () => {
    const brokenEngine = new PolicyEngine({
      version: 1,
      default_action: "allow",
      rules: [
        {
          id: "crash-rule",
          match: {
            tool: "*",
            contains: "secrets",
          },
          action: "allow",
          risk: "low",
        },
      ],
    });

    // Scanner predicate throws an unexpected error
    const decision = brokenEngine.evaluate({
      tool: "mock.db_query",
      args: { test: 123 },
      scannerPredicate: () => {
        throw new Error("Simulated scanner crash");
      },
    });

    expect(decision.action).toBe("block");
    expect(decision.risk).toBe("critical");
    expect(decision.reasons[0]).toContain("Fail closed");
  });

  it("security pipeline fails closed to block when policy engine is corrupted", async () => {
    const downstream = new DownstreamManager();
    const mockClient = {
      listTools: async () => ({ tools: [] }),
      callTool: async () => ({ content: [] }),
    } as any;
    downstream.registerClient("mock", mockClient);

    // Intentionally pass an invalid object that throws when evaluate is called
    const corruptedEngine: any = {
      evaluate: () => {
        throw new Error("Fatal engine memory failure");
      },
    };

    const pipeline = new SecurityPipeline(downstream, corruptedEngine);
    const result = await pipeline.handleCallTool("mock.db_query", {});

    expect(result.isError).toBe(true);
    if (result.content[0]?.type === "text") {
      expect(result.content[0].text).toContain("Blocked by Sudarshan due to internal pipeline error");
    }
  });
});
