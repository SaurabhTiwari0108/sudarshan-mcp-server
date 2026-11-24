import { describe, it, expect } from "vitest";
import { runDemoScenario } from "./demo.js";

describe("Phase 6: Full Demo Scenario (SPEC Section 13)", () => {
  it("executes all 6 demo scenarios end-to-end successfully", async () => {
    const logs: string[] = [];
    await runDemoScenario((msg) => logs.push(msg));
    expect(logs.some((l) => l.includes("ALL 6 DEMO SCENARIOS COMPLETED"))).toBe(true);
  });
});

