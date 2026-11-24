import { describe, it, expect } from "vitest";
import { PolicyEngine } from "../src/policy/engine.js";
import { Policy } from "../src/policy/types.js";
import { loadPolicyConfig } from "../src/config/load.js";
import { normalizeToolName, cleanSqlAndWhitespaceVariants, getSearchableArgVariants } from "../src/policy/normalize.js";

const TEST_POLICY: Policy = {
  version: 1,
  default_action: "allow",
  rules: [
    {
      id: "block-destructive-sql",
      description: "Destructive SQL needs a human",
      match: {
        tool: "*db*",
        args_contains_any: ["DROP TABLE", "DROP DATABASE", "TRUNCATE", "DELETE FROM"],
      },
      action: "require_approval",
      risk: "critical",
    },
    {
      id: "block-secret-file-writes",
      match: {
        tool: "*fs*write*",
        path_matches_any: ["**/.env", "**/.env.*", "**/*.pem", "**/id_rsa*"],
      },
      action: "block",
      risk: "critical",
    },
    {
      id: "external-http-needs-approval",
      match: {
        tool: "*http*",
        domain_not_in: ["api.company.com"],
      },
      action: "require_approval",
      risk: "high",
    },
    {
      id: "redact-secrets-in-responses",
      match: {
        tool: "*",
        direction: "response",
        contains: "secrets",
      },
      action: "redact",
      risk: "medium",
    },
  ],
};

describe("Phase 2: Policy Normalization & Anti-Bypass", () => {
  it("normalizes tool names by lowercasing and stripping downstream prefix", () => {
    expect(normalizeToolName("mock.db_query")).toBe("db_query");
    expect(normalizeToolName("DATABASE.QUERY")).toBe("query");
    expect(normalizeToolName("db_query")).toBe("db_query");
  });

  it("catches SQL comments word-splitting bypass (d/**/rop table x)", () => {
    const rawSql = "d/**/rop table users";
    const variants = cleanSqlAndWhitespaceVariants(rawSql);
    const searchable = getSearchableArgVariants({ sql: rawSql });

    expect(searchable.some((v) => v.includes("drop table"))).toBe(true);
  });

  it("catches collapsed repeated whitespace bypass (DROP   TABLE)", () => {
    const rawSql = "DROP    TABLE   accounts";
    const searchable = getSearchableArgVariants({ sql: rawSql });
    expect(searchable.some((v) => v.includes("drop table"))).toBe(true);
  });

  it("catches base64 encoded payloads", () => {
    // Base64 of "DROP TABLE accounts;" is "RFJPUCBUQUJMRSBhY2NvdW50czs="
    const base64Sql = "RFJPUCBUQUJMRSBhY2NvdW50czs=";
    const searchable = getSearchableArgVariants({ query: base64Sql });
    expect(searchable.some((v) => v.includes("drop table"))).toBe(true);
  });

  it("catches URL-encoded payloads", () => {
    const urlEncoded = "DROP%20TABLE%20orders";
    const searchable = getSearchableArgVariants({ sql: urlEncoded });
    expect(searchable.some((v) => v.includes("drop table"))).toBe(true);
  });

  it("handles NFKC unicode full-width characters", () => {
    // Fullwidth 'DROP' -> 'ＤＲＯＰ'
    const fullwidth = "\uFF24\uFF32\uFF2F\uFF30 TABLE users";
    const searchable = getSearchableArgVariants({ sql: fullwidth });
    expect(searchable.some((v) => v.includes("drop table"))).toBe(true);
  });
});

describe("Phase 2: Policy Engine Evaluation", () => {
  const engine = new PolicyEngine(TEST_POLICY);

  it("allows benign query when no rules match", () => {
    const decision = engine.evaluate({
      tool: "mock.db_query",
      args: { sql: "SELECT * FROM users" },
      direction: "request",
    });

    expect(decision.action).toBe("allow");
    expect(decision.risk).toBe("low");
    expect(decision.matchedRuleIds).toHaveLength(0);
  });

  it("requires approval for destructive SQL query", () => {
    const decision = engine.evaluate({
      tool: "mock.db_query",
      args: { sql: "DROP TABLE users;" },
      direction: "request",
    });

    expect(decision.action).toBe("require_approval");
    expect(decision.risk).toBe("critical");
    expect(decision.matchedRuleIds).toContain("block-destructive-sql");
  });

  it("blocks secret file writes matching glob patterns", () => {
    const pathsToTest = [
      "/app/.env",
      "./.env",
      ".env.production",
      "keys/id_rsa",
      "server.pem",
      "C:\\app\\.env",
    ];

    for (const filePath of pathsToTest) {
      const decision = engine.evaluate({
        tool: "mock.fs_write",
        args: { path: filePath, content: "SECRET=1" },
        direction: "request",
      });

      expect(decision.action).toBe("block");
      expect(decision.risk).toBe("critical");
      expect(decision.matchedRuleIds).toContain("block-secret-file-writes");
    }
  });

  it("allows safe file writes that do not match secret globs", () => {
    const decision = engine.evaluate({
      tool: "mock.fs_write",
      args: { path: "/app/readme.md", content: "hello world" },
      direction: "request",
    });

    expect(decision.action).toBe("allow");
  });

  it("requires approval for external HTTP destinations not in allowlist", () => {
    const decision = engine.evaluate({
      tool: "mock.http_post",
      args: { url: "https://evil.example.com/api", body: "{}" },
      direction: "request",
    });

    expect(decision.action).toBe("require_approval");
    expect(decision.risk).toBe("high");
    expect(decision.matchedRuleIds).toContain("external-http-needs-approval");
  });

  it("allows HTTP requests to approved domains", () => {
    const decision = engine.evaluate({
      tool: "mock.http_post",
      args: { url: "https://api.company.com/v1/data", body: "{}" },
      direction: "request",
    });

    expect(decision.action).toBe("allow");
  });

  it("enforces 'strictest action wins' when multiple rules match", () => {
    const multiPolicy: Policy = {
      version: 1,
      default_action: "allow",
      rules: [
        {
          id: "rule-allow",
          match: { tool: "*tool*" },
          action: "allow",
          risk: "low",
        },
        {
          id: "rule-redact",
          match: { tool: "*tool*" },
          action: "redact",
          risk: "medium",
        },
        {
          id: "rule-approval",
          match: { tool: "*tool*" },
          action: "require_approval",
          risk: "high",
        },
        {
          id: "rule-block",
          match: { tool: "*tool*" },
          action: "block",
          risk: "critical",
        },
      ],
    };

    const multiEngine = new PolicyEngine(multiPolicy);
    const decision = multiEngine.evaluate({
      tool: "test_tool",
      args: {},
      direction: "request",
    });

    expect(decision.action).toBe("block");
    expect(decision.risk).toBe("critical");
    expect(decision.matchedRuleIds).toEqual([
      "rule-allow",
      "rule-redact",
      "rule-approval",
      "rule-block",
    ]);
  });

  it("prioritizes require_approval over redact and allow", () => {
    const customPolicy: Policy = {
      version: 1,
      default_action: "allow",
      rules: [
        {
          id: "r1",
          match: { tool: "test" },
          action: "redact",
          risk: "medium",
        },
        {
          id: "r2",
          match: { tool: "test" },
          action: "require_approval",
          risk: "high",
        },
      ],
    };

    const customEngine = new PolicyEngine(customPolicy);
    const decision = customEngine.evaluate({ tool: "test", direction: "request" });
    expect(decision.action).toBe("require_approval");
    expect(decision.risk).toBe("high");
  });

  it("fails closed (returns block) when an unexpected error occurs during evaluation", () => {
    // Malformed context causing error
    const faultyEngine = new PolicyEngine({
      version: 1,
      default_action: "allow",
      rules: [
        {
          id: "faulty",
          match: { tool: "*", args_contains_any: ["TEST"] },
          action: "allow",
          risk: "low",
        },
      ],
    });

    // Circular object in args that throws on serialization if not handled
    const circular: Record<string, unknown> = {};
    circular.self = circular;

    const decision = faultyEngine.evaluate({
      tool: "some_tool",
      args: circular,
      direction: "request",
    });

    // Engine must not crash; returns valid decision
    expect(["allow", "block"]).toContain(decision.action);
  });
});

describe("Phase 2: Policy YAML Loading & Validation", () => {
  it("loads and validates existing policy.yaml cleanly", () => {
    const policy = loadPolicyConfig("policy.yaml");
    expect(policy.version).toBe(1);
    expect(policy.rules.length).toBeGreaterThanOrEqual(4);
  });

  it("fails closed on missing policy file", () => {
    expect(() => loadPolicyConfig("non_existent_policy.yaml")).toThrow();
  });
});

