import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { AuditLogger } from "../src/audit/log.js";
import { verifyAuditLog } from "../src/audit/verify.js";

describe("Phase 5: Audit Log Hash Chain & Verification", () => {
  let tempDir: string;
  let logFile: string;
  let auditLogger: AuditLogger;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-test-"));
    logFile = path.join(tempDir, "audit.jsonl");
    auditLogger = new AuditLogger(logFile);
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("creates genesis entry with prev_hash GENESIS and seq 1", async () => {
    const entry = await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "request",
      tool: "mock.db_query",
      args_redacted: { sql: "SELECT * FROM users" },
      decision: "allow",
      risk: "low",
      rule_ids: [],
    });

    expect(entry.seq).toBe(1);
    expect(entry.prev_hash).toBe("GENESIS");
    expect(entry.hash).toBeDefined();
    expect(entry.hash.length).toBe(64); // SHA-256 hex string

    const verifyResult = verifyAuditLog(logFile);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.totalEntries).toBe(1);
  });

  it("chains multiple entries sequentially with matching hashes", async () => {
    const e1 = await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "request",
      tool: "mock.db_query",
      args_redacted: { sql: "SELECT 1" },
      decision: "allow",
      risk: "low",
      rule_ids: [],
    });

    const e2 = await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "request",
      tool: "mock.db_query",
      args_redacted: { sql: "DROP TABLE users;" },
      decision: "require_approval",
      approval_result: "denied",
      risk: "critical",
      rule_ids: ["block-destructive-sql"],
    });

    const e3 = await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "response",
      tool: "mock.db_query",
      args_redacted: { result: "ok" },
      decision: "allow",
      risk: "low",
      rule_ids: [],
    });

    expect(e2.seq).toBe(2);
    expect(e2.prev_hash).toBe(e1.hash);
    expect(e3.seq).toBe(3);
    expect(e3.prev_hash).toBe(e2.hash);

    const verifyResult = verifyAuditLog(logFile);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.totalEntries).toBe(3);
  });

  it("serializes concurrent write calls without corrupting the chain", async () => {
    const promises = Array.from({ length: 15 }).map((_, i) =>
      auditLogger.appendEntry({
        agent_id: "agent-1",
        direction: "request",
        tool: `mock.tool_${i}`,
        args_redacted: { index: i },
        decision: "allow",
        risk: "low",
        rule_ids: [],
      })
    );

    const entries = await Promise.all(promises);
    expect(entries.length).toBe(15);

    const verifyResult = verifyAuditLog(logFile);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.totalEntries).toBe(15);
  });

  it("detects tampering when an entry payload is modified", async () => {
    await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "request",
      tool: "mock.db_query",
      args_redacted: { sql: "SELECT 1" },
      decision: "allow",
      risk: "low",
      rule_ids: [],
    });

    await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "request",
      tool: "mock.db_query",
      args_redacted: { sql: "DROP TABLE users;" },
      decision: "require_approval",
      approval_result: "denied",
      risk: "critical",
      rule_ids: ["block-destructive-sql"],
    });

    await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "request",
      tool: "mock.fs_write",
      args_redacted: { path: "/app/data.txt" },
      decision: "allow",
      risk: "low",
      rule_ids: [],
    });

    // Manually tamper with line 2 (change decision from denied to approved)
    const content = fs.readFileSync(logFile, "utf-8");
    const lines = content.split("\n");
    const tamperedLine2 = lines[1].replace('"decision":"require_approval"', '"decision":"allow"');
    lines[1] = tamperedLine2;
    fs.writeFileSync(logFile, lines.join("\n"), "utf-8");

    const verifyResult = verifyAuditLog(logFile);
    expect(verifyResult.valid).toBe(false);
    expect(verifyResult.brokenSeq).toBe(2);
    expect(verifyResult.reason).toContain("Tamper detected");
  });

  it("detects tampering when a line is deleted", async () => {
    await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "request",
      tool: "mock.db_query",
      args_redacted: { sql: "SELECT 1" },
      decision: "allow",
      risk: "low",
      rule_ids: [],
    });
    await auditLogger.appendEntry({
      agent_id: "agent-1",
      direction: "request",
      tool: "mock.db_query",
      args_redacted: { sql: "SELECT 2" },
      decision: "allow",
      risk: "low",
      rule_ids: [],
    });

    // Delete the first line
    const content = fs.readFileSync(logFile, "utf-8");
    const lines = content.split("\n").filter(Boolean);
    fs.writeFileSync(logFile, lines[1] + "\n", "utf-8");

    const verifyResult = verifyAuditLog(logFile);
    expect(verifyResult.valid).toBe(false);
    expect(verifyResult.reason).toContain("Sequence gap or mismatch");
  });
});

