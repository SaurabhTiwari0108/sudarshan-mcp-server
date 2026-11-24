import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { ApprovalQueue } from "../src/approval/queue.js";
import { ApprovalServer } from "../src/approval/server.js";
import { SecurityPipeline } from "../src/proxy/pipeline.js";
import { DownstreamManager } from "../src/proxy/downstream.js";
import { UpstreamServer } from "../src/proxy/upstream.js";
import { PolicyEngine } from "../src/policy/engine.js";
import { loadPolicyConfig } from "../src/config/load.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  createMockServer,
  getExecutionCount,
  resetStats,
} from "../fixtures/mock-server/index.js";

describe("Phase 4: Approval Queue & HTTP Server", () => {
  let tempDir: string;
  let queue: ApprovalQueue;
  let server: ApprovalServer;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "approval-test-"));
    queue = new ApprovalQueue(tempDir, 1); // 1s default timeout for fast tests
  });

  afterEach(async () => {
    if (server) {
      await server.stop();
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("creates and lists pending approval requests", async () => {
    const req = await queue.createRequest({
      agent_id: "agent-1",
      tool: "mock.db_query",
      redactedArgs: { sql: "DROP TABLE users;" },
      risk: "critical",
      reasons: ["Destructive SQL"],
    });

    expect(req.id).toBeDefined();
    expect(req.status).toBe("pending");

    const pending = await queue.listPending();
    expect(pending.length).toBe(1);
    expect(pending[0].id).toBe(req.id);
  });

  it("resolves an approval request with status approved or denied", async () => {
    const req = await queue.createRequest({
      agent_id: "agent-1",
      tool: "mock.db_query",
      redactedArgs: { sql: "DROP TABLE users;" },
      risk: "critical",
      reasons: ["Destructive SQL"],
    });

    await queue.resolveRequest(req.id, "approved", "admin");
    const updated = queue.getRequest(req.id);
    expect(updated?.status).toBe("approved");
    expect(updated?.resolvedBy).toBe("admin");

    const pendingAfter = await queue.listPending();
    expect(pendingAfter.length).toBe(0);
  });

  it("times out pending request and defaults to denied", async () => {
    const req = await queue.createRequest({
      agent_id: "agent-1",
      tool: "mock.db_query",
      redactedArgs: { sql: "DROP TABLE accounts;" },
      risk: "critical",
      reasons: ["Destructive SQL"],
    });

    // Wait for decision with 0.3s timeout
    const decision = await queue.waitForDecision(req.id, 0.3);
    expect(decision).toBe("denied");

    const updated = queue.getRequest(req.id);
    expect(updated?.status).toBe("denied");
    expect(updated?.resolvedBy).toBe("timeout");
  });

  it("serves approval dashboard and resolves via authenticated HTTP API", async () => {
    server = new ApprovalServer(queue, 7979);

    const req = await queue.createRequest({
      agent_id: "agent-1",
      tool: "mock.http_post",
      redactedArgs: { url: "https://evil.example.com" },
      risk: "high",
      reasons: ["External HTTP"],
    });

    const token = server.getStartupToken();

    // 1. Fetch dashboard HTML via handleRequest
    let htmlOutput = "";
    let htmlStatus = 0;
    const mockResGet: any = {
      writeHead(code: number) { htmlStatus = code; },
      end(data?: string) { if (data) htmlOutput += data; },
    };
    const mockReqGet: any = {
      method: "GET",
      url: `/?token=${token}`,
      headers: {},
      on: () => {},
    };
    await server.handleRequest(mockReqGet, mockResGet);
    expect(htmlStatus).toBe(200);
    expect(htmlOutput).toContain("Sudarshan MCP Gateway");
    expect(htmlOutput).toContain(req.id);

    // 2. Reject unauthorized resolve attempt (403)
    let badStatus = 0;
    const mockResBad: any = {
      writeHead(code: number) { badStatus = code; },
      end() {},
    };
    const mockReqBad: any = {
      method: "POST",
      url: "/api/resolve",
      headers: {},
      on(event: string, cb: any) {
        if (event === "data") cb(JSON.stringify({ id: req.id, status: "approved", token: "wrong" }));
        if (event === "end") cb();
      },
    };
    await server.handleRequest(mockReqBad, mockResBad);
    expect(badStatus).toBe(403);

    // 3. Resolve with valid token (200)
    let goodStatus = 0;
    const mockResGood: any = {
      writeHead(code: number) { goodStatus = code; },
      end() {},
    };
    const mockReqGood: any = {
      method: "POST",
      url: "/api/resolve",
      headers: {},
      on(event: string, cb: any) {
        if (event === "data") cb(JSON.stringify({ id: req.id, status: "approved", token }));
        if (event === "end") cb();
      },
    };
    await server.handleRequest(mockReqGood, mockResGood);
    expect(goodStatus).toBe(200);

    const updated = queue.getRequest(req.id);
    expect(updated?.status).toBe("approved");
  });
});

describe("Phase 4: Approval Flow in Pipeline (E2E scenarios)", () => {
  let tempDir: string;
  let queue: ApprovalQueue;
  let mockServer: ReturnType<typeof createMockServer>;
  let downstreamManager: DownstreamManager;
  let pipeline: SecurityPipeline;
  let upstreamServer: UpstreamServer;
  let agentClient: Client;

  beforeEach(async () => {
    resetStats();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pipeline-approval-"));
    queue = new ApprovalQueue(tempDir, 1);

    mockServer = createMockServer();
    const [mockClientTransport, mockServerTransport] = InMemoryTransport.createLinkedPair();
    await mockServer.connect(mockServerTransport);

    const mockClient = new Client(
      { name: "mock-client", version: "1.0.0" },
      { capabilities: {} }
    );
    await mockClient.connect(mockClientTransport);

    downstreamManager = new DownstreamManager();
    downstreamManager.registerClient("mock", mockClient);

    const policy = loadPolicyConfig("policy.yaml");
    const policyEngine = new PolicyEngine(policy);

    pipeline = new SecurityPipeline(downstreamManager, policyEngine, queue, {
      agentId: "test-agent",
      approvalTimeoutSeconds: 1, // 1 second timeout
    });
    upstreamServer = new UpstreamServer(pipeline);

    const [agentTransport, upstreamTransport] = InMemoryTransport.createLinkedPair();
    await upstreamServer.connect(upstreamTransport);

    agentClient = new Client(
      { name: "test-agent", version: "1.0.0" },
      { capabilities: {} }
    );
    await agentClient.connect(agentTransport);
  });

  afterEach(async () => {
    await agentClient.close();
    await upstreamServer.close();
    await downstreamManager.stop();
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("(a) approved call forwards unredacted call and executes downstream once", async () => {
    // Start tool call asynchronously
    const callPromise = agentClient.callTool({
      name: "mock.db_query",
      arguments: { sql: "DROP TABLE users;" },
    });

    // Wait until request is created in approval queue
    let pendingReq = null;
    for (let i = 0; i < 20; i++) {
      const list = await queue.listPending();
      if (list.length > 0) {
        pendingReq = list[0];
        break;
      }
      await new Promise((r) => setTimeout(r, 50));
    }

    expect(pendingReq).toBeDefined();
    expect(pendingReq?.tool).toBe("mock.db_query");

    // Human approves the call
    await queue.resolveRequest(pendingReq!.id, "approved", "tester");

    // Wait for tool result
    const result = await callPromise;
    expect(result.isError).toBeFalsy();
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: executed",
    });

    // Downstream executed exactly ONCE
    expect(getExecutionCount("db_query")).toBe(1);
  });

  it("(b) denied call never executes downstream and returns clear blocked message", async () => {
    const callPromise = agentClient.callTool({
      name: "mock.db_query",
      arguments: { sql: "DROP TABLE users;" },
    });

    let pendingReq = null;
    for (let i = 0; i < 20; i++) {
      const list = await queue.listPending();
      if (list.length > 0) {
        pendingReq = list[0];
        break;
      }
      await new Promise((r) => setTimeout(r, 50));
    }

    expect(pendingReq).toBeDefined();

    // Human denies the call
    await queue.resolveRequest(pendingReq!.id, "denied", "tester");

    const result = await callPromise;
    expect(result.isError).toBe(true);
    if (result.content[0]?.type === "text") {
      expect(result.content[0].text).toContain("Blocked by Sudarshan: action requires approval and was denied.");
    }

    // Downstream server was NEVER touched
    expect(getExecutionCount("db_query")).toBe(0);
  });

  it("(c) timed out approval call denies and never executes downstream", async () => {
    // We let the call time out (configured timeout is 1s)
    const result = await agentClient.callTool({
      name: "mock.db_query",
      arguments: { sql: "DROP DATABASE production;" },
    });

    expect(result.isError).toBe(true);
    if (result.content[0]?.type === "text") {
      expect(result.content[0].text).toContain("Blocked by Sudarshan: action requires approval and was denied.");
    }

    // Downstream server was NEVER touched
    expect(getExecutionCount("db_query")).toBe(0);
  });
});
