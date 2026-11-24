import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { DownstreamManager } from "../src/proxy/downstream.js";
import { SecurityPipeline } from "../src/proxy/pipeline.js";
import { UpstreamServer } from "../src/proxy/upstream.js";
import { PolicyEngine } from "../src/policy/engine.js";
import { loadPolicyConfig } from "../src/config/load.js";
import {
  createMockServer,
  getExecutionCount,
  resetStats,
} from "../fixtures/mock-server/index.js";

describe("Phase 1: Skeleton Proxy Pipeline", () => {
  let mockServer: ReturnType<typeof createMockServer>;
  let downstreamManager: DownstreamManager;
  let pipeline: SecurityPipeline;
  let upstreamServer: UpstreamServer;
  let agentClient: Client;

  beforeEach(async () => {
    resetStats();

    // 1. Setup mock downstream server with in-memory transport
    mockServer = createMockServer();
    const [mockClientTransport, mockServerTransport] = InMemoryTransport.createLinkedPair();
    await mockServer.connect(mockServerTransport);

    const mockClient = new Client(
      { name: "sudarshan-client-mock", version: "1.0.0" },
      { capabilities: {} }
    );
    await mockClient.connect(mockClientTransport);

    // 2. Setup DownstreamManager and register mock client
    downstreamManager = new DownstreamManager();
    downstreamManager.registerClient("mock", mockClient);

    // 3. Setup Pipeline & Upstream Server
    pipeline = new SecurityPipeline(downstreamManager);
    upstreamServer = new UpstreamServer(pipeline);

    // 4. Connect simulated Agent (MCP client) to Upstream Server
    const [agentTransport, upstreamTransport] = InMemoryTransport.createLinkedPair();
    await upstreamServer.connect(upstreamTransport);

    agentClient = new Client(
      { name: "ai-agent", version: "1.0.0" },
      { capabilities: {} }
    );
    await agentClient.connect(agentTransport);
  });

  afterEach(async () => {
    await agentClient.close();
    await upstreamServer.close();
    await downstreamManager.stop();
  });

  it("lists all downstream tools with prefix 'mock.'", async () => {
    const response = await agentClient.listTools();
    const toolNames = response.tools.map((t) => t.name);

    expect(toolNames).toContain("mock.db_query");
    expect(toolNames).toContain("mock.fs_write");
    expect(toolNames).toContain("mock.http_post");
    expect(response.tools).toHaveLength(3);
  });

  it("forwards mock.db_query to downstream and returns result", async () => {
    const result = await agentClient.callTool({
      name: "mock.db_query",
      arguments: { sql: "SELECT * FROM orders" },
    });

    expect(result.isError).toBeFalsy();
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: executed",
    });
    expect(getExecutionCount("db_query")).toBe(1);
  });

  it("forwards mock.fs_write to downstream and returns result", async () => {
    const result = await agentClient.callTool({
      name: "mock.fs_write",
      arguments: { path: "/workspace/config.json", content: "{}" },
    });

    expect(result.isError).toBeFalsy();
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: written",
    });
    expect(getExecutionCount("fs_write")).toBe(1);
  });

  it("forwards mock.http_post to downstream and returns result", async () => {
    const result = await agentClient.callTool({
      name: "mock.http_post",
      arguments: { url: "https://api.internal/data", body: "{}" },
    });

    expect(result.isError).toBeFalsy();
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: sent",
    });
    expect(getExecutionCount("http_post")).toBe(1);
  });

  it("blocks and fails closed on unknown downstream server or unprefixed tool", async () => {
    const result = await agentClient.callTool({
      name: "db_query", // Missing prefix
      arguments: { sql: "SELECT 1" },
    });

    expect(result.isError).toBe(true);
    expect(getExecutionCount()).toBe(0); // Downstream must NEVER be called
    if (result.content[0]?.type === "text") {
      expect(result.content[0].text).toContain("Blocked by Sudarshan");
    }
  });

  it("blocks call to an unregistered downstream server", async () => {
    const result = await agentClient.callTool({
      name: "github.create_issue",
      arguments: { title: "Test" },
    });

    expect(result.isError).toBe(true);
    expect(getExecutionCount()).toBe(0);
    if (result.content[0]?.type === "text") {
      expect(result.content[0].text).toContain("Blocked by Sudarshan");
    }
  });
});

describe("Phase 2: Policy-Enforced Pipeline Interception", () => {
  let mockServer: ReturnType<typeof createMockServer>;
  let downstreamManager: DownstreamManager;
  let pipeline: SecurityPipeline;
  let upstreamServer: UpstreamServer;
  let agentClient: Client;

  beforeEach(async () => {
    resetStats();

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

    pipeline = new SecurityPipeline(downstreamManager, policyEngine);
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
  });

  it("blocks secret file writes (.env) before reaching downstream", async () => {
    const result = await agentClient.callTool({
      name: "mock.fs_write",
      arguments: { path: "/app/.env", content: "SECRET=123" },
    });

    expect(result.isError).toBe(true);
    expect(getExecutionCount("fs_write")).toBe(0); // Downstream NEVER touched
    if (result.content[0]?.type === "text") {
      expect(result.content[0].text).toContain("Blocked by Sudarshan");
      expect(result.content[0].text).toContain("block-secret-file-writes");
    }
  });

  it("intercepts destructive SQL query requiring approval", async () => {
    const result = await agentClient.callTool({
      name: "mock.db_query",
      arguments: { sql: "DROP TABLE users;" },
    });

    expect(result.isError).toBe(true);
    expect(getExecutionCount("db_query")).toBe(0); // Downstream NEVER touched
    if (result.content[0]?.type === "text") {
      expect(result.content[0].text).toContain("requires approval");
    }
  });

  it("allows safe queries to pass through to downstream", async () => {
    const result = await agentClient.callTool({
      name: "mock.db_query",
      arguments: { sql: "SELECT * FROM users;" },
    });

    expect(result.isError).toBeFalsy();
    expect(getExecutionCount("db_query")).toBe(1);
  });

  it("redacts fake AWS key in response so it never reaches the agent", async () => {
    const result = await agentClient.callTool({
      name: "mock.db_query",
      arguments: { sql: "SELECT secret FROM config;" },
    });

    expect(result.isError).toBeFalsy();
    const content = result.content[0];
    expect(content.type).toBe("text");
    if (content.type === "text") {
      // Must not contain raw key
      expect(content.text).not.toContain("AKIAIOSFODNN7EXAMPLE");
      // Must contain redacted placeholder
      expect(content.text).toContain("[REDACTED:aws_access_key]");
    }
    expect(getExecutionCount("db_query")).toBe(1);
  });
});



