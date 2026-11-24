import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { DownstreamManager } from "../src/proxy/downstream.js";
import { SecurityPipeline } from "../src/proxy/pipeline.js";
import { UpstreamServer } from "../src/proxy/upstream.js";

describe("Phase 1 E2E: Real Stdio Downstream Process", () => {
  let statsFilePath: string;
  let downstreamManager: DownstreamManager;
  let pipeline: SecurityPipeline;
  let upstreamServer: UpstreamServer;
  let agentClient: Client;

  beforeAll(async () => {
    // Temporary stats file for the mock-server child process
    statsFilePath = path.join(os.tmpdir(), `mock-stats-${Date.now()}.json`);
    if (fs.existsSync(statsFilePath)) {
      fs.unlinkSync(statsFilePath);
    }

    const mockServerScript = path.resolve(process.cwd(), "fixtures/mock-server/index.js");

    // Configure DownstreamManager with real child process stdio
    downstreamManager = new DownstreamManager([
      {
        name: "mock",
        command: "node",
        args: [mockServerScript],
        env: {
          MOCK_STATS_FILE: statsFilePath,
        },
      },
    ]);

    await downstreamManager.start();

    // Setup pipeline & upstream
    pipeline = new SecurityPipeline(downstreamManager);
    upstreamServer = new UpstreamServer(pipeline);

    const [agentTransport, upstreamTransport] = InMemoryTransport.createLinkedPair();
    await upstreamServer.connect(upstreamTransport);

    agentClient = new Client(
      { name: "e2e-agent", version: "1.0.0" },
      { capabilities: {} }
    );
    await agentClient.connect(agentTransport);
  }, 15000);

  afterAll(async () => {
    try {
      await agentClient?.close();
      await upstreamServer?.close();
      await downstreamManager?.stop();
    } finally {
      if (fs.existsSync(statsFilePath)) {
        try {
          fs.unlinkSync(statsFilePath);
        } catch {
          // ignore cleanup error
        }
      }
    }
  });

  function getProcessStats(): { counts: Record<string, number>; history: unknown[] } {
    if (!fs.existsSync(statsFilePath)) {
      return { counts: {}, history: [] };
    }
    try {
      const data = fs.readFileSync(statsFilePath, "utf-8");
      return JSON.parse(data);
    } catch {
      return { counts: {}, history: [] };
    }
  }

  it("lists tools exposed by downstream stdio process", async () => {
    const response = await agentClient.listTools();
    const toolNames = response.tools.map((t) => t.name);

    expect(toolNames).toContain("mock.db_query");
    expect(toolNames).toContain("mock.fs_write");
    expect(toolNames).toContain("mock.http_post");
    expect(response.tools.length).toBeGreaterThanOrEqual(3);
  });

  it("calls mock.db_query through gateway to real child process", async () => {
    const result = await agentClient.callTool({
      name: "mock.db_query",
      arguments: { sql: "SELECT * FROM users" },
    });

    expect(result.isError).toBeFalsy();
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: executed",
    });

    // Check stats updated by child process
    const stats = getProcessStats();
    expect(stats.counts["db_query"]).toBe(1);
  });

  it("calls mock.fs_write through gateway to real child process", async () => {
    const result = await agentClient.callTool({
      name: "mock.fs_write",
      arguments: { path: "/tmp/sample.txt", content: "data" },
    });

    expect(result.isError).toBeFalsy();
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: written",
    });

    const stats = getProcessStats();
    expect(stats.counts["fs_write"]).toBe(1);
  });

  it("calls mock.http_post through gateway to real child process", async () => {
    const result = await agentClient.callTool({
      name: "mock.http_post",
      arguments: { url: "https://example.com/api", body: '{"ok":true}' },
    });

    expect(result.isError).toBeFalsy();
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: sent",
    });

    const stats = getProcessStats();
    expect(stats.counts["http_post"]).toBe(1);
  });

  it("fails closed on invalid tool name and does not call child process", async () => {
    const beforeStats = getProcessStats();
    const beforeTotal = Object.values(beforeStats.counts).reduce((a, b) => a + b, 0);

    const result = await agentClient.callTool({
      name: "nonexistent.tool",
      arguments: {},
    });

    expect(result.isError).toBe(true);

    const afterStats = getProcessStats();
    const afterTotal = Object.values(afterStats.counts).reduce((a, b) => a + b, 0);
    // Downstream process was never called
    expect(afterTotal).toBe(beforeTotal);
  });
});

