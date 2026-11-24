import { describe, it, expect, beforeEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  createMockServer,
  getExecutionCount,
  getCallHistory,
  resetStats,
} from "../fixtures/mock-server/index.js";

describe("Mock Server Fixture", () => {
  let client: Client;
  let server: ReturnType<typeof createMockServer>;

  beforeEach(async () => {
    resetStats();
    server = createMockServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);

    client = new Client(
      { name: "test-client", version: "1.0.0" },
      { capabilities: {} }
    );
    await client.connect(clientTransport);
  });

  it("lists all three mock tools", async () => {
    const response = await client.listTools();
    const toolNames = response.tools.map((t) => t.name);
    expect(toolNames).toContain("db_query");
    expect(toolNames).toContain("fs_write");
    expect(toolNames).toContain("http_post");
    expect(response.tools).toHaveLength(3);
  });

  it("executes db_query and tracks execution count", async () => {
    expect(getExecutionCount("db_query")).toBe(0);

    const result = await client.callTool({
      name: "db_query",
      arguments: { sql: "SELECT * FROM users" },
    });

    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: executed",
    });
    expect(getExecutionCount("db_query")).toBe(1);
    expect(getCallHistory()[0]).toMatchObject({
      tool: "db_query",
      args: { sql: "SELECT * FROM users" },
    });
  });

  it("returns fake AWS key for SELECT secret query", async () => {
    const result = await client.callTool({
      name: "db_query",
      arguments: { sql: "SELECT secret FROM config" },
    });

    const content = result.content[0];
    expect(content.type).toBe("text");
    if (content.type === "text") {
      expect(content.text).toContain("AKIAIOSFODNN7EXAMPLE");
    }
    expect(getExecutionCount("db_query")).toBe(1);
  });

  it("executes fs_write and tracks execution", async () => {
    const result = await client.callTool({
      name: "fs_write",
      arguments: { path: "/app/.env", content: "SECRET=123" },
    });

    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: written",
    });
    expect(getExecutionCount("fs_write")).toBe(1);
  });

  it("executes http_post and tracks execution", async () => {
    const result = await client.callTool({
      name: "http_post",
      arguments: { url: "https://example.com/api", body: '{"ok":true}' },
    });

    expect(result.content[0]).toMatchObject({
      type: "text",
      text: "ok: sent",
    });
    expect(getExecutionCount("http_post")).toBe(1);
  });

  it("handles unknown tool gracefully", async () => {
    const result = await client.callTool({
      name: "unknown_tool",
      arguments: {},
    });

    expect(result.isError).toBe(true);
  });

  it("resets statistics cleanly", async () => {
    await client.callTool({ name: "db_query", arguments: { sql: "SELECT 1" } });
    expect(getExecutionCount()).toBe(1);

    resetStats();
    expect(getExecutionCount()).toBe(0);
    expect(getCallHistory()).toHaveLength(0);
  });
});

