import fs from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// In-memory state for tracking tool executions
const state = {
  counts: {
    db_query: 0,
    fs_write: 0,
    http_post: 0,
  },
  history: [],
};

function recordExecution(tool, args) {
  state.counts[tool] = (state.counts[tool] || 0) + 1;
  state.history.push({
    tool,
    args,
    timestamp: new Date().toISOString(),
  });

  if (process.env.MOCK_STATS_FILE) {
    try {
      fs.writeFileSync(
        process.env.MOCK_STATS_FILE,
        JSON.stringify(state, null, 2),
        "utf-8"
      );
    } catch (err) {
      process.stderr.write(`Failed to write mock stats: ${err}\n`);
    }
  }
}

export function getExecutionCount(tool) {
  if (tool) {
    return state.counts[tool] || 0;
  }
  return Object.values(state.counts).reduce((a, b) => a + b, 0);
}

export function getCallHistory() {
  return [...state.history];
}

export function resetStats() {
  state.counts.db_query = 0;
  state.counts.fs_write = 0;
  state.counts.http_post = 0;
  state.history = [];
  if (process.env.MOCK_STATS_FILE && fs.existsSync(process.env.MOCK_STATS_FILE)) {
    try {
      fs.writeFileSync(
        process.env.MOCK_STATS_FILE,
        JSON.stringify(state, null, 2),
        "utf-8"
      );
    } catch {
      // ignore
    }
  }
}

export const TOOLS = [
  {
    name: "db_query",
    description: "Execute a database query safely in mock environment",
    inputSchema: {
      type: "object",
      properties: {
        sql: { type: "string", description: "SQL query" },
      },
      required: ["sql"],
    },
  },
  {
    name: "fs_write",
    description: "Write content to a file safely in mock environment",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "File path" },
        content: { type: "string", description: "File content" },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "http_post",
    description: "Send HTTP POST request safely in mock environment",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Target URL" },
        body: { type: "string", description: "Request body" },
      },
      required: ["url"],
    },
  },
];

export function createMockServer() {
  const server = new Server(
    {
      name: "mock-server",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    switch (name) {
      case "db_query": {
        const sql = String(args.sql || "");
        recordExecution("db_query", args);
        if (sql.includes("SELECT secret")) {
          return {
            content: [
              {
                type: "text",
                text: "ok: executed - key is AKIAIOSFODNN7EXAMPLE",
              },
            ],
          };
        }
        return {
          content: [
            {
              type: "text",
              text: "ok: executed",
            },
          ],
        };
      }

      case "fs_write": {
        recordExecution("fs_write", args);
        return {
          content: [
            {
              type: "text",
              text: "ok: written",
            },
          ],
        };
      }

      case "http_post": {
        recordExecution("http_post", args);
        return {
          content: [
            {
              type: "text",
              text: "ok: sent",
            },
          ],
        };
      }

      default:
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `Unknown tool: ${name}`,
            },
          ],
        };
    }
  });

  return server;
}

// When executed directly as a script (via node ./fixtures/mock-server/index.js)
const isMain = process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("fixtures/mock-server/index.js");

if (isMain) {
  const server = createMockServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("[mock-server] Mock MCP server connected via stdio\n");
}

