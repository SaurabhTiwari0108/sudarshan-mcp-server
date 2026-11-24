import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { Tool, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { DownstreamServerConfig } from "../config/types.js";
import { logger } from "../utils/logger.js";

export interface DownstreamEntry {
  name: string;
  client: Client;
  transport?: Transport;
}

export class DownstreamManager {
  private servers: Map<string, DownstreamEntry> = new Map();

  constructor(private configs: DownstreamServerConfig[] = []) {}

  /**
   * Connect to all configured downstream servers using StdioClientTransport.
   */
  async start(): Promise<void> {
    for (const cfg of this.configs) {
      logger.info(`Connecting to downstream server: ${cfg.name} (${cfg.command} ${cfg.args.join(" ")})`);
      
      const transport = new StdioClientTransport({
        command: cfg.command,
        args: cfg.args,
        env: {
          ...getDefaultEnvironment(),
          ...cfg.env,
        },
      });

      const client = new Client(
        {
          name: `sudarshan-client-${cfg.name}`,
          version: "1.0.0",
        },
        {
          capabilities: {},
        }
      );

      await client.connect(transport);
      this.servers.set(cfg.name, { name: cfg.name, client, transport });
      logger.info(`Connected to downstream server: ${cfg.name}`);
    }
  }

  /**
   * Register a pre-connected client (useful for unit testing with InMemoryTransport).
   */
  registerClient(name: string, client: Client, transport?: Transport) {
    this.servers.set(name, { name, client, transport });
  }

  /**
   * Close all client connections.
   */
  async stop(): Promise<void> {
    for (const [name, entry] of this.servers.entries()) {
      try {
        await entry.client.close();
      } catch (err) {
        logger.error(`Error closing downstream server ${name}:`, err);
      }
    }
    this.servers.clear();
  }

  /**
   * Resolve a prefixed tool name (e.g. "mock.db_query") into downstream server name and raw tool name.
   */
  resolveTool(prefixedName: string): { serverName: string; rawToolName: string } | null {
    const dotIndex = prefixedName.indexOf(".");
    if (dotIndex <= 0 || dotIndex === prefixedName.length - 1) {
      return null;
    }
    const serverName = prefixedName.substring(0, dotIndex);
    const rawToolName = prefixedName.substring(dotIndex + 1);

    if (!this.servers.has(serverName)) {
      return null;
    }

    return { serverName, rawToolName };
  }

  /**
   * Fetch tools from all downstream servers and prefix them with `${serverName}.`.
   */
  async listAllTools(): Promise<Tool[]> {
    const allTools: Tool[] = [];

    for (const [name, entry] of this.servers.entries()) {
      try {
        const response = await entry.client.listTools();
        for (const tool of response.tools) {
          allTools.push({
            ...tool,
            name: `${name}.${tool.name}`,
          });
        }
      } catch (err) {
        logger.error(`Failed to list tools from downstream server ${name}:`, err);
        // Fail closed or skip? For Phase 1 we log error
      }
    }

    return allTools;
  }

  /**
   * Execute a tool on the resolved downstream server.
   */
  async callTool(prefixedName: string, args: Record<string, unknown> = {}): Promise<CallToolResult> {
    const resolved = this.resolveTool(prefixedName);
    if (!resolved) {
      logger.error(`Unknown tool or downstream server: ${prefixedName}`);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Unknown tool: ${prefixedName}`,
          },
        ],
      };
    }

    const { serverName, rawToolName } = resolved;
    const entry = this.servers.get(serverName)!;

    try {
      const result = await entry.client.callTool({
        name: rawToolName,
        arguments: args,
      });
      return result as CallToolResult;
    } catch (err) {
      logger.error(`Error calling downstream tool ${prefixedName}:`, err);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error from downstream tool ${prefixedName}: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
      };
    }
  }

  getClient(serverName: string): Client | undefined {
    return this.servers.get(serverName)?.client;
  }
}

