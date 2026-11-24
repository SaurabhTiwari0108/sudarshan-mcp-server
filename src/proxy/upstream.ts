import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { SecurityPipeline } from "./pipeline.js";
import { logger } from "../utils/logger.js";

export class UpstreamServer {
  private server: Server;

  constructor(private pipeline: SecurityPipeline) {
    this.server = new Server(
      {
        name: "sudarshan-gateway",
        version: "0.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupHandlers();
  }

  private setupHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      logger.debug("Received ListTools request from upstream agent");
      return await this.pipeline.handleListTools();
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args = {} } = request.params;
      logger.debug(`Received CallTool request for "${name}" from upstream agent`);
      return await this.pipeline.handleCallTool(name, (args as Record<string, unknown>) || {});
    });
  }

  /**
   * Connect to a transport (e.g. StdioServerTransport or InMemoryTransport).
   */
  async connect(transport: Transport): Promise<void> {
    await this.server.connect(transport);
    logger.info("Upstream MCP server connected to transport");
  }

  /**
   * Convenience method to start on stdio transport.
   */
  async startStdio(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.connect(transport);
    logger.info("Sudarshan Gateway listening on stdio");
  }

  async close(): Promise<void> {
    await this.server.close();
    logger.info("Upstream MCP server closed");
  }

  getServer(): Server {
    return this.server;
  }
}

