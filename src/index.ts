import { loadGatewayConfig, loadPolicyConfig } from "./config/load.js";
import { DownstreamManager } from "./proxy/downstream.js";
import { SecurityPipeline } from "./proxy/pipeline.js";
import { UpstreamServer } from "./proxy/upstream.js";
import { PolicyEngine } from "./policy/engine.js";
import { ApprovalQueue } from "./approval/queue.js";
import { ApprovalServer } from "./approval/server.js";
import { AuditLogger } from "./audit/log.js";
import { logger } from "./utils/logger.js";

async function main() {
  logger.info("Initializing Sudarshan MCP Gateway...");

  try {
    const config = loadGatewayConfig();
    logger.info(`Loaded gateway config with ${config.downstream.length} downstream server(s)`);

    const policy = loadPolicyConfig();
    logger.info(`Loaded policy config with ${policy.rules.length} rule(s)`);

    // 1. Audit logger
    const auditLogger = new AuditLogger(config.gateway.audit_log_path);

    // 2. Approval queue & localhost HTTP server
    const approvalQueue = new ApprovalQueue(
      config.gateway.approval_dir,
      config.gateway.approval_timeout_seconds
    );
    const approvalServer = new ApprovalServer(
      approvalQueue,
      config.gateway.approval_http_port
    );
    await approvalServer.start();

    // 3. Downstream connections
    const downstreamManager = new DownstreamManager(config.downstream);
    await downstreamManager.start();

    // 4. Policy Engine & Pipeline
    const policyEngine = new PolicyEngine(policy);
    const pipeline = new SecurityPipeline(
      downstreamManager,
      policyEngine,
      approvalQueue,
      auditLogger,
      {
        agentId: config.gateway.agent_id,
        approvalTimeoutSeconds: config.gateway.approval_timeout_seconds,
      }
    );

    // 5. Upstream MCP server facing agent over stdio
    const upstream = new UpstreamServer(pipeline);
    await upstream.startStdio();
    logger.info("Sudarshan MCP Gateway ready.");

    const shutdown = async () => {
      logger.info("Shutting down Sudarshan MCP Gateway...");
      try {
        await upstream.close();
        await downstreamManager.stop();
        await approvalServer.stop();
      } catch (err) {
        logger.error("Error during shutdown:", err);
      }
      process.exit(0);
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } catch (err) {
    logger.error("Fatal startup error in Sudarshan MCP Gateway:", err);
    process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`Unhandled error: ${err}\n`);
  process.exit(1);
});
