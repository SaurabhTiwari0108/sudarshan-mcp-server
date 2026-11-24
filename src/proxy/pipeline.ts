import { Tool, CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { DownstreamManager } from "./downstream.js";
import { PolicyEngine } from "../policy/engine.js";
import { ApprovalQueue } from "../approval/queue.js";
import { AuditLogger } from "../audit/log.js";
import { containsSensitivity, redactDeep } from "../scanner/secrets.js";
import { logger } from "../utils/logger.js";

export interface PipelineOptions {
  agentId?: string;
  approvalTimeoutSeconds?: number;
}

export class SecurityPipeline {
  private agentId: string;
  private approvalTimeoutSeconds: number;
  private auditLogger?: AuditLogger;

  constructor(
    private downstreamManager: DownstreamManager,
    private policyEngine?: PolicyEngine,
    private approvalQueue?: ApprovalQueue,
    auditLoggerOrOptions?: AuditLogger | PipelineOptions,
    options?: PipelineOptions
  ) {
    if (auditLoggerOrOptions && typeof (auditLoggerOrOptions as any).appendEntry === "function") {
      this.auditLogger = auditLoggerOrOptions as AuditLogger;
      const opts = options || {};
      this.agentId = opts.agentId || "default-agent";
      this.approvalTimeoutSeconds = opts.approvalTimeoutSeconds || 120;
    } else {
      const opts = (auditLoggerOrOptions as PipelineOptions) || options || {};
      this.agentId = opts.agentId || "default-agent";
      this.approvalTimeoutSeconds = opts.approvalTimeoutSeconds || 120;
    }
  }

  /**
   * Handle tools/list request from the upstream client.
   * Returns union of all downstream tools prefixed with downstream server name.
   */
  async handleListTools(): Promise<{ tools: Tool[] }> {
    try {
      const tools = await this.downstreamManager.listAllTools();
      return { tools };
    } catch (err) {
      logger.error("Error listing tools in pipeline:", err);
      return { tools: [] };
    }
  }

  /**
   * Handle tools/call request from upstream client.
   * Runs request through policy engine & scanner, acts on decision, logs to audit chain.
   */
  async handleCallTool(
    name: string,
    args: Record<string, unknown> = {}
  ): Promise<CallToolResult> {
    logger.info(`Received call for tool: ${name}`);
    const redactedArgs = redactDeep(args) as Record<string, unknown>;

    try {
      // 1. Resolve which downstream server owns the tool
      const resolved = this.downstreamManager.resolveTool(name);
      if (!resolved) {
        logger.warn(`Rejected unknown or malformed tool name: ${name}`);
        if (this.auditLogger) {
          await this.auditLogger.appendEntry({
            agent_id: this.agentId,
            direction: "request",
            tool: name,
            args_redacted: redactedArgs,
            decision: "block",
            approval_result: null,
            risk: "high",
            rule_ids: ["unknown-tool"],
          });
        }
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `Blocked by Sudarshan: unknown tool "${name}". Tool name must be prefixed with downstream server name (e.g. mock.db_query).`,
            },
          ],
        };
      }

      let forwardedArgs = args;

      // 2. Request-side policy evaluation
      if (this.policyEngine) {
        const reqDecision = this.policyEngine.evaluate({
          tool: name,
          args,
          direction: "request",
          scannerPredicate: (type, text) => containsSensitivity(type, text),
        });

        logger.info(`Request policy decision for ${name}: ${reqDecision.action} (risk: ${reqDecision.risk})`, {
          rules: reqDecision.matchedRuleIds,
        });

        if (reqDecision.action === "block") {
          if (this.auditLogger) {
            await this.auditLogger.appendEntry({
              agent_id: this.agentId,
              direction: "request",
              tool: name,
              args_redacted: redactedArgs,
              decision: "block",
              approval_result: null,
              risk: reqDecision.risk,
              rule_ids: reqDecision.matchedRuleIds,
            });
          }
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: `Blocked by Sudarshan: ${reqDecision.reasons.join("; ")}`,
              },
            ],
          };
        }

        if (reqDecision.action === "require_approval") {
          if (!this.approvalQueue) {
            if (this.auditLogger) {
              await this.auditLogger.appendEntry({
                agent_id: this.agentId,
                direction: "request",
                tool: name,
                args_redacted: redactedArgs,
                decision: "require_approval",
                approval_result: "denied",
                risk: reqDecision.risk,
                rule_ids: reqDecision.matchedRuleIds,
              });
            }
            return {
              isError: true,
              content: [
                {
                  type: "text",
                  text: `Blocked by Sudarshan: action requires approval and no approval channel is active.`,
                },
              ],
            };
          }

          const approvalReq = await this.approvalQueue.createRequest({
            agent_id: this.agentId,
            tool: name,
            redactedArgs,
            risk: reqDecision.risk,
            reasons: reqDecision.reasons,
          });

          logger.info(`Waiting for human approval on ${approvalReq.id} (timeout: ${this.approvalTimeoutSeconds}s)...`);
          const approvalStatus = await this.approvalQueue.waitForDecision(
            approvalReq.id,
            this.approvalTimeoutSeconds
          );

          if (this.auditLogger) {
            await this.auditLogger.appendEntry({
              agent_id: this.agentId,
              direction: "request",
              tool: name,
              args_redacted: redactedArgs,
              decision: "require_approval",
              approval_result: approvalStatus,
              risk: reqDecision.risk,
              rule_ids: reqDecision.matchedRuleIds,
            });
          }

          if (approvalStatus !== "approved") {
            return {
              isError: true,
              content: [
                {
                  type: "text",
                  text: `Blocked by Sudarshan: action requires approval and was denied.`,
                },
              ],
            };
          }

          logger.info(`Action ${name} (${approvalReq.id}) was approved. Forwarding unredacted call.`);
        } else {
          // Allowed or Redacted request audit
          if (this.auditLogger) {
            await this.auditLogger.appendEntry({
              agent_id: this.agentId,
              direction: "request",
              tool: name,
              args_redacted: redactedArgs,
              decision: reqDecision.action,
              approval_result: null,
              risk: reqDecision.risk,
              rule_ids: reqDecision.matchedRuleIds,
            });
          }
        }

        if (reqDecision.action === "redact") {
          forwardedArgs = redactDeep(args) as Record<string, unknown>;
        }
      }

      // 3. Forward to downstream server
      const rawResult = await this.downstreamManager.callTool(name, forwardedArgs);

      // 4. Response-side security check and redaction
      let finalResult = rawResult;
      if (this.policyEngine) {
        const responseText = JSON.stringify(rawResult);
        const respDecision = this.policyEngine.evaluate({
          tool: name,
          args: { response: rawResult },
          direction: "response",
          scannerPredicate: (type) => containsSensitivity(type, responseText),
        });

        if (respDecision.action === "redact" || containsSensitivity("secrets", responseText)) {
          logger.info(`Redacting sensitive data in response for ${name}`);
          finalResult = redactDeep(rawResult) as CallToolResult;
        } else if (respDecision.action === "block") {
          if (this.auditLogger) {
            await this.auditLogger.appendEntry({
              agent_id: this.agentId,
              direction: "response",
              tool: name,
              args_redacted: redactDeep(rawResult) as Record<string, unknown>,
              decision: "block",
              approval_result: null,
              risk: respDecision.risk,
              rule_ids: respDecision.matchedRuleIds,
            });
          }
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: `Blocked by Sudarshan on response rule: ${respDecision.reasons.join("; ")}`,
              },
            ],
          };
        }

        if (this.auditLogger) {
          await this.auditLogger.appendEntry({
            agent_id: this.agentId,
            direction: "response",
            tool: name,
            args_redacted: redactDeep(finalResult) as Record<string, unknown>,
            decision: respDecision.action,
            approval_result: null,
            risk: respDecision.risk,
            rule_ids: respDecision.matchedRuleIds,
          });
        }
      }

      return finalResult;
    } catch (err) {
      logger.error(`Exception during pipeline execution for ${name}:`, err);
      if (this.auditLogger) {
        try {
          await this.auditLogger.appendEntry({
            agent_id: this.agentId,
            direction: "request",
            tool: name,
            args_redacted: redactedArgs,
            decision: "block",
            approval_result: null,
            risk: "critical",
            rule_ids: ["internal-pipeline-error"],
          });
        } catch {
          // ignore audit failure on fatal error
        }
      }
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Blocked by Sudarshan due to internal pipeline error: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
      };
    }
  }
}
