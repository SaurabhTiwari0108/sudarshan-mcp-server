import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { ApprovalRequest, ApprovalStatus } from "./types.js";
import { logger } from "../utils/logger.js";

export class ApprovalQueue {
  private approvalDir: string;
  private defaultTimeoutSeconds: number;

  constructor(approvalDir: string = "./data/approvals", defaultTimeoutSeconds: number = 120) {
    this.approvalDir = path.resolve(process.cwd(), approvalDir);
    this.defaultTimeoutSeconds = defaultTimeoutSeconds;
    this.ensureDir();
  }

  private ensureDir() {
    if (!fs.existsSync(this.approvalDir)) {
      fs.mkdirSync(this.approvalDir, { recursive: true });
    }
  }

  private getFilePath(id: string): string {
    return path.join(this.approvalDir, `${id}.json`);
  }

  /**
   * Creates a new pending approval file on disk.
   */
  async createRequest(
    data: Omit<ApprovalRequest, "id" | "ts" | "status">
  ): Promise<ApprovalRequest> {
    this.ensureDir();
    const id = crypto.randomBytes(6).toString("hex");
    const request: ApprovalRequest = {
      ...data,
      id,
      ts: new Date().toISOString(),
      status: "pending",
    };

    const filePath = this.getFilePath(id);
    fs.writeFileSync(filePath, JSON.stringify(request, null, 2), "utf-8");
    logger.info(`Created pending approval request ${id} for tool ${request.tool} at ${filePath}`);
    return request;
  }

  /**
   * Retrieves an approval request by ID.
   */
  getRequest(id: string): ApprovalRequest | null {
    const filePath = this.getFilePath(id);
    if (!fs.existsSync(filePath)) {
      return null;
    }
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(content) as ApprovalRequest;
    } catch (err) {
      logger.error(`Error reading approval request ${id}:`, err);
      return null;
    }
  }

  /**
   * Resolves an approval request with status 'approved' or 'denied'.
   */
  async resolveRequest(
    id: string,
    status: "approved" | "denied",
    resolvedBy: string = "system"
  ): Promise<ApprovalRequest | null> {
    const current = this.getRequest(id);
    if (!current) {
      return null;
    }

    if (current.status !== "pending") {
      logger.warn(`Approval request ${id} is already resolved as ${current.status}`);
      return current;
    }

    current.status = status;
    current.resolvedAt = new Date().toISOString();
    current.resolvedBy = resolvedBy;

    const filePath = this.getFilePath(id);
    fs.writeFileSync(filePath, JSON.stringify(current, null, 2), "utf-8");
    logger.info(`Approval request ${id} was ${status} by ${resolvedBy}`);
    return current;
  }

  /**
   * Lists all currently pending requests.
   */
  async listPending(): Promise<ApprovalRequest[]> {
    this.ensureDir();
    const files = fs.readdirSync(this.approvalDir);
    const pending: ApprovalRequest[] = [];

    for (const f of files) {
      if (!f.endsWith(".json")) continue;
      const id = f.replace(/\.json$/, "");
      const req = this.getRequest(id);
      if (req && req.status === "pending") {
        pending.push(req);
      }
    }

    return pending;
  }

  /**
   * Waits asynchronously until the request is approved, denied, or timed out.
   * Timeout defaults to denied.
   */
  async waitForDecision(
    id: string,
    timeoutSeconds?: number
  ): Promise<ApprovalStatus> {
    const timeoutSec = timeoutSeconds ?? this.defaultTimeoutSeconds;
    const startTime = Date.now();
    const timeoutMs = timeoutSec * 1000;

    while (Date.now() - startTime < timeoutMs) {
      const req = this.getRequest(id);
      if (!req) {
        // If file disappeared, fail closed
        return "denied";
      }

      if (req.status === "approved" || req.status === "denied") {
        return req.status;
      }

      // Check every 100ms
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    // Timeout expired -> mark as denied
    logger.warn(`Approval request ${id} timed out after ${timeoutSec}s; defaulting to denied`);
    await this.resolveRequest(id, "denied", "timeout");
    return "denied";
  }
}

