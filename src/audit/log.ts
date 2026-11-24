import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { AuditEntry, AuditEntryData } from "./types.js";
import { logger } from "../utils/logger.js";

/**
 * Produces deterministic canonical JSON with recursively sorted keys.
 */
export function canonicalJson(val: unknown): string {
  if (val === null || typeof val !== "object") {
    return JSON.stringify(val);
  }

  if (Array.isArray(val)) {
    return "[" + val.map((item) => canonicalJson(item)).join(",") + "]";
  }

  const obj = val as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  return "{" + pairs.join(",") + "}";
}

/**
 * Computes the SHA-256 hash of (prev_hash + canonical JSON of entry without 'hash').
 */
export function computeEntryHash(
  prevHash: string,
  entryWithoutHash: Omit<AuditEntry, "hash">
): string {
  const canonical = canonicalJson(entryWithoutHash);
  return crypto
    .createHash("sha256")
    .update(prevHash + canonical)
    .digest("hex");
}

export class AuditLogger {
  private logFilePath: string;
  private lastSeq: number = 0;
  private lastHash: string = "GENESIS";
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(logFilePath: string = "./data/audit.jsonl") {
    this.logFilePath = path.resolve(process.cwd(), logFilePath);
    this.init();
  }

  private init() {
    const dir = path.dirname(this.logFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    if (fs.existsSync(this.logFilePath)) {
      const content = fs.readFileSync(this.logFilePath, "utf-8").trim();
      if (content) {
        const lines = content.split(/\r?\n/).filter(Boolean);
        if (lines.length > 0) {
          try {
            const lastEntry = JSON.parse(lines[lines.length - 1]) as AuditEntry;
            this.lastSeq = lastEntry.seq;
            this.lastHash = lastEntry.hash;
          } catch (err) {
            logger.error("Failed to parse last audit log line, starting fresh chain", err);
          }
        }
      }
    }
  }

  /**
   * Appends an entry to the audit log in a strictly serialized fashion.
   * Guarantees that hash chain never forks even under high concurrency.
   */
  async appendEntry(data: AuditEntryData): Promise<AuditEntry> {
    return new Promise((resolve, reject) => {
      this.writeQueue = this.writeQueue
        .then(() => {
          const seq = ++this.lastSeq;
          const ts = new Date().toISOString();
          const prev_hash = this.lastHash;

          const entryWithoutHash: Omit<AuditEntry, "hash"> = {
            seq,
            ts,
            agent_id: data.agent_id,
            direction: data.direction,
            tool: data.tool,
            args_redacted: data.args_redacted,
            decision: data.decision,
            approval_result: data.approval_result ?? null,
            risk: data.risk,
            rule_ids: data.rule_ids,
            prev_hash,
          };

          const hash = computeEntryHash(prev_hash, entryWithoutHash);
          const fullEntry: AuditEntry = {
            ...entryWithoutHash,
            hash,
          };

          this.lastHash = hash;

          fs.appendFileSync(this.logFilePath, JSON.stringify(fullEntry) + "\n", "utf-8");
          resolve(fullEntry);
        })
        .catch((err) => {
          logger.error("Error writing audit log:", err);
          reject(err);
        });
    });
  }

  getLastHash(): string {
    return this.lastHash;
  }

  getLastSeq(): number {
    return this.lastSeq;
  }
}

