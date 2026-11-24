import fs from "node:fs";
import path from "node:path";
import { AuditEntry, VerificationResult } from "./types.js";
import { computeEntryHash } from "./log.js";

/**
 * Re-computes the entire audit log hash chain and verifies integrity.
 * Reports the exact line/seq of the first tamper or error.
 */
export function verifyAuditLog(logFilePath: string): VerificationResult {
  const resolvedPath = path.resolve(process.cwd(), logFilePath);
  if (!fs.existsSync(resolvedPath)) {
    return {
      valid: false,
      totalEntries: 0,
      reason: `Audit log file does not exist at ${resolvedPath}`,
    };
  }

  const raw = fs.readFileSync(resolvedPath, "utf-8").trim();
  if (!raw) {
    return {
      valid: true,
      totalEntries: 0,
    };
  }

  const lines = raw.split(/\r?\n/).filter(Boolean);
  let expectedPrevHash = "GENESIS";
  let expectedSeq = 1;

  for (let i = 0; i < lines.length; i++) {
    const lineStr = lines[i];
    let entry: AuditEntry;

    try {
      entry = JSON.parse(lineStr);
    } catch {
      return {
        valid: false,
        totalEntries: lines.length,
        brokenSeq: expectedSeq,
        reason: `Line ${i + 1} is not valid JSON`,
      };
    }

    // 1. Verify sequence order
    if (entry.seq !== expectedSeq) {
      return {
        valid: false,
        totalEntries: lines.length,
        brokenSeq: entry.seq,
        reason: `Sequence gap or mismatch at line ${i + 1}: expected seq ${expectedSeq}, got ${entry.seq}`,
      };
    }

    // 2. Verify previous hash pointer
    if (entry.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        totalEntries: lines.length,
        brokenSeq: entry.seq,
        reason: `Broken chain pointer at seq ${entry.seq}: prev_hash does not match previous entry's hash`,
      };
    }

    // 3. Re-calculate SHA-256 hash
    const { hash: reportedHash, ...entryWithoutHash } = entry;
    const computed = computeEntryHash(entry.prev_hash, entryWithoutHash);

    if (computed !== reportedHash) {
      return {
        valid: false,
        totalEntries: lines.length,
        brokenSeq: entry.seq,
        reason: `Tamper detected at seq ${entry.seq}: recorded hash does not match recomputed SHA-256`,
      };
    }

    // Advance chain
    expectedPrevHash = entry.hash;
    expectedSeq++;
  }

  return {
    valid: true,
    totalEntries: lines.length,
  };
}

