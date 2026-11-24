#!/usr/bin/env node
import { verifyAuditLog } from "./verify.js";

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const auditPath = args[1] || "./data/audit.jsonl";

  if (!command || command === "help") {
    console.log(`
Sudarshan Audit CLI
Usage:
  sudarshan-audit verify [auditLogPath]
`);
    process.exit(0);
  }

  if (command === "verify") {
    const result = verifyAuditLog(auditPath);
    if (result.valid) {
      console.log(`OK: Audit log integrity verified. (${result.totalEntries} entries checked)`);
      process.exit(0);
    } else {
      console.error(`FAILED: Tamper detected at seq ${result.brokenSeq || "unknown"}!`);
      console.error(`Reason: ${result.reason}`);
      process.exit(1);
    }
  }

  console.error(`Unknown command: "${command}". Run "sudarshan-audit help" for usage.`);
  process.exit(1);
}

main().catch((err) => {
  console.error("CLI error:", err);
  process.exit(1);
});

