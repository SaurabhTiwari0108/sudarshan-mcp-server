#!/usr/bin/env node
import { ApprovalQueue } from "./queue.js";

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  // Optional approval dir argument or default
  const approvalDir = args[2] && !args[2].startsWith("-") ? args[2] : "./data/approvals";
  const queue = new ApprovalQueue(approvalDir);

  if (!command || command === "help") {
    console.log(`
Sudarshan Approval CLI
Usage:
  sudarshan-approve list [approvalDir]
  sudarshan-approve allow <id> [approvalDir]
  sudarshan-approve deny <id> [approvalDir]
`);
    process.exit(0);
  }

  if (command === "list") {
    const pending = await queue.listPending();
    if (pending.length === 0) {
      console.log("No pending approvals.");
      return;
    }

    console.log(`\nFound ${pending.length} pending approval request(s):\n`);
    for (const p of pending) {
      console.log(`ID:      ${p.id}`);
      console.log(`Tool:    ${p.tool}`);
      console.log(`Risk:    ${p.risk}`);
      console.log(`Reasons: ${p.reasons.join(", ")}`);
      console.log(`Args:    ${JSON.stringify(p.redactedArgs)}`);
      console.log(`Time:    ${p.ts}`);
      console.log("-".repeat(50));
    }
    return;
  }

  if (command === "allow" || command === "approve") {
    const id = args[1];
    if (!id) {
      console.error("Error: Missing approval ID. Example: sudarshan-approve allow <id>");
      process.exit(1);
    }
    const resolved = await queue.resolveRequest(id, "approved", "cli");
    if (!resolved) {
      console.error(`Error: Request ${id} not found.`);
      process.exit(1);
    }
    console.log(`Approved action ${id} (${resolved.tool}).`);
    return;
  }

  if (command === "deny" || command === "reject") {
    const id = args[1];
    if (!id) {
      console.error("Error: Missing approval ID. Example: sudarshan-approve deny <id>");
      process.exit(1);
    }
    const resolved = await queue.resolveRequest(id, "denied", "cli");
    if (!resolved) {
      console.error(`Error: Request ${id} not found.`);
      process.exit(1);
    }
    console.log(`Denied action ${id} (${resolved.tool}).`);
    return;
  }

  console.error(`Unknown command: "${command}". Run "sudarshan-approve help" for usage.`);
  process.exit(1);
}

main().catch((err) => {
  console.error("CLI error:", err);
  process.exit(1);
});

