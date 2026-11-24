# Sudarshan MCP Gateway

> **Security proxy that sits between an AI agent (Antigravity, Claude Code, Cursor, or any MCP client) and real MCP servers.**

```
AI agent (MCP client)  -->  Sudarshan Gateway  -->  Real MCP servers
                            (check, scan, approve, log)
```

To the agent, Sudarshan looks like a standard MCP **server**.  
To the real downstream tools, Sudarshan looks like a standard MCP **client**.  
In the middle, every `tools/list` and `tools/call` goes through an uncompromising security pipeline.

---

## Key Capabilities

1. **Blocks or Holds Destructive Actions**: Intercepts destructive SQL (`DROP`, `DELETE`, `TRUNCATE`), secret file writes (`.env`, `.pem`, `id_rsa`), and unauthorized external HTTP destinations.
2. **Secret & Sensitive Data Protection**: High-speed scanner detects AWS keys, JWTs, Bearer tokens, GitHub/Slack/Google tokens, Shannon high-entropy keys, and Indian PII (Aadhaar with Verhoeff checksum algorithm, PAN). Automatically redacts tool responses before they can leak to the agent.
3. **Out-of-Band Human Approval**: High- and critical-risk actions are held in a separate channel (Localhost HTTP Dashboard or CLI) so stdout protocol messages are never polluted. Timeout strictly defaults to denied.
4. **Tamper-Evident Hash-Chained Audit Log**: Append-only JSONL audit log chained with SHA-256 hashes (`GENESIS` to entry $N$). Any manual alteration or line deletion is instantly detected.
5. **Fail-Closed Architecture**: Any internal error, missing configuration, or scanner exception fails closed to `block`.

---

## Project Structure

```
sudarshan/
  SPEC.md                      # Specification document
  gateway.config.yaml          # Downstream servers + paths
  policy.yaml                  # Security rules & thresholds
  fixtures/
    mock-server/               # Safe in-memory MCP server for tests
  src/
    index.ts                   # Gateway main entry point (stdio)
    config/
      types.ts                 # Zod configuration schemas
      load.ts                  # YAML loaders with fail-closed validation
    proxy/
      downstream.ts            # MCP clients connecting to real servers
      upstream.ts              # Upstream MCP server facing agent
      pipeline.ts              # Central security pipeline
    policy/
      types.ts                 # Policy and rule type definitions
      normalize.ts             # Anti-bypass normalization & decoding
      engine.ts                # Deterministic policy engine
    scanner/
      patterns.ts              # Secret, PII & Verhoeff algorithms
      secrets.ts               # Scanner and deep redaction engine
    approval/
      types.ts                 # Approval types
      queue.ts                 # Disk-backed approval queue
      server.ts                # 127.0.0.1 HTTP approval dashboard
      cli.ts                   # sudarshan-approve CLI
    audit/
      types.ts                 # Audit entry types
      log.ts                   # Serialized hash-chained JSONL writer
      verify.ts                # Audit integrity verification
  test/
    mock-server.test.ts        # Standalone mock server tests
    pipeline.test.ts           # Pipeline & pass-through tests
    policy.test.ts             # Anti-bypass & rule engine tests
    scanner.test.ts            # Scanner true/false positive tests
    approval.test.ts           # Approval queue & HTTP dashboard tests
    audit.test.ts              # Hash chain & tampering tests
    hardening.test.ts          # Fail-closed guarantee tests
    e2e.test.ts                # Real child process stdio tests
    demo.test.ts               # Section 13 demo scenario runner
```

---

## Quickstart

### 1. Install Dependencies
```bash
npm install
```

### 2. Build TypeScript
```bash
npm run build
```

### 3. Run All Tests
```bash
npm test
```
*Executes all 70 tests across 9 test suites covering units, anti-bypass, redaction, approvals, audit integrity, and E2E stdio child processes.*

### 4. Run the Full Security Demo
```bash
npm run demo
```
*Demonstrates all 6 core requirements from Section 13 of the SPEC.*

---

## Attaching to Google Antigravity / MCP Clients

The agent must **only see the Sudarshan Gateway**. Real servers are configured solely inside `gateway.config.yaml`.

In your Antigravity MCP configuration (`~/.gemini/config/mcp_config.json`):

```json
{
  "mcpServers": {
    "sudarshan": {
      "command": "node",
      "args": ["C:/Users/CHOTACODERR/Desktop/sudarshan/dist/index.js"],
      "env": {}
    }
  }
}
```

*Note: For live development, you can use `npx tsx C:/Users/CHOTACODERR/Desktop/sudarshan/src/index.ts`.*

---

## Operating Approvals & Audits

### Approval Channels
When an action requires approval, it is placed in `./data/approvals/<id>.json`:

1. **Web Dashboard**:
   Open the localhost URL printed to stderr on startup:
   `http://127.0.0.1:7878/?token=<startupToken>`
   Click **Allow** or **Deny** for each request.

2. **CLI**:
   Run in a separate terminal:
   ```bash
   # List pending actions
   node ./bin/sudarshan-approve.js list

   # Approve an action
   node ./bin/sudarshan-approve.js allow <id>

   # Deny an action
   node ./bin/sudarshan-approve.js deny <id>
   ```

### Audit Log Integrity Verification
Verify that the audit log has not been modified or tampered with:
```bash
node ./bin/sudarshan-audit.js verify ./data/audit.jsonl
```

---

## Security Checklist & Guarantees

- [x] **Zero stdout Pollution**: All gateway logging strictly writes to `stderr`. `stdout` belongs exclusively to standard MCP JSON-RPC protocol frames.
- [x] **Fail-Closed by Design**: Missing config files, malformed YAML, or unexpected internal scanner exceptions immediately trigger `block` decisions.
- [x] **Zero Raw Secret Leakage**: Arguments stored in the audit log and displayed to humans in approval queues are deeply redacted (`[REDACTED:<type>]`).
- [x] **Localhost Only**: The approval HTTP dashboard strictly binds to `127.0.0.1` and requires a random startup token for state changes.
- [x] **Verified Zero Downstream Leakage**: Tests prove that blocked or denied calls never reach downstream execution (execution count is 0).
- [x] **Timeout Means Denied**: Any pending approval that is not answered within `approval_timeout_seconds` automatically defaults to denied.
- [x] **Known Bypass Limits Documented**:
  - *Sudarshan intercepts MCP tool calls (`tools/call`)*. Direct shell / terminal commands (e.g. `bash`, `powershell`, or direct process spawns by agents with local shell access) are not intercepted by the MCP protocol layer.
  - Sub-second timing attacks on local files are mitigated by filesystem locks and serialized write queues.

