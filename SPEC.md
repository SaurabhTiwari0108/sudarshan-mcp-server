# SPEC.md: Sudarshan MCP Gateway (Phase 1 MVP)

> Instructions for the coding agent: read this whole file before writing any code.
> Work **one phase at a time** (see "Build phases"). After each phase, run the tests,
> show me the results, and **stop and wait** for my go-ahead before starting the next phase.
> Do not add features that are not in this spec. If something is unclear, ask me.

---

## 1. What we are building

**Sudarshan MCP Gateway** is a security proxy that sits between an AI agent
(Antigravity, Claude Code, Cursor, or any MCP client) and the real MCP servers
(database, filesystem, GitHub, Slack, etc.).

```
AI agent (MCP client)  -->  Sudarshan Gateway  -->  Real MCP servers
                            (check, scan, approve, log)
```

To the agent, the gateway looks like a normal MCP **server**.
To the real tools, the gateway looks like a normal MCP **client**.
In the middle, every `tools/call` goes through a security pipeline.

### The three things the MVP must do
1. **Block or hold destructive actions** (DROP, DELETE, TRUNCATE, rm -rf, force push, writes to secret files).
2. **Stop secrets and sensitive data from leaking** (scan and redact tool arguments and tool responses).
3. **Ask a human for approval** on high and critical risk actions.

Plus: an **audit log** that records every decision and cannot be silently edited.

### Non-goals for this MVP (do NOT build these)
- No desktop app, no UI, no cloud sync, no multi-user accounts.
- No shell/terminal interception (that is a separate component later).
- No machine-learning anomaly detection.
- No browser plugin, no network proxy.

---

## 2. Tech stack

- Language: **TypeScript** (strict mode), Node.js 20+
- MCP: the **official** `@modelcontextprotocol/sdk` (check its current docs for exact API names; do not guess)
- Config parsing: `yaml`; validation: `zod`
- Glob matching: `picomatch`
- Tests: `vitest`
- Approval storage and audit: plain files (JSONL) for the MVP. No database yet.
- Transport: **stdio** for both sides (agent-facing and downstream). HTTP transport is out of scope.

---

## 3. Critical technical rules (read carefully)

1. **stdout belongs to the MCP protocol.** When the gateway runs as a stdio server, stdin and stdout carry protocol messages. Therefore:
   - NEVER `console.log` anything. All logs go to **stderr** or to log files.
   - NEVER prompt the user via stdin/stdout. Approval must use a **separate channel** (see section 8).
2. **Fail closed.** If the policy file is missing or invalid, the policy engine throws, or the scanner crashes, the decision is `block`. Never default to allow on an internal error.
3. **Never log raw secrets.** Audit entries and logs must store the redacted version of arguments, never the original secret value.
4. **Gateway config is the only place real servers are defined.** The agent only ever sees the gateway.
5. **Be deterministic and testable.** Policy engine, scanner, and audit log are pure modules with unit tests. No network calls inside them.

---

## 4. Folder structure

```
sudarshan-gateway/
  SPEC.md
  package.json
  tsconfig.json
  vitest.config.ts
  gateway.config.yaml          # downstream servers + paths
  policy.yaml                  # security rules
  src/
    index.ts                   # entry: starts gateway
    config/
      load.ts                  # load + validate both YAML files (zod)
    proxy/
      upstream.ts              # MCP server facing the agent
      downstream.ts            # MCP clients facing the real servers
      pipeline.ts              # the security pipeline for each tools/call
    policy/
      types.ts
      normalize.ts             # normalize tool name + args before matching
      engine.ts                # evaluate rules -> decision
    scanner/
      patterns.ts              # secret / PII patterns
      secrets.ts               # scan + redact functions
    approval/
      queue.ts                 # pending approvals stored on disk
      server.ts                # tiny localhost HTTP server for approve/deny
      cli.ts                   # `sudarshan-approve` command
    audit/
      log.ts                   # append-only hash-chained JSONL
      verify.ts                # verify chain integrity
  fixtures/
    mock-server/               # fake MCP server for safe testing
  test/
    policy.test.ts
    scanner.test.ts
    audit.test.ts
    pipeline.test.ts
    e2e.test.ts
```

---

## 5. Config file formats

### 5.1 `gateway.config.yaml`

```yaml
gateway:
  agent_id: "default-agent"        # identity attached to every audit entry
  audit_log_path: "./data/audit.jsonl"
  approval_dir: "./data/approvals"
  approval_http_port: 7878         # localhost only
  approval_timeout_seconds: 120    # no answer = deny

downstream:
  - name: "mock"
    command: "node"
    args: ["./fixtures/mock-server/index.js"]
    env: {}
```

Tool names exposed to the agent are prefixed with the downstream name:
`mock.db_query`, `mock.fs_write`, `mock.http_post`. Strip the prefix when forwarding.
Use `.` as separator in the exposed name if the SDK allows it; otherwise use `__` and document the choice.

### 5.2 `policy.yaml`

```yaml
version: 1
default_action: allow        # used only when no rule matches
rules:
  - id: block-destructive-sql
    description: "Destructive SQL needs a human"
    match:
      tool: "*db*"
      args_contains_any: ["DROP TABLE", "DROP DATABASE", "TRUNCATE", "DELETE FROM"]
    action: require_approval
    risk: critical

  - id: block-secret-file-writes
    match:
      tool: "*fs*write*"
      path_matches_any: ["**/.env", "**/.env.*", "**/*.pem", "**/id_rsa*"]
    action: block
    risk: critical

  - id: external-http-needs-approval
    match:
      tool: "*http*"
      domain_not_in: ["api.company.com"]
    action: require_approval
    risk: high

  - id: redact-secrets-in-responses
    match:
      tool: "*"
      direction: response
      contains: secrets
    action: redact
    risk: medium
```

### Rule fields
- `id` (required, unique), `description` (optional)
- `match.tool`: glob against the normalized tool name
- `match.args_contains_any`: case-insensitive substrings searched in the normalized, serialized arguments
- `match.path_matches_any`: globs tested against every string argument that looks like a path (keys named `path`, `file`, `filepath`, `filename`, `target`, or any string containing `/` or `\`)
- `match.domain_not_in`: extract hostnames from any URL-like string argument; the rule matches if any host is not in this list
- `match.direction`: `request` (default) or `response`
- `match.contains`: `secrets` or `pii` (uses the scanner)
- `action`: `allow` | `redact` | `require_approval` | `block`
- `risk`: `low` | `medium` | `high` | `critical`

### Decision logic
- Evaluate **all** rules, not just the first match.
- If several rules match, the **strictest action wins**: `block` > `require_approval` > `redact` > `allow`.
- If no rule matches, use `default_action`.
- Output: `{ action, risk, matchedRuleIds[], reasons[] }`.

---

## 6. Normalization (anti-bypass), `policy/normalize.ts`

Before matching, normalize so trivial tricks do not bypass rules:
- Lowercase the tool name; strip the downstream prefix for matching but keep it for logs.
- Serialize arguments to a string; also include **URL-decoded** and **base64-decoded** variants of every string value (best effort, ignore decode failures).
- Collapse repeated whitespace and strip SQL comments (`/* ... */`, `-- ...`) before keyword search.
- Unicode NFKC normalize strings.

Add tests proving that `d/**/rop table x`, `DROP   TABLE`, and a base64 of `DROP TABLE x` are all caught.

---

## 7. Scanner, `scanner/`

Functions:
- `scanText(text): Finding[]` where `Finding = { type, start, end }`
- `redactText(text): { text, findings }` which replaces matches with `[REDACTED:<type>]`
- `redactDeep(value)`: applies redaction to every string inside a JSON value

Detect at least:
- AWS access key (`AKIA[0-9A-Z]{16}`), generic `api_key=` / `secret=` / `token=` assignments
- Private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- JWTs, `Bearer <token>` headers, GitHub tokens (`ghp_`, `github_pat_`), Slack tokens (`xox[baprs]-`), Google API keys (`AIza...`)
- High-entropy strings (Shannon entropy threshold, length >= 20) when adjacent to words like key, secret, token, password
- India PII: Aadhaar (12 digits, optional spaces, validate with Verhoeff checksum), PAN (`[A-Z]{5}[0-9]{4}[A-Z]`)
- Email and phone numbers (type `pii`, only flagged when rule says `contains: pii`)

Tests must include true positives AND false positives (for example a normal 12-digit order ID that fails the Verhoeff check must NOT be flagged as Aadhaar).

---

## 8. Approval flow, `approval/`

Because stdio is used by the MCP protocol, approvals use a **separate channel**.

Flow when decision is `require_approval`:
1. Pipeline writes a pending file `approval_dir/<id>.json`: `{ id, ts, agent_id, tool, redactedArgs, risk, reasons, status: "pending" }`.
2. Pipeline **waits** (async, polling or fs.watch) until status becomes `approved` or `denied`, or until `approval_timeout_seconds` passes. Timeout means **denied**.
3. A human resolves it through either:
   - **CLI:** `sudarshan-approve list`, `sudarshan-approve allow <id>`, `sudarshan-approve deny <id>` (run in a second terminal), or
   - **Local web page:** `http://127.0.0.1:<port>/` listing pending items with Allow / Deny buttons. Bind to 127.0.0.1 only. Protect state-changing requests with a random token generated at startup and printed to stderr.
4. Only the **redacted** args are shown to the human.
5. Result is written to the audit log either way.

If `approved`, forward the **original** (unredacted) call. If `denied` or timed out, return an MCP tool result with `isError: true` and a clear message such as: `"Blocked by Sudarshan: action requires approval and was denied."`. Do not leak internal rule details beyond the rule id.

---

## 9. Audit log, `audit/`

Append-only JSONL file. One line per decision. Fields:

```json
{
  "seq": 12,
  "ts": "2026-11-13T10:15:30.123Z",
  "agent_id": "default-agent",
  "direction": "request",
  "tool": "mock.db_query",
  "args_redacted": { "...": "..." },
  "decision": "require_approval",
  "approval_result": "denied",
  "risk": "critical",
  "rule_ids": ["block-destructive-sql"],
  "prev_hash": "<hash of previous line>",
  "hash": "<sha256 of prev_hash + canonical JSON of this entry without hash>"
}
```

- The first entry uses `prev_hash = "GENESIS"`.
- `verify.ts` and a CLI command `sudarshan-audit verify` re-compute the chain and report the first broken line.
- Writes must be serialized (no two entries written at the same time) so the chain never forks.
- Tests: tamper with one line, verify must fail and point to that line.

---

## 10. The pipeline, `proxy/pipeline.ts`

For every `tools/call` from the agent:

1. Resolve which downstream server owns the tool; unknown tool -> block.
2. Normalize tool name and args.
3. **Request-side policy decision** (section 5).
4. Act on the decision:
   - `block`: audit, return error result.
   - `require_approval`: run approval flow (section 8), then continue or return error.
   - `redact`: replace sensitive values in arguments, continue.
   - `allow`: continue.
5. Forward to the downstream server.
6. **Response-side check:** run response rules and the scanner on the result; redact secrets before returning to the agent.
7. Audit both the request decision and the response decision.
8. Return the result to the agent.

Also handle `tools/list`: return the union of all downstream tools (with prefix). Optional: a policy flag to hide tools that are always blocked.

Any thrown error inside the pipeline -> audit it, return a blocked error result (fail closed).

---

## 11. Mock server for testing, `fixtures/mock-server`

A tiny MCP server exposing three **fake, harmless** tools. They must never touch real files, databases, or the network. They only record what they were called with (in memory) and return canned text.

- `db_query({ sql })` returns `"ok: executed"`. For the string `SELECT secret` return text containing a fake key like `AKIAIOSFODNN7EXAMPLE` (to test response redaction).
- `fs_write({ path, content })` returns `"ok: written"`
- `http_post({ url, body })` returns `"ok: sent"`

A test helper must expose how many times each tool was **actually executed**, so tests can prove that a blocked call never reached the downstream server.

---

## 12. Build phases (stop after each phase and show me test results)

### Phase 1: Skeleton proxy
- Project setup, strict TS, vitest.
- Upstream server + downstream client + mock server; `tools/list` and `tools/call` pass through.
- All logging to stderr.
- **Done when:** an MCP client (test script or MCP Inspector) can list and call `mock.*` tools through the gateway.

### Phase 2: Config + policy engine
- `config/load.ts` with zod validation, fail closed on invalid config.
- `normalize.ts`, `engine.ts`, rules from section 5.
- **Done when:** `policy.test.ts` passes, including strictest-wins and all normalization bypass tests from section 6.

### Phase 3: Scanner + redaction
- Section 7, request and response redaction wired into the pipeline.
- **Done when:** `scanner.test.ts` passes (true and false positives) and an e2e test shows the fake AWS key never reaches the agent.

### Phase 4: Approval flow
- Section 8: queue, CLI, localhost page, timeout.
- **Done when:** e2e test shows (a) approved call executes once, (b) denied call never executes downstream, (c) timeout denies.

### Phase 5: Audit log
- Section 9 and the verify command.
- **Done when:** `audit.test.ts` passes, including the tamper test.

### Phase 6: Hardening + demo
- Fail-closed tests (broken policy file, scanner exception).
- README with setup, how to attach to Antigravity (`~/.gemini/config/mcp_config.json`, only the gateway listed, never the real servers), and how to run the demo.
- **Done when:** the demo script below runs end to end.

---

## 13. Demo scenario (must work at the end)

1. Agent calls `mock.db_query` with `SELECT * FROM users` -> **allowed**, logged.
2. Agent calls `mock.db_query` with `DROP TABLE users` -> **held for approval**. Human denies -> agent gets an error, mock server execution count for that call is **0**.
3. Agent calls `mock.fs_write` with path `/app/.env` -> **blocked** immediately.
4. Agent calls `mock.db_query` with `SELECT secret` -> response contains a fake key -> agent receives `[REDACTED:aws_access_key]`.
5. Agent calls `mock.http_post` to `https://evil.example.com` -> **approval required**.
6. `sudarshan-audit verify` prints OK. After manually editing one line of the log, it reports the broken line.

---

## 14. Working rules for the coding agent

- Write the tests for a module **before or together with** the module.
- Keep modules small and pure; no global state except the audit writer's queue.
- No new dependencies beyond section 2 without asking me.
- Never hardcode real secrets, tokens, or personal data anywhere. Use only the fake examples in this spec.
- Do not run any destructive command on my machine. The mock server is the only thing that simulates destructive tools.
- At the end of each phase, print: what was built, test results, known gaps, and what you plan to do next. Then stop.

---

## 15. Security checklist (verify before calling the MVP done)

- [ ] Nothing is ever written to stdout except MCP protocol messages
- [ ] Invalid policy or config -> gateway refuses to start or blocks everything
- [ ] Scanner or policy crash -> call is blocked, not allowed
- [ ] Audit log never contains raw secrets
- [ ] Approval HTTP server listens on 127.0.0.1 only and requires the startup token
- [ ] A blocked or denied call is proven by tests to never reach the downstream server
- [ ] Timeout on approval means denied
- [ ] Known bypass limits are listed in the README (for example: the gateway only sees MCP calls, not direct terminal commands)