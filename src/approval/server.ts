import http from "node:http";
import crypto from "node:crypto";
import { ApprovalQueue } from "./queue.js";
import { logger } from "../utils/logger.js";

export class ApprovalServer {
  private server?: http.Server;
  private startupToken: string;

  constructor(
    private queue: ApprovalQueue,
    private port: number = 7878,
    private host: string = "127.0.0.1"
  ) {
    this.startupToken = crypto.randomBytes(16).toString("hex");
  }

  getStartupToken(): string {
    return this.startupToken;
  }

  /**
   * Directly handles an HTTP request. Exposing this allows testing
   * HTTP logic cleanly without network socket restrictions.
   */
  async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      const urlObj = new URL(req.url || "/", `http://${this.host}:${this.port}`);
      const pathname = urlObj.pathname;
      const tokenParam = urlObj.searchParams.get("token") || req.headers["x-approval-token"];

      // 1. API: List pending requests (JSON)
      if (pathname === "/api/pending" && req.method === "GET") {
        const list = await this.queue.listPending();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(list));
        return;
      }

      // 2. API: Resolve request (POST)
      if (pathname === "/api/resolve" && req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", async () => {
          try {
            const data = JSON.parse(body || "{}");
            const authTok = data.token || tokenParam;
            if (authTok !== this.startupToken) {
              res.writeHead(403, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Invalid approval token" }));
              return;
            }

            if (!data.id || (data.status !== "approved" && data.status !== "denied")) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Missing or invalid id/status" }));
              return;
            }

            const resolved = await this.queue.resolveRequest(data.id, data.status, "web");
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: true, item: resolved }));
          } catch (err) {
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: String(err) }));
          }
        });
        return;
      }

      // 3. Web UI Dashboard (GET /)
      if (pathname === "/" && req.method === "GET") {
        const pending = await this.queue.listPending();
        const tokenToUse = (tokenParam as string) || "";
        const isAuthorized = tokenToUse === this.startupToken;

        const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sudarshan Approval Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
    h1 { color: #38bdf8; }
    .card { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
    .meta { color: #94a3b8; font-size: 0.9rem; margin-bottom: 0.5rem; }
    .risk-critical { color: #f87171; font-weight: bold; }
    .risk-high { color: #fb923c; font-weight: bold; }
    .risk-medium { color: #facc15; }
    .risk-low { color: #4ade80; }
    pre { background: #090d16; padding: 1rem; border-radius: 4px; overflow-x: auto; color: #e2e8f0; }
    button { padding: 0.6rem 1.2rem; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; margin-right: 0.5rem; }
    .btn-allow { background: #22c55e; color: #022c22; }
    .btn-deny { background: #ef4444; color: #450a0a; }
    .auth-warning { background: #7f1d1d; color: #fecaca; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <h1>🛡️ Sudarshan MCP Gateway - Approval Queue</h1>
  ${
    !isAuthorized
      ? `<div class="auth-warning">⚠️ Token required to perform actions. Include ?token=${this.startupToken} in your browser URL.</div>`
      : `<p class="meta">Authenticated session. Token: <code>${this.startupToken}</code></p>`
  }

  ${
    pending.length === 0
      ? `<p>No pending approvals. All systems normal.</p>`
      : pending
          .map(
            (p) => `
    <div class="card" id="card-${p.id}">
      <div class="meta">ID: <strong>${p.id}</strong> | Timestamp: ${p.ts} | Agent: ${p.agent_id}</div>
      <div>Tool: <code>${p.tool}</code> | Risk: <span class="risk-${p.risk}">${p.risk.toUpperCase()}</span></div>
      <p><strong>Reasons:</strong> ${p.reasons.join(", ")}</p>
      <div><strong>Arguments (Redacted):</strong></div>
      <pre>${JSON.stringify(p.redactedArgs, null, 2)}</pre>
      ${
        isAuthorized
          ? `<div>
        <button class="btn-allow" onclick="resolve('${p.id}', 'approved')">Allow</button>
        <button class="btn-deny" onclick="resolve('${p.id}', 'denied')">Deny</button>
      </div>`
          : `<em>Enter valid token in URL to enable action buttons.</em>`
      }
    </div>`
          )
          .join("")
  }

  <script>
    async function resolve(id, status) {
      const res = await fetch('/api/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, status, token: '${tokenToUse}' })
      });
      if (res.ok) {
        const card = document.getElementById('card-' + id);
        if (card) card.remove();
        alert('Action ' + status + ' successfully.');
        window.location.reload();
      } else {
        const err = await res.json();
        alert('Failed: ' + err.error);
      }
    }
  </script>
</body>
</html>`;
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(html);
        return;
      }

      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found");
    } catch (err) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(`Internal Server Error: ${err}`);
    }
  }

  async start(): Promise<string> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => this.handleRequest(req, res));
      this.server.on("error", (err) => reject(err));

      // Strictly bind to 127.0.0.1
      this.server.listen(this.port, this.host, () => {
        const url = `http://${this.host}:${this.port}/?token=${this.startupToken}`;
        process.stderr.write(`[sudarshan-approval] Approval dashboard running at ${url}\n`);
        resolve(url);
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }
}
