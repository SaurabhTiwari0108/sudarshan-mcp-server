export interface AuditEntryData {
  agent_id: string;
  direction: "request" | "response";
  tool: string;
  args_redacted: Record<string, unknown>;
  decision: string;
  approval_result?: string | null;
  risk: string;
  rule_ids: string[];
}

export interface AuditEntry extends AuditEntryData {
  seq: number;
  ts: string;
  prev_hash: string;
  hash: string;
}

export interface VerificationResult {
  valid: boolean;
  totalEntries: number;
  brokenSeq?: number;
  reason?: string;
}

