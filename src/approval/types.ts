export type ApprovalStatus = "pending" | "approved" | "denied";

export interface ApprovalRequest {
  id: string;
  ts: string;
  agent_id: string;
  tool: string;
  redactedArgs: Record<string, unknown>;
  risk: string;
  reasons: string[];
  status: ApprovalStatus;
  resolvedAt?: string;
  resolvedBy?: string;
}

