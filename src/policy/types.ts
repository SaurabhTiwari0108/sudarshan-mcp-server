import { z } from "zod";

export const ActionSchema = z.enum(["allow", "redact", "require_approval", "block"]);
export type Action = z.infer<typeof ActionSchema>;

export const RiskSchema = z.enum(["low", "medium", "high", "critical"]);
export type Risk = z.infer<typeof RiskSchema>;

export const DirectionSchema = z.enum(["request", "response"]);
export type Direction = z.infer<typeof DirectionSchema>;

export const ContainsSchema = z.enum(["secrets", "pii"]);
export type Contains = z.infer<typeof ContainsSchema>;

export const RuleMatchSchema = z.object({
  tool: z.string().optional(),
  args_contains_any: z.array(z.string()).optional(),
  path_matches_any: z.array(z.string()).optional(),
  domain_not_in: z.array(z.string()).optional(),
  direction: DirectionSchema.default("request"),
  contains: ContainsSchema.optional(),
});
export type RuleMatch = z.infer<typeof RuleMatchSchema>;

export const PolicyRuleSchema = z.object({
  id: z.string().min(1),
  description: z.string().optional(),
  match: RuleMatchSchema,
  action: ActionSchema,
  risk: RiskSchema,
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySchema = z.object({
  version: z.number().int().positive().default(1),
  default_action: ActionSchema.default("allow"),
  rules: z.array(PolicyRuleSchema).default([]),
});
export type Policy = z.infer<typeof PolicySchema>;

export interface PolicyDecision {
  action: Action;
  risk: Risk;
  matchedRuleIds: string[];
  reasons: string[];
}

export interface EvaluationContext {
  tool: string; // raw or prefixed name
  args?: Record<string, unknown>;
  response?: unknown;
  direction?: Direction;
  scannerPredicate?: (type: "secrets" | "pii", text: string) => boolean;
}

