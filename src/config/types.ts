import { z } from "zod";

export const DownstreamServerConfigSchema = z.object({
  name: z.string().min(1),
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  env: z.record(z.string()).default({}),
});

export type DownstreamServerConfig = z.infer<typeof DownstreamServerConfigSchema>;

export const GatewaySettingsSchema = z.object({
  agent_id: z.string().default("default-agent"),
  audit_log_path: z.string().default("./data/audit.jsonl"),
  approval_dir: z.string().default("./data/approvals"),
  approval_http_port: z.number().int().positive().default(7878),
  approval_timeout_seconds: z.number().int().positive().default(120),
});

export type GatewaySettings = z.infer<typeof GatewaySettingsSchema>;

export const GatewayConfigSchema = z.object({
  gateway: GatewaySettingsSchema.default({}),
  downstream: z.array(DownstreamServerConfigSchema).min(1),
});

export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;

