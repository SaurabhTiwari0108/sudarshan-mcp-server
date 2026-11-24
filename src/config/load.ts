import fs from "node:fs";
import path from "node:path";
import yaml from "yaml";
import { GatewayConfig, GatewayConfigSchema } from "./types.js";
import { Policy, PolicySchema } from "../policy/types.js";
import { logger } from "../utils/logger.js";

export function loadGatewayConfig(configPath: string = "gateway.config.yaml"): GatewayConfig {
  const resolvedPath = path.resolve(process.cwd(), configPath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Gateway config file not found at: ${resolvedPath}`);
  }

  const rawContent = fs.readFileSync(resolvedPath, "utf-8");
  let parsed: unknown;
  try {
    parsed = yaml.parse(rawContent);
  } catch (err) {
    throw new Error(`Failed to parse gateway config YAML: ${err}`);
  }

  const validation = GatewayConfigSchema.safeParse(parsed);
  if (!validation.success) {
    logger.error("Invalid gateway config:", validation.error.format());
    throw new Error(`Invalid gateway configuration: ${validation.error.message}`);
  }

  return validation.data;
}

export function loadPolicyConfig(policyPath: string = "policy.yaml"): Policy {
  const resolvedPath = path.resolve(process.cwd(), policyPath);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(`Policy file not found at: ${resolvedPath}`);
  }

  const rawContent = fs.readFileSync(resolvedPath, "utf-8");
  let parsed: unknown;
  try {
    parsed = yaml.parse(rawContent);
  } catch (err) {
    throw new Error(`Failed to parse policy YAML: ${err}`);
  }

  const validation = PolicySchema.safeParse(parsed);
  if (!validation.success) {
    logger.error("Invalid policy config:", validation.error.format());
    throw new Error(`Invalid policy configuration: ${validation.error.message}`);
  }

  // Ensure rule IDs are unique
  const ruleIds = new Set<string>();
  for (const rule of validation.data.rules) {
    if (ruleIds.has(rule.id)) {
      throw new Error(`Duplicate rule id found in policy: "${rule.id}"`);
    }
    ruleIds.add(rule.id);
  }

  return validation.data;
}
