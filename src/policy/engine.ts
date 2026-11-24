import picomatch from "picomatch";
import {
  Policy,
  PolicyRule,
  PolicyDecision,
  Action,
  Risk,
  EvaluationContext,
} from "./types.js";
import {
  normalizeToolName,
  getSearchableArgVariants,
  extractPathStrings,
  extractHostnames,
} from "./normalize.js";

const ACTION_RANK: Record<Action, number> = {
  allow: 1,
  redact: 2,
  require_approval: 3,
  block: 4,
};

const RISK_RANK: Record<Risk, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export class PolicyEngine {
  constructor(private policy: Policy) {}

  /**
   * Evaluate policy rules against a tool call or response context.
   * Guarantees fail-closed behavior: on any internal error, returns 'block'.
   */
  evaluate(context: EvaluationContext): PolicyDecision {
    try {
      return this.evaluateInternal(context);
    } catch (err) {
      // Fail closed
      return {
        action: "block",
        risk: "critical",
        matchedRuleIds: [],
        reasons: [
          `Fail closed: Policy engine encountered internal error: ${err instanceof Error ? err.message : String(err)}`,
        ],
      };
    }
  }

  private evaluateInternal(context: EvaluationContext): PolicyDecision {
    const direction = context.direction || "request";
    const normalizedTool = normalizeToolName(context.tool);
    const searchableVariants = getSearchableArgVariants(context.args || {});
    const pathStrings = extractPathStrings(context.args || {});
    const hostnames = extractHostnames(context.args || {});

    const matchedRules: PolicyRule[] = [];
    const reasons: string[] = [];

    for (const rule of this.policy.rules) {
      // 1. Direction match
      const ruleDirection = rule.match.direction || "request";
      if (ruleDirection !== direction) {
        continue;
      }

      // 2. Tool glob match
      if (rule.match.tool) {
        const isToolMatch = picomatch(rule.match.tool, { nocase: true });
        // Match against both normalized name and raw name
        if (!isToolMatch(normalizedTool) && !isToolMatch(context.tool.toLowerCase())) {
          continue;
        }
      }

      // 3. args_contains_any match
      if (rule.match.args_contains_any && rule.match.args_contains_any.length > 0) {
        let matchedSubstring = false;
        for (const target of rule.match.args_contains_any) {
          const targetLower = target.toLowerCase();
          for (const variant of searchableVariants) {
            if (variant.includes(targetLower)) {
              matchedSubstring = true;
              break;
            }
          }
          if (matchedSubstring) break;
        }
        if (!matchedSubstring) {
          continue;
        }
      }

      // 4. path_matches_any match
      if (rule.match.path_matches_any && rule.match.path_matches_any.length > 0) {
        let matchedPath = false;
        const isPathMatch = picomatch(rule.match.path_matches_any, {
          dot: true,
          nocase: true,
        });

        for (const rawPath of pathStrings) {
          const normalized = rawPath.replace(/\\/g, "/").replace(/^\.\//, "");
          if (isPathMatch(normalized) || isPathMatch("/" + normalized)) {
            matchedPath = true;
            break;
          }
        }

        if (!matchedPath) {
          continue;
        }
      }

      // 5. domain_not_in match
      if (rule.match.domain_not_in && rule.match.domain_not_in.length > 0) {
        // If there are no hostnames in args, this rule does not match
        if (hostnames.length === 0) {
          continue;
        }

        const allowedDomains = new Set(
          rule.match.domain_not_in.map((d) => d.toLowerCase().trim())
        );

        let hasDisallowedDomain = false;
        for (const host of hostnames) {
          if (!allowedDomains.has(host)) {
            hasDisallowedDomain = true;
            break;
          }
        }

        if (!hasDisallowedDomain) {
          continue;
        }
      }

      // 6. contains match (secrets or pii)
      if (rule.match.contains) {
        if (!context.scannerPredicate) {
          continue;
        }
        const textToScan = searchableVariants.join(" ");
        const containsMatch = context.scannerPredicate(rule.match.contains, textToScan);
        if (!containsMatch) {
          continue;
        }
      }

      // If we made it here, rule matched!
      matchedRules.push(rule);
      const desc = rule.description || `Rule ${rule.id} matched`;
      reasons.push(`[${rule.id}] ${desc}`);
    }

    // Decision logic:
    // If no rules matched -> default_action
    if (matchedRules.length === 0) {
      return {
        action: this.policy.default_action,
        risk: "low",
        matchedRuleIds: [],
        reasons: ["No policy rules matched; default action applied."],
      };
    }

    // Strictest action wins: block > require_approval > redact > allow
    let winningAction: Action = "allow";
    for (const rule of matchedRules) {
      if (ACTION_RANK[rule.action] > ACTION_RANK[winningAction]) {
        winningAction = rule.action;
      }
    }

    // Highest risk among all matched rules
    let maxRisk: Risk = "low";
    for (const rule of matchedRules) {
      if (RISK_RANK[rule.risk] > RISK_RANK[maxRisk]) {
        maxRisk = rule.risk;
      }
    }

    return {
      action: winningAction,
      risk: maxRisk,
      matchedRuleIds: matchedRules.map((r) => r.id),
      reasons,
    };
  }
}

