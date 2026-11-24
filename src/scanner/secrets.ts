import {
  PATTERNS,
  Finding,
  validateVerhoeff,
  calculateShannonEntropy,
} from "./patterns.js";

export interface ScanOptions {
  includePii?: boolean;
}

/**
 * Scans a text string for sensitive tokens, secrets, and optionally PII.
 */
export function scanText(text: string, options: ScanOptions = {}): Finding[] {
  if (!text || typeof text !== "string") {
    return [];
  }

  const findings: Finding[] = [];
  const includePii = options.includePii ?? true;

  // Helper to add regex matches
  const matchAll = (
    regex: RegExp,
    type: string,
    category: "secrets" | "pii",
    captureIndex: number | number[] = 0,
    validator?: (val: string) => boolean
  ) => {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      let target = match[0];
      if (Array.isArray(captureIndex)) {
        for (const idx of captureIndex) {
          if (match[idx]) {
            target = match[idx];
            break;
          }
        }
      } else if (captureIndex > 0 && match[captureIndex]) {
        target = match[captureIndex];
      }

      const offsetInMatch = match[0].indexOf(target);
      const start = match.index + (offsetInMatch >= 0 ? offsetInMatch : 0);
      const end = start + target.length;

      if (!validator || validator(target)) {
        findings.push({
          type,
          category,
          start,
          end,
          value: target,
        });
      }
    }
  };

  // 1. AWS Access Keys
  matchAll(PATTERNS.awsAccessKey, "aws_access_key", "secrets", 1);

  // 2. Private Key blocks
  matchAll(PATTERNS.privateKey, "private_key", "secrets", 0);

  // 3. GitHub Tokens
  matchAll(PATTERNS.githubToken, "github_token", "secrets", 1);

  // 4. Slack Tokens
  matchAll(PATTERNS.slackToken, "slack_token", "secrets", 1);

  // 5. Google API Keys
  matchAll(PATTERNS.googleApiKey, "google_api_key", "secrets", 1);

  // 6. JWTs
  matchAll(PATTERNS.jwt, "jwt", "secrets", 1);

  // 7. Bearer Tokens
  matchAll(PATTERNS.bearerToken, "bearer_token", "secrets", 1);

  // 8. Generic assignments (secret=..., token: "...")
  matchAll(PATTERNS.genericSecretAssignment, "generic_secret", "secrets", [1, 2]);

  // 9. India PAN Cards
  matchAll(PATTERNS.panCard, "india_pan", "secrets", 1);

  // 10. India Aadhaar numbers (with Verhoeff validation)
  matchAll(
    PATTERNS.aadhaarCandidate,
    "india_aadhaar",
    "secrets",
    1,
    (val) => validateVerhoeff(val)
  );

  // 11. High-Entropy Strings adjacent to secret/key/token/password keywords
  const highEntropyPattern = /(?:key|secret|token|password|auth|credential)[^\w\r\n]{1,6}['"]?([A-Za-z0-9_\-.~+]{20,})['"]?/gi;
  highEntropyPattern.lastIndex = 0;
  let heMatch: RegExpExecArray | null;
  while ((heMatch = highEntropyPattern.exec(text)) !== null) {
    const candidate = heMatch[1];
    if (candidate) {
      const entropy = calculateShannonEntropy(candidate);
      if (entropy >= 3.6) {
        const start = heMatch.index + heMatch[0].indexOf(candidate);
        findings.push({
          type: "high_entropy_secret",
          category: "secrets",
          start,
          end: start + candidate.length,
          value: candidate,
        });
      }
    }
  }

  // 12. PII (Email & Phone)
  if (includePii) {
    matchAll(PATTERNS.email, "email", "pii", 1);
    matchAll(PATTERNS.phone, "phone", "pii", 0);
  }

  // Deduplicate and filter overlapping ranges (keep earliest and longest)
  findings.sort((a, b) => a.start - b.start || b.end - a.end);

  const nonOverlapping: Finding[] = [];
  let lastEnd = -1;

  for (const f of findings) {
    if (f.start >= lastEnd) {
      nonOverlapping.push(f);
      lastEnd = f.end;
    }
  }

  return nonOverlapping;
}

/**
 * Replaces detected sensitive findings with `[REDACTED:<type>]`.
 */
export function redactText(
  text: string,
  options: ScanOptions = {}
): { text: string; findings: Finding[] } {
  const findings = scanText(text, options);
  if (findings.length === 0) {
    return { text, findings: [] };
  }

  let result = text;
  // Apply replacements from back to front so indices remain valid
  for (let i = findings.length - 1; i >= 0; i--) {
    const f = findings[i];
    const replacement = `[REDACTED:${f.type}]`;
    result = result.substring(0, f.start) + replacement + result.substring(f.end);
  }

  return { text: result, findings };
}

/**
 * Recursively applies redaction to every string value in a JSON object or primitive.
 */
export function redactDeep(val: unknown, options: ScanOptions = {}): unknown {
  if (typeof val === "string") {
    return redactText(val, options).text;
  }
  if (Array.isArray(val)) {
    return val.map((item) => redactDeep(item, options));
  }
  if (val && typeof val === "object") {
    const output: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      output[k] = redactDeep(v, options);
    }
    return output;
  }
  return val;
}

/**
 * Predicate to check if text contains secrets or pii.
 */
export function containsSensitivity(
  type: "secrets" | "pii",
  text: string
): boolean {
  const findings = scanText(text, { includePii: type === "pii" });
  if (type === "secrets") {
    return findings.some((f) => f.category === "secrets");
  }
  if (type === "pii") {
    return findings.some((f) => f.category === "pii");
  }
  return false;
}
