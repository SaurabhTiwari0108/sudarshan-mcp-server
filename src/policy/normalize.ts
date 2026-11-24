// Anti-bypass normalization utilities for policy enforcement.

export function normalizeToolName(toolName: string): string {
  const nfkc = toolName.normalize("NFKC").trim().toLowerCase();
  const dotIndex = nfkc.indexOf(".");
  if (dotIndex >= 0 && dotIndex < nfkc.length - 1) {
    return nfkc.substring(dotIndex + 1);
  }
  return nfkc;
}

// Strips SQL comments and collapses whitespace.
// Returns multiple variants to catch both:
// 1. Keyword splitting: d/*comment*/rop table -> drop table (comment stripped to empty)
// 2. Token separation: DROP/*comment*/TABLE -> DROP TABLE (comment stripped to space)
export function cleanSqlAndWhitespaceVariants(text: string): string[] {
  const nfkc = text.normalize("NFKC");

  // Variant A: comments replaced with space (delimiter preservation)
  const withSpaces = nfkc
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\r\n]*/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  // Variant B: inline comments replaced with empty string (catches word-splitting)
  const withEmpty = nfkc
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/--[^\r\n]*/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  const set = new Set<string>();
  set.add(nfkc.replace(/\s+/g, " ").trim());
  set.add(withSpaces);
  set.add(withEmpty);

  return Array.from(set);
}

// Attempts to decode base64 strings if they produce valid UTF-8 text.
function tryBase64Decode(str: string): string | null {
  const trimmed = str.trim();
  // Quick sanity check for base64 characters and padding
  if (trimmed.length < 4 || trimmed.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    return null;
  }

  try {
    const buf = Buffer.from(trimmed, "base64");
    const decoded = buf.toString("utf-8");
    // Ensure decoded is valid printable / meaningful text
    if (/[\x00-\x08\x0E-\x1F]/.test(decoded)) {
      return null;
    }
    // Check if re-encoding matches original
    if (buf.toString("base64") === trimmed) {
      return decoded;
    }
    return decoded;
  } catch {
    return null;
  }
}

// Recursively collects all strings from an arbitrary object or value.
function collectAllStrings(val: unknown, collected: string[] = []): string[] {
  if (typeof val === "string") {
    collected.push(val);
  } else if (Array.isArray(val)) {
    for (const item of val) {
      collectAllStrings(item, collected);
    }
  } else if (val && typeof val === "object") {
    for (const v of Object.values(val as Record<string, unknown>)) {
      collectAllStrings(v, collected);
    }
  }
  return collected;
}

// Collects all searchable representations of args:
// - JSON serialized representation
// - Raw string values
// - URL decoded variants
// - Base64 decoded variants
// - SQL comment stripped & whitespace collapsed variants
export function getSearchableArgVariants(args: Record<string, unknown> = {}): string[] {
  const results = new Set<string>();

  // Full serialized JSON
  let serialized = "";
  try {
    serialized = JSON.stringify(args);
  } catch {
    serialized = String(args);
  }

  const rawStrings = [serialized, ...collectAllStrings(args)];

  for (const raw of rawStrings) {
    if (!raw) continue;

    // 1. Direct variants
    for (const cleaned of cleanSqlAndWhitespaceVariants(raw)) {
      results.add(cleaned.toLowerCase());
    }

    // 2. URL decode
    try {
      const urlDecoded = decodeURIComponent(raw);
      if (urlDecoded !== raw) {
        for (const cleaned of cleanSqlAndWhitespaceVariants(urlDecoded)) {
          results.add(cleaned.toLowerCase());
        }
      }
    } catch {
      // ignore malformed URI components
    }

    // 3. Base64 decode (full string)
    const base64Decoded = tryBase64Decode(raw);
    if (base64Decoded && base64Decoded !== raw) {
      for (const cleaned of cleanSqlAndWhitespaceVariants(base64Decoded)) {
        results.add(cleaned.toLowerCase());
      }
    }

    // 4. Base64 tokens inside strings (e.g. auth: <base64>)
    const base64TokenMatches = raw.match(/[A-Za-z0-9+/]{4,}={0,2}/g);
    if (base64TokenMatches) {
      for (const token of base64TokenMatches) {
        const decodedToken = tryBase64Decode(token);
        if (decodedToken && decodedToken !== token) {
          for (const cleaned of cleanSqlAndWhitespaceVariants(decodedToken)) {
            results.add(cleaned.toLowerCase());
          }
        }
      }
    }
  }

  return Array.from(results);
}

// Extracts candidate path strings from args.
// Checks keys named path, file, filepath, filename, target,
// or any string containing slashes or backslashes.
// Forward slashes are normalized for consistent glob matching.
export function extractPathStrings(val: unknown, keyName: string = ""): string[] {
  const paths: string[] = [];

  const isPathKey = /^(path|file|filepath|filename|target)$/i.test(keyName);

  if (typeof val === "string") {
    if (isPathKey || val.includes("/") || val.includes("\\")) {
      // Normalize slashes to '/'
      paths.push(val.replace(/\\/g, "/"));
    }
  } else if (Array.isArray(val)) {
    for (const item of val) {
      paths.push(...extractPathStrings(item, keyName));
    }
  } else if (val && typeof val === "object") {
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      paths.push(...extractPathStrings(v, k));
    }
  }

  return paths;
}

// Extracts hostnames from URL-like string arguments.
export function extractHostnames(val: unknown): string[] {
  const hostnames: string[] = [];
  const rawStrings = collectAllStrings(val);

  for (const str of rawStrings) {
    // Regex for URLs
    const urlMatches = str.match(/https?:\/\/[^\s/"'>)]+/gi);
    if (urlMatches) {
      for (const u of urlMatches) {
        try {
          const parsed = new URL(u);
          if (parsed.hostname) {
            hostnames.push(parsed.hostname.toLowerCase());
          }
        } catch {
          // ignore invalid URLs
        }
      }
    } else {
      // If the string itself might be a bare URL
      try {
        const parsed = new URL(str);
        if (parsed.hostname) {
          hostnames.push(parsed.hostname.toLowerCase());
        }
      } catch {
        // not a URL
      }
    }
  }

  return hostnames;
}
