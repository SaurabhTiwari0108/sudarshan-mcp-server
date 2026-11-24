// Verhoeff checksum lookup tables
const D_TABLE = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const P_TABLE = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

export function validateVerhoeff(numStr: string): boolean {
  const clean = numStr.replace(/\D/g, "");
  if (!clean || clean.length !== 12) return false;
  if (clean.startsWith("0") || clean.startsWith("1")) return false;

  const digits = clean.split("").reverse().map(Number);
  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    c = D_TABLE[c][P_TABLE[i % 8][digits[i]]];
  }
  return c === 0;
}

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export type FindingCategory = "secrets" | "pii";

export interface Finding {
  type: string;
  category: FindingCategory;
  start: number;
  end: number;
  value: string;
}

export const PATTERNS = {
  // AWS Access Key ID
  awsAccessKey: /\b(AKIA[0-9A-Z]{16})\b/g,

  // Private Key Blocks
  privateKey: /-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+)?PRIVATE KEY-----/g,

  // JWTs (three base64url segments separated by dots)
  jwt: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,})\b/g,

  // Bearer tokens
  bearerToken: /\bBearer\s+([A-Za-z0-9_\-\.]{20,})\b/gi,

  // GitHub Personal Access Tokens (ghp_ or github_pat_)
  githubToken: /\b(ghp_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{70,})\b/g,

  // Slack tokens (xoxb-, xoxa-, xoxp-, xoxr-, xoxs-)
  slackToken: /\b(xox[baprs]-(?:[0-9A-Za-z]{10,48}-?)+)\b/g,

  // Google API keys
  googleApiKey: /\b(AIza[0-9A-Za-z\-_]{30,40})\b/g,

  // Generic key/token assignments: api_key = "...", secret: '...', password=...
  genericSecretAssignment: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*(?:['"]([^'"]{10,})['"]|([A-Za-z0-9_\-.~+]{16,}))/gi,

  // India PAN card format: 5 letters, 4 digits, 1 letter
  panCard: /\b([A-Z]{5}[0-9]{4}[A-Z])\b/g,

  // India Aadhaar candidate: 12 digits, optional spaces
  aadhaarCandidate: /\b(\d{4}\s?\d{4}\s?\d{4})\b/g,

  // Email address
  email: /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,

  // Phone numbers with strict boundary checks
  phone: /(?:\+91[\s-]?)?\b[6789]\d{9}\b|(?:\+?1[\s.-]?)?\b\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
};
