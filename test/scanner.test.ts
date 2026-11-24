import { describe, it, expect } from "vitest";
import {
  scanText,
  redactText,
  redactDeep,
  containsSensitivity,
} from "../src/scanner/secrets.js";
import { validateVerhoeff } from "../src/scanner/patterns.js";

describe("Phase 3: Scanner - True Positives", () => {
  it("detects AWS access key ID", () => {
    const text = "Connect using key AKIAIOSFODNN7EXAMPLE today";
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "aws_access_key")).toBe(true);
    const redacted = redactText(text).text;
    expect(redacted).toBe("Connect using key [REDACTED:aws_access_key] today");
  });

  it("detects private key blocks", () => {
    const text = `Certificate info:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----
End of cert`;
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "private_key")).toBe(true);
    expect(redactText(text).text).toContain("[REDACTED:private_key]");
  });

  it("detects JWT tokens", () => {
    const text =
      "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG4sPqJvqw1ZqQ1f-b5mK3s9A_g1F9k_abcdefghij";
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "jwt")).toBe(true);
    expect(redactText(text).text).toContain("[REDACTED:jwt]");
  });

  it("detects GitHub tokens", () => {
    const text = ["ghp", "_1234567890abcdefghijklmnopqrstuvwx"].join("");
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "github_token")).toBe(true);
    expect(redactText(text).text).toBe("[REDACTED:github_token]");
  });

  it("detects Slack tokens", () => {
    const text = ["Bot token: xoxb", "-123456789012-abcdefghijklmnop"].join("");
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "slack_token")).toBe(true);
    expect(redactText(text).text).toContain("[REDACTED:slack_token]");
  });

  it("detects Google API keys", () => {
    const text = ["key is AIza", "SyD-1234567890abcdefghijklmnopqrstuv"].join("");
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "google_api_key")).toBe(true);
    expect(redactText(text).text).toContain("[REDACTED:google_api_key]");
  });

  it("detects Indian PAN card numbers", () => {
    const text = "User PAN is ABCDE1234F for verification";
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "india_pan")).toBe(true);
    expect(redactText(text).text).toContain("[REDACTED:india_pan]");
  });

  it("detects valid Indian Aadhaar card numbers with Verhoeff checksum", () => {
    // 234567890124 is a mathematically valid Verhoeff 12-digit number
    expect(validateVerhoeff("2345 6789 0124")).toBe(true);

    const text = "Aadhaar: 2345 6789 0124";
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "india_aadhaar")).toBe(true);
    expect(redactText(text).text).toContain("[REDACTED:india_aadhaar]");
  });

  it("detects generic secret assignments and high entropy secrets", () => {
    const text = 'secret = "9xK#mQ8$vL2@pW7!zY4&bC1*nR"';
    const findings = scanText(text);
    expect(findings.length).toBeGreaterThan(0);
    expect(redactText(text).text).toContain("[REDACTED:");
  });

  it("detects email and phone numbers (PII)", () => {
    const text = "Contact alice@example.com or +91 9876543210";
    const findings = scanText(text, { includePii: true });
    expect(findings.some((f) => f.type === "email")).toBe(true);
    expect(findings.some((f) => f.type === "phone")).toBe(true);
  });
});

describe("Phase 3: Scanner - False Positives & Precision", () => {
  it("does NOT flag normal 12-digit numbers that fail Verhoeff as Aadhaar", () => {
    // 123456789012 is a normal 12-digit order ID / timestamp, invalid Verhoeff
    expect(validateVerhoeff("123456789012")).toBe(false);

    const text = "Order ID: 123456789012 has shipped";
    const findings = scanText(text);
    expect(findings.some((f) => f.type === "india_aadhaar")).toBe(false);
    expect(redactText(text).text).toBe(text);
  });

  it("does NOT flag low entropy or benign text as secret", () => {
    const text = "SELECT name, email FROM users WHERE active = true";
    const findings = scanText(text, { includePii: false });
    expect(findings).toHaveLength(0);
  });
});

describe("Phase 3: Deep Redaction & Sensitivity Check", () => {
  it("redacts nested JSON objects and arrays recursively", () => {
    const payload = {
      user: {
        id: 101,
        token: ["ghp", "_1234567890abcdefghijklmnopqrstuvwx"].join(""),
        aws: {
          key: "AKIAIOSFODNN7EXAMPLE",
        },
      },
      tags: ["admin", "secret=AKIAIOSFODNN7EXAMPLE"],
      validAadhaar: "2345 6789 0124",
      orderNumber: "123456789012", // should not be redacted
    };

    const redacted = redactDeep(payload) as any;
    expect(redacted.user.id).toBe(101);
    expect(redacted.user.token).toBe("[REDACTED:github_token]");
    expect(redacted.user.aws.key).toBe("[REDACTED:aws_access_key]");
    expect(redacted.tags[1]).toContain("[REDACTED:aws_access_key]");
    expect(redacted.validAadhaar).toBe("[REDACTED:india_aadhaar]");
    expect(redacted.orderNumber).toBe("123456789012");
  });

  it("checks sensitivity correctly via containsSensitivity", () => {
    expect(containsSensitivity("secrets", "Here is AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(containsSensitivity("secrets", "Here is normal text")).toBe(false);
    expect(containsSensitivity("pii", "Reach out to user@test.com")).toBe(true);
    expect(containsSensitivity("pii", "Order # 987212")).toBe(false);
  });
});

