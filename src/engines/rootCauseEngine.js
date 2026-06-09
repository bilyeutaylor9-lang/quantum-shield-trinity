// src/engines/rootCauseEngine.js

const normalize = (value = "") => String(value ?? "").toLowerCase();

const normalizeSeverity = (value = "LOW") => {
  const severity = normalize(value);

  if (severity === "critical") return "CRITICAL";
  if (severity === "high") return "HIGH";
  if (severity === "medium") return "MEDIUM";
  if (severity === "low") return "LOW";

  return "LOW";
};

const includesAny = (text = "", patterns = []) =>
  patterns.some((pattern) => text.includes(pattern));

export function rootCauseEngine(finding = {}) {
  const type = normalize(finding.type);
  const title = normalize(finding.title);
  const description = normalize(finding.description);
  const category = normalize(finding.category);
  const ruleId = normalize(finding.ruleId);
  const file = normalize(finding.file ?? finding.path);
  const raw = normalize(JSON.stringify(finding));

  const combined = [
    type,
    title,
    description,
    category,
    ruleId,
    file,
    raw
  ].join(" ");

  const severity = normalizeSeverity(
    finding.severity ??
      finding.riskLevel ??
      finding.exploitability ??
      "LOW"
  );

  if (
    includesAny(combined, [
      "private key",
      "ethereum private key",
      "hardcoded private",
      "wallet private",
      "mnemonic",
      "seed phrase",
      "secret recovery phrase"
    ])
  ) {
    return {
      source: "Hardcoded Credential",
      reason: "Private key, mnemonic, or wallet recovery material appears to be stored directly in source code.",
      attackSurface: "Repository Access",
      exploitability: "CRITICAL",
      likelihood: "HIGH",
      impact: "Complete wallet or signing-key compromise",
      remediationPriority: 1,
      recommendation: "Remove the exposed key immediately, rotate the affected wallet/key, and move secrets into a managed secret store."
    };
  }

  if (
    includesAny(combined, [
      "api key",
      "github token",
      "ghp_",
      "github_pat",
      "aws access key",
      "aws_secret_access_key",
      "secret key",
      "bearer token",
      "authorization token",
      "access token",
      "refresh token"
    ])
  ) {
    return {
      source: "Exposed Credential",
      reason: "Authentication token or service credential appears to be exposed in source control or application code.",
      attackSurface: "Repository Access",
      exploitability: "HIGH",
      likelihood: "HIGH",
      impact: "Unauthorized service access, privilege escalation, or supply-chain compromise",
      remediationPriority: 2,
      recommendation: "Revoke and rotate the credential, remove it from history if necessary, and enforce secret scanning in CI."
    };
  }

  if (
    includesAny(combined, [
      "command injection",
      "exec(",
      "child_process",
      "shell",
      "spawn",
      "user input to execution",
      "remote code execution",
      "rce"
    ])
  ) {
    return {
      source: "Unsafe Command Execution",
      reason: "User-controlled input may reach command execution or shell-sensitive logic.",
      attackSurface: "Application Runtime",
      exploitability: "CRITICAL",
      likelihood: "MEDIUM",
      impact: "Remote code execution or server compromise",
      remediationPriority: 3,
      recommendation: "Remove shell execution where possible, use strict allowlists, validate inputs, and prefer non-shell APIs."
    };
  }

  if (
    includesAny(combined, [
      "ssrf",
      "server-side request forgery",
      "fetch",
      "axios",
      "request url",
      "internal url",
      "metadata service"
    ])
  ) {
    return {
      source: "Untrusted Network Request",
      reason: "Application logic may allow user-controlled URLs or requests to internal resources.",
      attackSurface: "Network Boundary",
      exploitability: "HIGH",
      likelihood: "MEDIUM",
      impact: "Internal service exposure, metadata theft, or cloud credential compromise",
      remediationPriority: 4,
      recommendation: "Block internal IP ranges, validate destinations, disable redirects where needed, and use outbound request allowlists."
    };
  }

  if (
    includesAny(combined, [
      "sql injection",
      "sqli",
      "raw query",
      "query concatenation",
      "database query",
      "user input to database"
    ])
  ) {
    return {
      source: "Unsafe Database Query Construction",
      reason: "User input may be reaching database queries without strong parameterization.",
      attackSurface: "Database Layer",
      exploitability: "HIGH",
      likelihood: "MEDIUM",
      impact: "Data theft, data modification, or authentication bypass",
      remediationPriority: 5,
      recommendation: "Use parameterized queries or ORM-safe bindings and avoid string concatenation in database calls."
    };
  }

  if (
    includesAny(combined, [
      "xss",
      "cross site scripting",
      "dangerouslysetinnerhtml",
      "innerhtml",
      "html injection",
      "script injection"
    ])
  ) {
    return {
      source: "Unsafe HTML Rendering",
      reason: "Untrusted content may be rendered into HTML or script-sensitive contexts.",
      attackSurface: "Client-Side Web Surface",
      exploitability: "MEDIUM",
      likelihood: "MEDIUM",
      impact: "Session theft, malicious script execution, or user impersonation",
      remediationPriority: 6,
      recommendation: "Sanitize untrusted HTML, avoid unsafe rendering APIs, and apply Content Security Policy protections."
    };
  }

  if (
    includesAny(combined, [
      "path traversal",
      "../",
      "directory traversal",
      "file read",
      "user input to file",
      "fs.readfile",
      "fs.writefile"
    ])
  ) {
    return {
      source: "Unsafe File Path Handling",
      reason: "User-controlled input may influence filesystem paths.",
      attackSurface: "Filesystem Boundary",
      exploitability: "HIGH",
      likelihood: "MEDIUM",
      impact: "Unauthorized file read/write or sensitive file disclosure",
      remediationPriority: 7,
      recommendation: "Normalize paths, enforce base directories, reject traversal sequences, and use strict filename allowlists."
    };
  }

  if (
    includesAny(combined, [
      "rsa",
      "ecdsa",
      "secp256k1",
      "elliptic",
      "legacy cryptography",
      "quantum vulnerable"
    ])
  ) {
    return {
      source: "Legacy Cryptography",
      reason: "Cryptographic algorithm or signing scheme may be vulnerable to future quantum attacks.",
      attackSurface: "Cryptographic Infrastructure",
      exploitability: "MEDIUM",
      likelihood: "MEDIUM",
      impact: "Future cryptographic compromise or signature forgery risk",
      remediationPriority: 8,
      recommendation: "Inventory affected cryptography and plan migration toward post-quantum-safe algorithms where applicable."
    };
  }

  if (
    includesAny(combined, [
      "environment secret",
      ".env",
      "process.env",
      "configuration exposure",
      "config secret"
    ])
  ) {
    return {
      source: "Configuration Exposure",
      reason: "Sensitive configuration or environment secret handling requires review.",
      attackSurface: "Application Runtime",
      exploitability: "MEDIUM",
      likelihood: "MEDIUM",
      impact: "Potential credential disclosure or runtime misconfiguration",
      remediationPriority: 9,
      recommendation: "Move sensitive values to a managed secret store and ensure environment files are excluded from source control."
    };
  }

  if (
    includesAny(combined, [
      "ci",
      "github actions",
      "workflow",
      "deployment",
      "npm publish",
      "supply chain",
      "package script"
    ])
  ) {
    return {
      source: "CI/CD Supply Chain Exposure",
      reason: "Build, workflow, or deployment logic may expose sensitive automation paths.",
      attackSurface: "CI/CD Pipeline",
      exploitability: "HIGH",
      likelihood: "MEDIUM",
      impact: "Unauthorized deployment, package compromise, or pipeline abuse",
      remediationPriority: 10,
      recommendation: "Restrict workflow permissions, protect deployment environments, pin actions, and require approval for release jobs."
    };
  }

  return {
    source: "Unknown Security Risk",
    reason: "Security-sensitive pattern detected and requires manual review.",
    attackSurface: "Unknown",
    exploitability: severity,
    likelihood: "UNKNOWN",
    impact: "Requires manual review",
    remediationPriority: 99,
    recommendation: "Review the finding manually and classify it into a specific root-cause category."
  };
}

export default rootCauseEngine;
