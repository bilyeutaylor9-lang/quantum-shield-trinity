export function rootCauseEngine(finding) {
  const type = finding.type ?? "";
  const severity = finding.severity ?? "LOW";

  if (
    type.includes("Private Key") ||
    type.includes("Ethereum Private Key")
  ) {
    return {
      source: "Hardcoded Credential",
      reason: "Private key appears to be stored directly in source code",
      attackSurface: "Repository Access",
      exploitability: "CRITICAL",
      likelihood: "HIGH",
      impact: "Complete wallet compromise",
      remediationPriority: 1
    };
  }

  if (
    type.includes("API Key") ||
    type.includes("GitHub Token") ||
    type.includes("AWS Access Key")
  ) {
    return {
      source: "Exposed Credential",
      reason: "Authentication token detected in source control",
      attackSurface: "Repository Access",
      exploitability: "HIGH",
      likelihood: "HIGH",
      impact: "Unauthorized service access",
      remediationPriority: 2
    };
  }

  if (
    type.includes("RSA") ||
    type.includes("ECDSA")
  ) {
    return {
      source: "Legacy Cryptography",
      reason: "Cryptographic algorithm vulnerable to future quantum attacks",
      attackSurface: "Cryptographic Infrastructure",
      exploitability: "MEDIUM",
      likelihood: "MEDIUM",
      impact: "Future cryptographic compromise",
      remediationPriority: 3
    };
  }

  if (
    type.includes("Environment Secret")
  ) {
    return {
      source: "Configuration Exposure",
      reason: "Sensitive configuration appears exposed",
      attackSurface: "Application Runtime",
      exploitability: "MEDIUM",
      likelihood: "MEDIUM",
      impact: "Potential credential disclosure",
      remediationPriority: 4
    };
  }

  return {
    source: "Unknown Security Risk",
    reason: "Security-sensitive pattern detected",
    attackSurface: "Unknown",
    exploitability: severity,
    likelihood: "Unknown",
    impact: "Requires manual review",
    remediationPriority: 99
  };
}
