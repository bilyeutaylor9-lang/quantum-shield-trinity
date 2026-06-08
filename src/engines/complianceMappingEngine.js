export function complianceMappingEngine(report = {}) {
  const findings = collectFindings(report);

  const mappedFindings = findings.slice(0, 100).map((finding, index) => {
    const type = finding.type ?? finding.sourceFinding ?? "Security Finding";
    const mapping = getComplianceMapping(type);

    return {
      id: `MAP-${String(index + 1).padStart(3, "0")}`,
      type,
      severity: finding.severity ?? "MEDIUM",
      file: finding.file ?? "Unknown file",
      line: finding.line ?? "N/A",
      cwe: mapping.cwe,
      owaspSmartContractTop10: mapping.owaspSmartContractTop10,
      owaspWebTop10: mapping.owaspWebTop10,
      category: mapping.category,
      explanation: mapping.explanation,
      recommendedControl: mapping.recommendedControl
    };
  });

  return {
    engine: "CWE and OWASP Mapping Engine",
    scannerVersion: "1.0.0",
    totalMappedFindings: mappedFindings.length,
    mappedFindings
  };
}

function collectFindings(report = {}) {
  return [
    ...(report.smartContractAuditReport?.auditFindings ?? []),
    ...(report.attackSurfaceReport?.attackFindings ?? []),
    ...(report.exploitSimulationReport?.simulations ?? []),
    ...(report.remediationReport?.remediationItems ?? []),
    ...(report.autoFixReport?.fixes ?? []),
    ...(report.attackPathReport?.attackPaths ?? []),
    ...(report.quantumReadinessReport?.findings ?? [])
  ];
}

function getComplianceMapping(type = "") {
  const normalized = String(type).toLowerCase();

  if (normalized.includes("reentrancy")) {
    return map(
      "CWE-841",
      "SC05: Reentrancy",
      "A01: Broken Access Control",
      "Reentrancy / State Consistency",
      "Reentrancy allows external calls to re-enter contract logic before state is finalized.",
      "Use checks-effects-interactions, update state before external calls, and apply ReentrancyGuard."
    );
  }

  if (normalized.includes("tx.origin")) {
    return map(
      "CWE-346",
      "SC01: Access Control Vulnerabilities",
      "A01: Broken Access Control",
      "Authorization",
      "tx.origin based authorization can be abused through phishing-style contract calls.",
      "Use msg.sender and explicit role-based or owner-based access control."
    );
  }

  if (normalized.includes("delegatecall")) {
    return map(
      "CWE-829",
      "SC06: Unchecked External Calls",
      "A08: Software and Data Integrity Failures",
      "Untrusted Code Execution",
      "delegatecall executes external code in the storage context of the calling contract.",
      "Restrict delegatecall targets, validate implementations, and protect upgrade paths."
    );
  }

  if (normalized.includes("selfdestruct")) {
    return map(
      "CWE-284",
      "SC01: Access Control Vulnerabilities",
      "A01: Broken Access Control",
      "Destructive Functionality",
      "selfdestruct can permanently disrupt contract behavior if exposed or improperly controlled.",
      "Remove selfdestruct where possible or protect it with strict authorization and timelocks."
    );
  }

  if (normalized.includes("unchecked external call")) {
    return map(
      "CWE-252",
      "SC06: Unchecked External Calls",
      "A04: Insecure Design",
      "Unchecked Return Value",
      "Unchecked low-level calls can fail silently and create inconsistent contract state.",
      "Check success return values and revert on failure."
    );
  }

  if (normalized.includes("hardcoded address")) {
    return map(
      "CWE-547",
      "SC10: Denial of Service / Operational Risk",
      "A05: Security Misconfiguration",
      "Configuration Risk",
      "Hardcoded addresses create hidden network assumptions and migration risk.",
      "Move addresses into constructor parameters, deployment config, or verified registries."
    );
  }

  if (normalized.includes("oracle")) {
    return map(
      "CWE-345",
      "SC02: Price Oracle Manipulation",
      "A04: Insecure Design",
      "Oracle Manipulation",
      "Oracle-dependent logic can fail when price data is stale, manipulated, or incorrectly scaled.",
      "Validate freshness, decimals, round completeness, fallback sources, and manipulation resistance."
    );
  }

  if (normalized.includes("upgrade")) {
    return map(
      "CWE-269",
      "SC03: Logic Errors",
      "A01: Broken Access Control",
      "Upgradeability / Privilege Risk",
      "Upgradeable contracts can be compromised through weak admin controls or unsafe initialization.",
      "Use initializer guards, multisig ownership, timelocks, protected upgrade authorization, and storage layout checks."
    );
  }

  if (normalized.includes("timestamp")) {
    return map(
      "CWE-829",
      "SC03: Logic Errors",
      "A04: Insecure Design",
      "Timestamp Dependence",
      "Block timestamps can be influenced within limits and should not control critical logic.",
      "Avoid timestamp-based randomness or critical settlement rules."
    );
  }

  if (normalized.includes("randomness")) {
    return map(
      "CWE-330",
      "SC09: Insecure Randomness",
      "A02: Cryptographic Failures",
      "Randomness",
      "Weak randomness can allow attackers or validators to predict outcomes.",
      "Use verifiable randomness or commit-reveal schemes."
    );
  }

  if (normalized.includes("assembly")) {
    return map(
      "CWE-119",
      "SC03: Logic Errors",
      "A04: Insecure Design",
      "Low-Level Code",
      "Assembly bypasses many Solidity safety guarantees and can introduce memory or storage corruption.",
      "Review assembly manually, add tests, and document storage/memory assumptions."
    );
  }

  if (normalized.includes("rsa")) {
    return map(
      "CWE-327",
      "SC08: Cryptographic Weakness",
      "A02: Cryptographic Failures",
      "Quantum-Vulnerable Cryptography",
      "RSA is vulnerable to future cryptographically relevant quantum computers.",
      "Inventory RSA usage and plan migration toward ML-KEM, ML-DSA, or SLH-DSA where applicable."
    );
  }

  if (
    normalized.includes("ecdsa") ||
    normalized.includes("ecc") ||
    normalized.includes("secp256k1")
  ) {
    return map(
      "CWE-327",
      "SC08: Cryptographic Weakness",
      "A02: Cryptographic Failures",
      "Quantum-Vulnerable Signatures",
      "ECDSA and elliptic-curve signatures are vulnerable to future quantum attacks.",
      "Inventory signature flows and prepare a post-quantum or hybrid-signature migration roadmap."
    );
  }

  if (normalized.includes("sha-1") || normalized.includes("sha1")) {
    return map(
      "CWE-328",
      "SC08: Cryptographic Weakness",
      "A02: Cryptographic Failures",
      "Weak Hashing",
      "SHA-1 is considered weak and should not be used for security-sensitive integrity guarantees.",
      "Replace SHA-1 with stronger hashing algorithms."
    );
  }

  if (normalized.includes("dependency")) {
    return map(
      "CWE-1104",
      "SC07: Vulnerable Dependencies",
      "A06: Vulnerable and Outdated Components",
      "Dependency Risk",
      "Outdated or vulnerable dependencies can introduce supply-chain exposure.",
      "Update, replace, pin, or review dependencies before production deployment."
    );
  }

  return map(
    "CWE-693",
    "SC03: Logic Errors",
    "A04: Insecure Design",
    "General Security Control",
    "This finding indicates a security control or design weakness that should be reviewed.",
    "Review the affected code, reduce privileges, add validation, and re-run the scan."
  );
}

function map(
  cwe,
  owaspSmartContractTop10,
  owaspWebTop10,
  category,
  explanation,
  recommendedControl
) {
  return {
    cwe,
    owaspSmartContractTop10,
    owaspWebTop10,
    category,
    explanation,
    recommendedControl
  };
}
