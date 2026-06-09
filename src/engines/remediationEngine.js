export function remediationEngine(report = {}) {
  const findings = collectFindings(report);

  const remediationItems = findings.slice(0, 25).map((finding, index) => {
    const type = finding.type ?? finding.finding ?? "Security Finding";
    const severity = finding.severity ?? "MEDIUM";

    return {
      id: `REM-${String(index + 1).padStart(3, "0")}`,
      severity,
      type,
      file: finding.file ?? "Unknown file",
      line: finding.line ?? "N/A",
      whyItMatters: getWhyItMatters(type),
      howToFix: getHowToFix(type),
      exampleFix: getExampleFix(type),
      priority: getPriority(severity),
      estimatedEffort: getEstimatedEffort(severity)
    };
  });

  return {
    engine: "Remediation Engine",
    scannerVersion: "1.0.0",
    totalRemediationItems: remediationItems.length,
    remediationItems
  };
}

function collectFindings(report = {}) {
  return [
    ...(report.smartContractAuditReport?.auditFindings ?? []),
    ...(report.attackSurfaceReport?.attackFindings ?? []),
    ...(report.dependencyRiskReport?.dependencyFindings ?? []),
    ...(report.assessmentReport?.criticalFindings ?? []),
    ...(report.assessmentReport?.highFindings ?? []),
    ...(report.assessmentReport?.mediumFindings ?? [])
  ];
}

function getWhyItMatters(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("reentrancy")) {
    return "External calls before state updates can allow attackers to repeatedly enter the contract and drain funds or manipulate state.";
  }

  if (normalized.includes("delegatecall")) {
    return "delegatecall executes code in the context of the calling contract, which can expose storage, permissions, and upgrade paths to serious compromise.";
  }

  if (normalized.includes("tx.origin")) {
    return "tx.origin authorization can be bypassed through phishing-style contract calls and should not be used for access control.";
  }

  if (normalized.includes("selfdestruct")) {
    return "selfdestruct can permanently disable contract functionality or force ETH transfers, creating destructive operational risk.";
  }

  if (normalized.includes("hardcoded address")) {
    return "Hardcoded addresses can break deployments across networks and create hidden trust assumptions.";
  }

  if (normalized.includes("oracle")) {
    return "Oracle values can be stale, manipulated, or unavailable, which can cause incorrect contract execution.";
  }

  if (normalized.includes("upgrade")) {
    return "Upgradeable contracts introduce governance and storage-layout risks that can compromise user funds if not controlled.";
  }

  if (normalized.includes("dependency")) {
    return "Third-party packages can introduce supply-chain vulnerabilities, outdated code, or untrusted execution paths.";
  }

  return "This finding may increase security, reliability, operational, or migration risk and should be reviewed before production use.";
}

function getHowToFix(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("reentrancy")) {
    return "Move state updates before external calls, use checks-effects-interactions, and add a ReentrancyGuard where appropriate.";
  }

  if (normalized.includes("delegatecall")) {
    return "Avoid delegatecall unless absolutely required. Restrict targets, validate implementation addresses, and protect upgrade functions.";
  }

  if (normalized.includes("tx.origin")) {
    return "Replace tx.origin authorization with msg.sender and enforce explicit role-based or owner-based access control.";
  }

  if (normalized.includes("selfdestruct")) {
    return "Remove selfdestruct where possible or protect it with strict authorization, timelocks, and documented emergency procedures.";
  }

  if (normalized.includes("hardcoded address")) {
    return "Move hardcoded addresses into deployment configuration, environment variables, or constructor parameters.";
  }

  if (normalized.includes("oracle")) {
    return "Validate oracle freshness, decimals, round completeness, fallback sources, and manipulation resistance.";
  }

  if (normalized.includes("upgrade")) {
    return "Use protected upgrade authorization, initializer guards, storage layout checks, and multisig/timelock governance.";
  }

  if (normalized.includes("dependency")) {
    return "Update or replace risky dependencies and pin versions where possible.";
  }

  return "Review the affected code path, add validation, reduce privileges, improve error handling, and re-run the scan after remediation.";
}

function getExampleFix(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("tx.origin")) {
    return "require(msg.sender == owner, 'Not authorized');";
  }

  if (normalized.includes("hardcoded address")) {
    return "constructor(address configuredAddress) { target = configuredAddress; }";
  }

  if (normalized.includes("reentrancy")) {
    return "function withdraw() external nonReentrant { balances[msg.sender] = 0; payable(msg.sender).call{value: amount}(''); }";
  }

  if (normalized.includes("oracle")) {
    return "require(updatedAt >= block.timestamp - maxStaleness, 'Stale oracle price');";
  }

  return "Apply the recommended fix pattern and validate with tests before deployment.";
}

function getPriority(severity = "") {
  const normalized = String(severity).toUpperCase();

  if (normalized === "CRITICAL") return "Immediate";
  if (normalized === "HIGH") return "High";
  if (normalized === "MEDIUM") return "Medium";
  return "Low";
}

function getEstimatedEffort(severity = "") {
  const normalized = String(severity).toUpperCase();

  if (normalized === "CRITICAL") return "1-3 days";
  if (normalized === "HIGH") return "4-8 hours";
  if (normalized === "MEDIUM") return "1-4 hours";
  return "Under 1 hour";
}
