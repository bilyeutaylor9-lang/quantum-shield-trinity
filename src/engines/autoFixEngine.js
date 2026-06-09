export function autoFixEngine(report = {}) {
  const findings = collectFindings(report);

  const fixes = findings.slice(0, 50).map((finding, index) => {
    const type = finding.type ?? "Security Finding";
    const currentCode = finding.context?.match ?? "";

    return {
      id: `FIX-${String(index + 1).padStart(3, "0")}`,
      type,
      severity: finding.severity ?? "MEDIUM",
      file: finding.file ?? "Unknown file",
      line: finding.line ?? "N/A",
      currentCode,
      recommendedFix: getRecommendedFix(type, currentCode),
      patchSuggestion: getPatchSuggestion(type, currentCode),
      confidence: getFixConfidence(type),
      requiresManualReview: requiresManualReview(type),
      warning:
        "AutoFix suggestions should be reviewed by a developer before production use."
    };
  });

  return {
    engine: "AutoFix Engine",
    scannerVersion: "1.0.0",
    totalFixes: fixes.length,
    safeAutoFixes: fixes.filter(fix => fix.requiresManualReview === false).length,
    manualReviewFixes: fixes.filter(fix => fix.requiresManualReview === true).length,
    fixes
  };
}

function collectFindings(report = {}) {
  return [
    ...(report.smartContractAuditReport?.auditFindings ?? []),
    ...(report.attackSurfaceReport?.attackFindings ?? []),
    ...(report.remediationReport?.remediationItems ?? []),
    ...(report.quantumReadinessReport?.findings ?? [])
  ];
}

function getRecommendedFix(type = "", currentCode = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("tx.origin")) {
    return "Replace tx.origin authorization with msg.sender and enforce explicit role-based access control.";
  }

  if (normalized.includes("hardcoded address")) {
    return "Move hardcoded addresses into constructor parameters, deployment configuration, or environment variables.";
  }

  if (normalized.includes("reentrancy")) {
    return "Apply checks-effects-interactions and add ReentrancyGuard where appropriate.";
  }

  if (normalized.includes("delegatecall")) {
    return "Avoid delegatecall unless absolutely required. Restrict target implementations and protect upgrade paths.";
  }

  if (normalized.includes("selfdestruct")) {
    return "Remove selfdestruct or protect it with strict authorization, timelocks, and emergency governance.";
  }

  if (normalized.includes("oracle")) {
    return "Validate oracle freshness, decimals, round completeness, and fallback behavior.";
  }

  if (normalized.includes("unchecked external call")) {
    return "Check the returned success value and revert when the call fails.";
  }

  if (normalized.includes("upgrade")) {
    return "Add protected upgrade authorization, initializer guards, and storage layout checks.";
  }

  if (normalized.includes("rsa")) {
    return "Inventory RSA usage and plan migration toward ML-KEM, ML-DSA, or SLH-DSA where applicable.";
  }

  if (normalized.includes("ecdsa") || normalized.includes("secp256k1")) {
    return "Inventory signature flows and prepare a post-quantum migration roadmap.";
  }

  return "Review the affected code path, reduce privileges, add validation, and re-run the scan.";
}

function getPatchSuggestion(type = "", currentCode = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("tx.origin")) {
    return currentCode
      ? currentCode.replaceAll("tx.origin", "msg.sender")
      : "require(msg.sender == owner, 'Not authorized');";
  }

  if (normalized.includes("hardcoded address")) {
    return "constructor(address configuredAddress) {\n  target = configuredAddress;\n}";
  }

  if (normalized.includes("reentrancy")) {
    return "function withdraw() external nonReentrant {\n  uint256 amount = balances[msg.sender];\n  balances[msg.sender] = 0;\n  (bool success, ) = msg.sender.call{value: amount}(\"\");\n  require(success, \"Transfer failed\");\n}";
  }

  if (normalized.includes("unchecked external call")) {
    return "(bool success, ) = target.call(data);\nrequire(success, \"External call failed\");";
  }

  if (normalized.includes("oracle")) {
    return "require(updatedAt >= block.timestamp - maxStaleness, \"Stale oracle price\");";
  }

  if (normalized.includes("delegatecall")) {
    return "require(approvedImplementations[target], \"Unapproved delegatecall target\");";
  }

  if (normalized.includes("selfdestruct")) {
    return "Remove selfdestruct or restrict it behind onlyOwner + timelock governance.";
  }

  return "Manual patch required. Review recommendation before applying changes.";
}

function getFixConfidence(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("tx.origin")) return "HIGH";
  if (normalized.includes("hardcoded address")) return "MEDIUM";
  if (normalized.includes("unchecked external call")) return "HIGH";
  if (normalized.includes("oracle")) return "MEDIUM";
  if (normalized.includes("reentrancy")) return "MEDIUM";
  if (normalized.includes("delegatecall")) return "LOW";
  if (normalized.includes("selfdestruct")) return "LOW";

  return "MEDIUM";
}

function requiresManualReview(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("tx.origin")) return false;
  if (normalized.includes("unchecked external call")) return false;

  return true;
}
