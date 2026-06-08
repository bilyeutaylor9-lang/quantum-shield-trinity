export function attackPathGeneratorEngine(report = {}) {
  const findings = collectFindings(report);

  const attackPaths = findings.slice(0, 25).map((finding, index) => {
    const type = finding.type ?? "Security Finding";

    return {
      id: `PATH-${String(index + 1).padStart(3, "0")}`,
      title: buildTitle(type),
      severity: finding.severity ?? "MEDIUM",
      file: finding.file ?? "Unknown file",
      line: finding.line ?? "N/A",
      entryPoint: getEntryPoint(type),
      attackChain: getAttackChain(type),
      potentialImpact: getImpact(type),
      likelihood: getLikelihood(finding.severity),
      difficulty: getDifficulty(type),
      recommendedDefense: getDefense(type),
      sourceFinding: type
    };
  });

  return {
    engine: "Attack Path Generator Engine",
    scannerVersion: "1.0.0",
    totalAttackPaths: attackPaths.length,
    criticalAttackPaths: countSeverity(attackPaths, "CRITICAL"),
    highAttackPaths: countSeverity(attackPaths, "HIGH"),
    mediumAttackPaths: countSeverity(attackPaths, "MEDIUM"),
    attackPaths
  };
}

function collectFindings(report = {}) {
  return [
    ...(report.smartContractAuditReport?.auditFindings ?? []),
    ...(report.attackSurfaceReport?.attackFindings ?? []),
    ...(report.exploitSimulationReport?.simulations ?? []),
    ...(report.remediationReport?.remediationItems ?? []),
    ...(report.autoFixReport?.fixes ?? [])
  ];
}

function buildTitle(type = "") {
  return `${type} Attack Path`;
}

function getEntryPoint(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("reentrancy")) return "External payable or withdrawal function";
  if (normalized.includes("delegatecall")) return "Low-level delegatecall execution path";
  if (normalized.includes("tx.origin")) return "Authorization check using tx.origin";
  if (normalized.includes("selfdestruct")) return "Destructive contract function";
  if (normalized.includes("oracle")) return "Price or oracle-dependent execution path";
  if (normalized.includes("hardcoded address")) return "Network-specific address dependency";
  if (normalized.includes("upgrade")) return "Upgrade or proxy administration path";

  return "Public or externally reachable code path";
}

function getAttackChain(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("reentrancy")) {
    return [
      "Attacker deploys a malicious contract.",
      "Malicious contract calls the vulnerable withdrawal or external-call function.",
      "Target contract sends value or calls attacker-controlled code.",
      "Attacker re-enters before state is safely finalized.",
      "Funds or state may be manipulated repeatedly."
    ];
  }

  if (normalized.includes("delegatecall")) {
    return [
      "Attacker influences or reaches delegatecall target selection.",
      "Contract executes external code in its own storage context.",
      "Malicious implementation modifies storage or permissions.",
      "Owner/admin state or funds may be compromised."
    ];
  }

  if (normalized.includes("tx.origin")) {
    return [
      "Victim is tricked into calling a malicious contract.",
      "Malicious contract calls the vulnerable target contract.",
      "tx.origin still equals the victim address.",
      "Authorization check passes incorrectly.",
      "Sensitive action executes under attacker-controlled flow."
    ];
  }

  if (normalized.includes("selfdestruct")) {
    return [
      "Attacker reaches a destructive execution path.",
      "Authorization or guard conditions are bypassed or misconfigured.",
      "selfdestruct is triggered.",
      "Contract functionality or funds may be permanently disrupted."
    ];
  }

  if (normalized.includes("oracle")) {
    return [
      "Attacker identifies oracle-dependent logic.",
      "Oracle value becomes stale, manipulated, or incorrectly scaled.",
      "Contract executes using unsafe price data.",
      "Funds, collateral, swaps, or settlement logic may be impacted."
    ];
  }

  if (normalized.includes("hardcoded address")) {
    return [
      "Contract relies on a fixed address.",
      "Deployment occurs on a different network or changed environment.",
      "Address points to the wrong contract, stale dependency, or attacker-controlled service.",
      "Execution routes through an unintended dependency."
    ];
  }

  if (normalized.includes("upgrade")) {
    return [
      "Attacker targets proxy or upgrade control.",
      "Weak admin control or initializer issue is abused.",
      "Implementation is changed or initialized incorrectly.",
      "Contract behavior, storage, or permissions are compromised."
    ];
  }

  return [
    "Attacker identifies an exposed code path.",
    "Input, configuration, or dependency behavior is manipulated.",
    "Contract or application enters an unsafe state.",
    "Security, reliability, or operational impact may occur."
  ];
}

function getImpact(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("reentrancy")) return "Potential fund drain or repeated state manipulation.";
  if (normalized.includes("delegatecall")) return "Potential storage takeover, privilege escalation, or arbitrary logic execution.";
  if (normalized.includes("tx.origin")) return "Potential authorization bypass through phishing-style contract calls.";
  if (normalized.includes("selfdestruct")) return "Potential permanent contract disruption or forced asset movement.";
  if (normalized.includes("oracle")) return "Potential incorrect pricing, liquidation, swap, or settlement behavior.";
  if (normalized.includes("hardcoded address")) return "Potential network migration failure or dependency misrouting.";
  if (normalized.includes("upgrade")) return "Potential implementation takeover or unsafe contract upgrade.";

  return "Potential security, reliability, or operational risk.";
}

function getLikelihood(severity = "") {
  const normalized = String(severity).toUpperCase();

  if (normalized === "CRITICAL") return "High";
  if (normalized === "HIGH") return "Medium-High";
  if (normalized === "MEDIUM") return "Medium";
  return "Low";
}

function getDifficulty(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("tx.origin")) return "Low";
  if (normalized.includes("hardcoded address")) return "Low";
  if (normalized.includes("reentrancy")) return "Medium";
  if (normalized.includes("oracle")) return "Medium";
  if (normalized.includes("delegatecall")) return "Medium-High";
  if (normalized.includes("upgrade")) return "Medium-High";

  return "Medium";
}

function getDefense(type = "") {
  const normalized = type.toLowerCase();

  if (normalized.includes("reentrancy")) {
    return "Use checks-effects-interactions, update state before external calls, and add ReentrancyGuard.";
  }

  if (normalized.includes("delegatecall")) {
    return "Restrict delegatecall targets, require trusted implementations, and protect upgrade controls.";
  }

  if (normalized.includes("tx.origin")) {
    return "Replace tx.origin with msg.sender and enforce explicit role-based access control.";
  }

  if (normalized.includes("selfdestruct")) {
    return "Remove selfdestruct or protect it with strict authorization, timelocks, and emergency governance.";
  }

  if (normalized.includes("oracle")) {
    return "Validate freshness, decimals, round completeness, fallback sources, and manipulation resistance.";
  }

  if (normalized.includes("hardcoded address")) {
    return "Move addresses into deployment configuration, constructor parameters, or verified registry contracts.";
  }

  if (normalized.includes("upgrade")) {
    return "Use initializer guards, access-controlled upgrades, multisig ownership, timelocks, and storage layout checks.";
  }

  return "Review the affected path, add validation, reduce privileges, and re-run the scan.";
}

function countSeverity(items = [], severity = "") {
  return items.filter(item => item.severity === severity).length;
}
