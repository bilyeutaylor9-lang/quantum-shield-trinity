export function dependencyRiskEngine(packageJson = {}) {
  const dependencies = {
    ...(packageJson.dependencies ?? {}),
    ...(packageJson.devDependencies ?? {})
  };

  const findings = [];
  const dependencyNames = Object.keys(dependencies);

  for (const dependencyName of dependencyNames) {
    const version = dependencies[dependencyName];

    const finding = analyzeDependency(dependencyName, version);

    if (finding) {
      findings.push(finding);
    }
  }

  const criticalFindings = findings.filter(
    finding => finding.severity === "CRITICAL"
  ).length;

  const highFindings = findings.filter(
    finding => finding.severity === "HIGH"
  ).length;

  const mediumFindings = findings.filter(
    finding => finding.severity === "MEDIUM"
  ).length;

  const lowFindings = findings.filter(
    finding => finding.severity === "LOW"
  ).length;

  const riskScore = Math.min(
    100,
    criticalFindings * 30 +
      highFindings * 15 +
      mediumFindings * 6 +
      lowFindings * 2
  );

  return {
    engine: "Dependency Risk Engine",
    scannerVersion: "1.0.0",
    scannedDependencies: dependencyNames.length,
    riskScore,
    riskLevel: calculateRiskLevel(riskScore),
    summary: buildSummary({
      dependencyCount: dependencyNames.length,
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      riskScore
    }),
    findings,
    counts: {
      criticalFindings,
      highFindings,
      mediumFindings,
      lowFindings,
      totalFindings: findings.length
    }
  };
}

function analyzeDependency(name = "", version = "") {
  const normalizedName = name.toLowerCase();
  const normalizedVersion = String(version).toLowerCase();

  const riskyPackages = [
    {
      match: "web3",
      severity: "MEDIUM",
      category: "Blockchain Dependency",
      reason: "Web3 dependency detected. Review wallet, signing, and provider flows."
    },
    {
      match: "ethers",
      severity: "MEDIUM",
      category: "Blockchain Dependency",
      reason: "Ethers dependency detected. Review signing, wallet, and private key handling."
    },
    {
      match: "hardhat",
      severity: "LOW",
      category: "Smart Contract Tooling",
      reason: "Hardhat detected. Ensure private keys and RPC URLs are not stored in config files."
    },
    {
      match: "truffle",
      severity: "LOW",
      category: "Smart Contract Tooling",
      reason: "Truffle detected. Review deployment secrets and network configuration."
    },
    {
      match: "solc",
      severity: "LOW",
      category: "Smart Contract Compiler",
      reason: "Solidity compiler detected. Verify compiler version and optimizer settings."
    },
    {
      match: "jsonwebtoken",
      severity: "HIGH",
      category: "Authentication Dependency",
      reason: "JWT library detected. Review token signing secrets, expiration, and algorithm controls."
    },
    {
      match: "express",
      severity: "LOW",
      category: "Web Server Dependency",
      reason: "Express detected. Review middleware, authentication, and input validation."
    },
    {
      match: "axios",
      severity: "LOW",
      category: "Network Dependency",
      reason: "Axios detected. Review outbound request destinations and SSRF protections."
    },
    {
      match: "request",
      severity: "HIGH",
      category: "Deprecated Dependency",
      reason: "Request is deprecated. Replace with a maintained HTTP client."
    },
    {
      match: "lodash",
      severity: "LOW",
      category: "Utility Dependency",
      reason: "Lodash detected. Ensure version is current and avoid unsafe template usage."
    },
    {
      match: "moment",
      severity: "LOW",
      category: "Legacy Dependency",
      reason: "Moment detected. Consider lighter maintained alternatives where appropriate."
    }
  ];

  for (const rule of riskyPackages) {
    if (normalizedName === rule.match || normalizedName.includes(rule.match)) {
      return {
        dependency: name,
        version,
        severity: rule.severity,
        category: rule.category,
        reason: rule.reason,
        recommendation: buildRecommendation(rule),
        confidence: 80
      };
    }
  }

  if (looksPinnedToOldMajor(normalizedVersion)) {
    return {
      dependency: name,
      version,
      severity: "MEDIUM",
      category: "Potentially Old Dependency",
      reason: "Dependency appears pinned to an old major version.",
      recommendation:
        "Review changelog, security advisories, and upgrade path before production use.",
      confidence: 55
    };
  }

  if (usesLooseVersionRange(normalizedVersion)) {
    return {
      dependency: name,
      version,
      severity: "LOW",
      category: "Loose Version Range",
      reason: "Dependency uses a loose version range.",
      recommendation:
        "Consider pinning versions or using lockfiles for reproducible builds.",
      confidence: 50
    };
  }

  return null;
}

function buildRecommendation(rule = {}) {
  if (rule.severity === "HIGH") {
    return "Prioritize review before production. Confirm patch status, configuration safety, and secure usage patterns.";
  }

  if (rule.severity === "MEDIUM") {
    return "Review dependency usage, update to a maintained version, and document security assumptions.";
  }

  return "Keep dependency updated and verify safe configuration.";
}

function looksPinnedToOldMajor(version = "") {
  return (
    version.startsWith("0.") ||
    version.startsWith("^0.") ||
    version.startsWith("~0.") ||
    version.startsWith("1.") ||
    version.startsWith("^1.") ||
    version.startsWith("~1.")
  );
}

function usesLooseVersionRange(version = "") {
  return (
    version.includes("*") ||
    version.includes(">") ||
    version.includes("<") ||
    version.includes("latest")
  );
}

function calculateRiskLevel(score = 0) {
  if (score >= 90) return "CRITICAL";
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  return "LOW";
}

function buildSummary({
  dependencyCount,
  criticalFindings,
  highFindings,
  mediumFindings,
  lowFindings,
  riskScore
}) {
  return `Scanned ${dependencyCount} dependencies. Risk Score: ${riskScore}/100. Findings: ${criticalFindings} critical, ${highFindings} high, ${mediumFindings} medium, ${lowFindings} low.`;
}
