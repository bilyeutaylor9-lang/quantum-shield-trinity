export function dependencyIntelligenceEngine(files = []) {
  const dependencyFindings = [];

  for (const file of files) {
    const fileName = file.name ?? "";
    const content = file.content ?? "";

    if (fileName.endsWith("package.json")) {
      analyzePackageJson(fileName, content, dependencyFindings);
    }

    if (fileName.endsWith("foundry.toml")) {
      analyzeFoundryToml(fileName, content, dependencyFindings);
    }

    if (
      fileName.endsWith("package-lock.json") ||
      fileName.endsWith("yarn.lock") ||
      fileName.endsWith("pnpm-lock.yaml")
    ) {
      analyzeLockFile(fileName, content, dependencyFindings);
    }
  }

  const highRiskDependencies = dependencyFindings.filter(
    finding => finding.severity === "HIGH"
  ).length;

  const mediumRiskDependencies = dependencyFindings.filter(
    finding => finding.severity === "MEDIUM"
  ).length;

  return {
    engine: "Dependency Intelligence Engine",
    scannerVersion: "1.6.0",
    scannedDependencyFiles: files.filter(file =>
      isDependencyFile(file.name ?? "")
    ).length,
    dependencyFindings,
    highRiskDependencies,
    mediumRiskDependencies,
    dependencyRiskLevel:
      highRiskDependencies > 0
        ? "HIGH"
        : mediumRiskDependencies > 0
        ? "MEDIUM"
        : "LOW"
  };
}

function analyzePackageJson(fileName, content, findings) {
  try {
    const parsed = JSON.parse(content);

    const dependencies = {
      ...(parsed.dependencies ?? {}),
      ...(parsed.devDependencies ?? {})
    };

    for (const [name, version] of Object.entries(dependencies)) {
      const finding = evaluateDependency(name, version, fileName);

      if (finding) {
        findings.push(finding);
      }
    }
  } catch {
    findings.push({
      file: fileName,
      dependency: "package.json",
      severity: "MEDIUM",
      category: "Dependency Parsing",
      risk: "Unable to parse package.json.",
      recommendation: "Validate package.json formatting."
    });
  }
}

function analyzeFoundryToml(fileName, content, findings) {
  const knownPatterns = [
    {
      match: "openzeppelin",
      dependency: "OpenZeppelin Contracts",
      severity: "MEDIUM",
      risk:
        "OpenZeppelin contracts may include ECDSA or cryptographic utilities that require review for quantum migration planning.",
      recommendation:
        "Review ECDSA usage, signature verification, and cryptographic dependencies."
    },
    {
      match: "forge-std",
      dependency: "Forge Standard Library",
      severity: "LOW",
      risk:
        "Forge standard library detected. This is usually development tooling, not production risk.",
      recommendation:
        "Ensure test and tooling dependencies are separated from production deployment logic."
    }
  ];

  for (const pattern of knownPatterns) {
    if (content.toLowerCase().includes(pattern.match)) {
      findings.push({
        file: fileName,
        dependency: pattern.dependency,
        severity: pattern.severity,
        category: "Smart Contract Dependency",
        risk: pattern.risk,
        recommendation: pattern.recommendation
      });
    }
  }
}

function analyzeLockFile(fileName, content, findings) {
  const lockPatterns = [
    {
      match: "elliptic",
      dependency: "elliptic",
      severity: "HIGH",
      risk:
        "Elliptic curve cryptography dependency detected. This may indicate ECDSA/secp256k1 usage.",
      recommendation:
        "Inventory signing flows and prepare a quantum migration roadmap."
    },
    {
      match: "crypto-js",
      dependency: "crypto-js",
      severity: "MEDIUM",
      risk:
        "Crypto utility dependency detected. Review usage for SHA1, MD5, or legacy cryptography.",
      recommendation:
        "Audit hashing and encryption usage."
    },
    {
      match: "jsonwebtoken",
      dependency: "jsonwebtoken",
      severity: "MEDIUM",
      risk:
        "JWT dependency detected. Verify secret handling and signing configuration.",
      recommendation:
        "Ensure JWT secrets are stored securely and signing algorithms are modern."
    }
  ];

  for (const pattern of lockPatterns) {
    if (content.toLowerCase().includes(pattern.match)) {
      findings.push({
        file: fileName,
        dependency: pattern.dependency,
        severity: pattern.severity,
        category: "Lockfile Dependency Signal",
        risk: pattern.risk,
        recommendation: pattern.recommendation
      });
    }
  }
}

function evaluateDependency(name, version, fileName) {
  const normalized = name.toLowerCase();

  const dependencyRules = {
    elliptic: {
      severity: "HIGH",
      category: "Quantum-Sensitive Dependency",
      risk:
        "Elliptic curve cryptography dependency detected. May indicate ECDSA/secp256k1 signing.",
      recommendation:
        "Inventory signing flows and prepare for ML-DSA or SLH-DSA migration planning."
    },
    ethers: {
      severity: "MEDIUM",
      category: "Blockchain Dependency",
      risk:
        "Ethers.js detected. Wallet signing and ECDSA-based flows may require future quantum migration planning.",
      recommendation:
        "Review wallet signing, message signing, and key management flows."
    },
    web3: {
      severity: "MEDIUM",
      category: "Blockchain Dependency",
      risk:
        "Web3 dependency detected. Review wallet and signing flows for crypto-agility.",
      recommendation:
        "Prepare signing abstractions and wallet security guidance."
    },
    "crypto-js": {
      severity: "MEDIUM",
      category: "Crypto Utility Dependency",
      risk:
        "Crypto utility library detected. Review for SHA1, MD5, or weak crypto usage.",
      recommendation:
        "Audit actual crypto usage and replace legacy algorithms."
    },
    jsonwebtoken: {
      severity: "MEDIUM",
      category: "Authentication Dependency",
      risk:
        "JWT library detected. Secret handling and signing algorithm configuration should be reviewed.",
      recommendation:
        "Use strong secrets, rotate exposed credentials, and avoid weak signing algorithms."
    }
  };

  const rule = dependencyRules[normalized];

  if (!rule) {
    return null;
  }

  return {
    file: fileName,
    dependency: name,
    version,
    severity: rule.severity,
    category: rule.category,
    risk: rule.risk,
    recommendation: rule.recommendation
  };
}

function isDependencyFile(fileName = "") {
  return (
    fileName.endsWith("package.json") ||
    fileName.endsWith("package-lock.json") ||
    fileName.endsWith("yarn.lock") ||
    fileName.endsWith("pnpm-lock.yaml") ||
    fileName.endsWith("foundry.toml")
  );
}
