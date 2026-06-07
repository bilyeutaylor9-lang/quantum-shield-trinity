import { classifyFile } from "../utils/fileClassifier.js";
import { isProductionFile } from "../utils/isProductionFile.js";
import { smartContractContextEngine } from "./smartContractContextEngine.js";

export function smartContractAuditEngine(files = []) {
  const auditFindings = [];

  const rules = [
    {
      type: "Reentrancy Risk",
      regex: /\.call\s*\{|\bcall\s*\(/g,
      severity: "CRITICAL",
      category: "Smart Contract Vulnerability",
      recommendation:
        "Review external calls for reentrancy. Apply checks-effects-interactions and consider ReentrancyGuard."
    },
    {
      type: "tx.origin Authorization",
      regex: /\btx\.origin\b/g,
      severity: "HIGH",
      category: "Authorization Risk",
      recommendation:
        "Do not use tx.origin for authorization. Use msg.sender with proper access control."
    },
    {
      type: "Delegatecall Usage",
      regex: /\bdelegatecall\b/g,
      severity: "CRITICAL",
      category: "Low-Level Call Risk",
      recommendation:
        "Review delegatecall carefully. Ensure target contracts are trusted and upgrade paths are access-controlled."
    },
    {
      type: "Selfdestruct Usage",
      regex: /\bselfdestruct\b/g,
      severity: "HIGH",
      category: "Destructive Contract Risk",
      recommendation:
        "Avoid selfdestruct unless required. Restrict with strict access control and document the risk."
    },
    {
      type: "Unchecked External Call",
      regex: /\.call\s*\{/g,
      severity: "HIGH",
      category: "External Call Risk",
      recommendation:
        "Validate call success values and protect external calls against reentrancy."
    },
    {
      type: "Missing Access Control Signal",
      regex: /\bfunction\s+\w+\s*\([^)]*\)\s*(public|external)/g,
      severity: "INFO",
      category: "Access Control Review",
      recommendation:
        "Review public/external functions for required access control, validation, and rate limits."
    },
    {
      type: "Owner/Admin Control",
      regex: /\bonlyOwner\b|\bDEFAULT_ADMIN_ROLE\b|\bOwnable\b|\bAccessControl\b/g,
      severity: "INFO",
      category: "Centralization Review",
      recommendation:
        "Review admin privileges. Consider multisig, timelock, and least-privilege role design."
    },
    {
      type: "Upgradeable Contract",
      regex: /\bUUPSUpgradeable\b|\bInitializable\b|\bupgradeTo\b|\bupgradeToAndCall\b|\bTransparentUpgradeableProxy\b|\bimplementation\b|\bproxy\b/g,
      severity: "MEDIUM",
      category: "Upgradeability Risk",
      recommendation:
        "Ensure upgrade authorization, initializer safety, storage layout compatibility, and admin controls."
    },
    {
      type: "Oracle Usage",
      regex: /\bAggregatorV3Interface\b|\blatestRoundData\b|\bpriceFeed\b|\boracle\b/g,
      severity: "MEDIUM",
      category: "Oracle Risk",
      recommendation:
        "Validate oracle freshness, decimals, staleness, fallback behavior, and manipulation resistance."
    },
    {
      type: "Permit Signature Usage",
      regex: /\bpermit\s*\(|\bEIP712\b|\bDOMAIN_SEPARATOR\b/g,
      severity: "MEDIUM",
      category: "Signature Risk",
      recommendation:
        "Review permit and EIP-712 signature handling for replay protection, domain separation, and nonce safety."
    },
    {
      type: "Hardcoded Address",
      regex: /0x[a-fA-F0-9]{40}/g,
      severity: "INFO",
      category: "Configuration Review",
      recommendation:
        "Verify hardcoded addresses are intentional, documented, and network-specific."
    }
  ];

  let skippedNonSmartContractFiles = 0;
  let skippedNonProductionFiles = 0;

  for (const file of files) {
    const fileName = file.name ?? "Unknown File";
    const fileType = classifyFile(fileName);

    if (fileType !== "SMART_CONTRACT") {
      skippedNonSmartContractFiles += 1;
      continue;
    }

    if (!isProductionFile(fileName)) {
      skippedNonProductionFiles += 1;
      continue;
    }

    const content = file.content ?? "";
    const lines = content.split("\n");

    for (const rule of rules) {
      lines.forEach((line, index) => {
        const matches = line.match(rule.regex);

        if (!matches || isCommentOnlyLine(line)) {
          return;
        }

        const smartContractContext = smartContractContextEngine(line, fileName);
        const confidence = calculateAuditConfidence(
          line,
          fileName,
          rule,
          smartContractContext
        );

        if (confidence < 40) {
          return;
        }

        const severity = adjustAuditSeverity(
          rule.severity,
          smartContractContext,
          confidence
        );

        auditFindings.push({
          file: fileName,
          line: index + 1,
          fileType,
          type: rule.type,
          severity,
          originalSeverity: rule.severity,
          category: rule.category,
          recommendation: rule.recommendation,
          confidence,
          occurrences: matches.length,
          smartContractContext,
          context: {
            match: line.trim()
          }
        });
      });
    }
  }

  const criticalFindings = countSeverity(auditFindings, "CRITICAL");
  const highFindings = countSeverity(auditFindings, "HIGH");
  const mediumFindings = countSeverity(auditFindings, "MEDIUM");
  const infoFindings = countSeverity(auditFindings, "INFO");

  const auditRiskScore = Math.min(
    100,
    criticalFindings * 40 +
      highFindings * 15 +
      mediumFindings * 5
  );

  const auditSecurityScore = Math.max(0, 100 - auditRiskScore);

  return {
    engine: "Smart Contract Audit Engine",
    scannerVersion: "2.0.0",
    auditedContracts: files.filter(
      file =>
        classifyFile(file.name ?? "") === "SMART_CONTRACT" &&
        isProductionFile(file.name ?? "")
    ).length,
    skippedNonSmartContractFiles,
    skippedNonProductionFiles,
    auditRiskScore,
    auditSecurityScore,
    auditRiskLevel:
      auditRiskScore >= 90
        ? "CRITICAL"
        : auditRiskScore >= 70
        ? "HIGH"
        : auditRiskScore >= 40
        ? "MEDIUM"
        : "LOW",
    criticalFindings,
    highFindings,
    mediumFindings,
    infoFindings,
    totalAuditFindings: auditFindings.length,
    auditFindings
  };
}

function countSeverity(findings = [], severity = "") {
  return findings.filter(finding => finding.severity === severity).length;
}

function adjustAuditSeverity(severity, smartContractContext = {}, confidence = 50) {
  if (severity === "INFO") {
    return "INFO";
  }

  if (confidence < 50 && severity === "CRITICAL") {
    return "HIGH";
  }

  if (confidence < 50 && severity === "HIGH") {
    return "MEDIUM";
  }

  if (smartContractContext.exploitability === "CRITICAL") {
    return "CRITICAL";
  }

  if (smartContractContext.exploitability === "HIGH" && severity === "MEDIUM") {
    return "HIGH";
  }

  return severity;
}

function calculateAuditConfidence(line = "", fileName = "", rule = {}, smartContractContext = {}) {
  const normalizedLine = line.toLowerCase();
  const normalizedFile = fileName.toLowerCase();

  let confidence = 65;

  if (rule.severity === "CRITICAL") confidence += 15;
  if (smartContractContext.exploitability === "CRITICAL") confidence += 15;

  if (
    normalizedLine.includes("onlyowner") ||
    normalizedLine.includes("require(") ||
    normalizedLine.includes("modifier") ||
    normalizedLine.includes("external") ||
    normalizedLine.includes("public")
  ) {
    confidence += 10;
  }

  if (
    normalizedFile.includes("/legacy/") ||
    normalizedFile.includes("vault") ||
    normalizedFile.includes("bridge") ||
    normalizedFile.includes("router") ||
    normalizedFile.includes("wallet")
  ) {
    confidence += 10;
  }

  if (
    normalizedLine.includes("test") ||
    normalizedLine.includes("mock") ||
    normalizedLine.includes("example") ||
    normalizedLine.includes("todo")
  ) {
    confidence -= 25;
  }

  return Math.max(5, Math.min(100, confidence));
}

function isCommentOnlyLine(line = "") {
  const trimmed = line.trim();

  return (
    trimmed.startsWith("//") ||
    trimmed.startsWith("*") ||
    trimmed.startsWith("/*") ||
    trimmed.startsWith("*/")
  );
}
