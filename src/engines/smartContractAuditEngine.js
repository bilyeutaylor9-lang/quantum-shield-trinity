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
      type: "Unchecked Transfer",
      regex: /\.transfer\s*\(|\.send\s*\(/g,
      severity: "MEDIUM",
      category: "Value Transfer Risk",
      recommendation:
        "Review ETH transfer logic. Prefer safer withdrawal patterns where appropriate."
    },
    {
      type: "Missing Access Control Signal",
      regex: /\bfunction\s+\w+\s*\([^)]*\)\s*(public|external)/g,
      severity: "MEDIUM",
      category: "Access Control Review",
      recommendation:
        "Review public/external functions for required access control, validation, and rate limits."
    },
    {
      type: "Owner/Admin Control",
      regex: /\bonlyOwner\b|\bDEFAULT_ADMIN_ROLE\b|\bOwnable\b|\bAccessControl\b/g,
      severity: "MEDIUM",
      category: "Centralization Risk",
      recommendation:
        "Review owner/admin privileges. Consider multisig, timelock, and least-privilege role design."
    },
    {
      type: "Upgradeable Contract",
      regex: /\bUUPSUpgradeable\b|\bInitializable\b|\bupgradeTo\b|\bupgradeToAndCall\b|\bTransparentUpgradeableProxy\b|\bimplementation\b|\bproxy\b/g,
      severity: "HIGH",
      category: "Upgradeability Risk",
      recommendation:
        "Ensure upgrade authorization, initializer safety, storage layout compatibility, and admin controls."
    },
    {
      type: "Unchecked Math Block",
      regex: /\bunchecked\s*\{/g,
      severity: "MEDIUM",
      category: "Arithmetic Review",
      recommendation:
        "Review unchecked math blocks to ensure overflow/underflow cannot create exploitable behavior."
    },
    {
      type: "Block Timestamp Dependency",
      regex: /\bblock\.timestamp\b|\bnow\b/g,
      severity: "MEDIUM",
      category: "Time Manipulation Risk",
      recommendation:
        "Avoid relying on block timestamps for critical randomness, settlement, or authorization logic."
    },
    {
      type: "Weak Randomness",
      regex: /\bblockhash\b|\bprevrandao\b|\bdifficulty\b|\bkeccak256\s*\([^)]*block/g,
      severity: "HIGH",
      category: "Randomness Risk",
      recommendation:
        "Do not use predictable block values for secure randomness. Use a trusted randomness oracle when needed."
    },
    {
      type: "Hardcoded Address",
      regex: /0x[a-fA-F0-9]{40}/g,
      severity: "MEDIUM",
      category: "Configuration Risk",
      recommendation:
        "Verify hardcoded addresses are intentional, documented, and network-specific."
    },
    {
      type: "External Token Approval",
      regex: /\bapprove\s*\(|\bsetApprovalForAll\s*\(/g,
      severity: "MEDIUM",
      category: "Token Approval Risk",
      recommendation:
        "Review approval flows for excessive allowances, approval reset issues, and user safety."
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

        if (!matches) {
          return;
        }

        if (isCommentOnlyLine(line)) {
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

  const criticalFindings = auditFindings.filter(
    finding => finding.severity === "CRITICAL"
  ).length;

  const highFindings = auditFindings.filter(
    finding => finding.severity === "HIGH"
  ).length;

  const mediumFindings = auditFindings.filter(
    finding => finding.severity === "MEDIUM"
  ).length;

  const auditScore = Math.min(
    100,
    criticalFindings * 40 +
      highFindings * 15 +
      mediumFindings * 5
  );

  return {
    engine: "Smart Contract Audit Engine",
    scannerVersion: "1.9.2",
    auditedContracts: files.filter(
      file =>
        classifyFile(file.name ?? "") === "SMART_CONTRACT" &&
        isProductionFile(file.name ?? "")
    ).length,
    skippedNonSmartContractFiles,
    skippedNonProductionFiles,
    auditScore,
    auditRiskLevel:
      auditScore >= 90
        ? "CRITICAL"
        : auditScore >= 70
        ? "HIGH"
        : auditScore >= 40
        ? "MEDIUM"
        : "LOW",
    criticalFindings,
    highFindings,
    mediumFindings,
    totalAuditFindings: auditFindings.length,
    auditFindings
  };
}

function adjustAuditSeverity(severity, smartContractContext = {}, confidence = 50) {
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

  if (smartContractContext.exploitability === "LOW" && severity === "HIGH") {
    return "MEDIUM";
  }

  return severity;
}

function calculateAuditConfidence(line = "", fileName = "", rule = {}, smartContractContext = {}) {
  const normalizedLine = line.toLowerCase();
  const normalizedFile = fileName.toLowerCase();

  let confidence = 65;

  if (rule.severity === "CRITICAL") {
    confidence += 15;
  }

  if (smartContractContext.exploitability === "CRITICAL") {
    confidence += 15;
  }

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
