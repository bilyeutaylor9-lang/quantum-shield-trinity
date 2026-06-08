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
      type: "Unchecked External Call",
      regex: /\.call\s*\{/g,
      severity: "HIGH",
      category: "External Call Risk",
      recommendation:
        "Validate call success values and protect external calls against reentrancy."
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
      type: "Missing Access Control Review",
      regex: /\bfunction\s+\w+\s*\([^)]*\)\s*(public|external)(?![^;{]*\bonlyOwner\b)(?![^;{]*\bonlyRole\b)(?![^;{]*\brequiresAuth\b)/g,
      severity: "MEDIUM",
      category: "Access Control Review",
      recommendation:
        "Review public/external functions for required access control, input validation, and rate limits."
    },
    {
      type: "Owner/Admin Control",
      regex: /\bonlyOwner\b|\bDEFAULT_ADMIN_ROLE\b|\bOwnable\b|\bAccessControl\b/g,
      severity: "MEDIUM",
      category: "Centralization Review",
      recommendation:
        "Review admin privileges. Consider multisig, timelock, and least-privilege role design."
    },
    {
      type: "Upgradeable Contract",
      regex: /\bUUPSUpgradeable\b|\bInitializable\b|\binitializer\b|\bupgradeTo\b|\bupgradeToAndCall\b|\bTransparentUpgradeableProxy\b|\bimplementation\b|\bproxy\b/g,
      severity: "HIGH",
      category: "Upgradeability Risk",
      recommendation:
        "Ensure upgrade authorization, initializer safety, storage layout compatibility, and admin controls."
    },
    {
      type: "Oracle Usage",
      regex: /\bAggregatorV3Interface\b|\blatestRoundData\b|\bpriceFeed\b|\boracle\b|\bTWAP\b|\bgetPrice\b|\bspotPrice\b/g,
      severity: "MEDIUM",
      category: "Oracle Risk",
      recommendation:
        "Validate oracle freshness, decimals, staleness, fallback behavior, and manipulation resistance."
    },
    {
      type: "Permit Signature Usage",
      regex: /\bpermit\s*\(|\bEIP712\b|\bDOMAIN_SEPARATOR\b|\becrecover\b|\bsignature\b|\bnonces\b/g,
      severity: "MEDIUM",
      category: "Signature Risk",
      recommendation:
        "Review permit and EIP-712 signature handling for replay protection, domain separation, and nonce safety."
    },
    {
      type: "Hardcoded Address",
      regex: /0x[a-fA-F0-9]{40}/g,
      severity: "MEDIUM",
      category: "Configuration Review",
      recommendation:
        "Verify hardcoded addresses are intentional, documented, network-specific, and configurable."
    },
    {
      type: "Unbounded Loop Risk",
      regex: /\bfor\s*\(|\bwhile\s*\(/g,
      severity: "MEDIUM",
      category: "Gas Risk",
      recommendation:
        "Review loops for unbounded iteration and gas exhaustion risk."
    },
    {
      type: "Unsafe ERC20 Transfer Pattern",
      regex: /\.transfer\s*\(|\.transferFrom\s*\(|\.approve\s*\(/g,
      severity: "MEDIUM",
      category: "Token Safety Risk",
      recommendation:
        "Review ERC20 transfer, transferFrom, and approve calls. Prefer SafeERC20 wrappers where appropriate."
    },
    {
      type: "Timestamp Dependence",
      regex: /\bblock\.timestamp\b|\bnow\b/g,
      severity: "MEDIUM",
      category: "Time Manipulation Risk",
      recommendation:
        "Avoid relying on block timestamps for critical randomness, price, or settlement logic."
    },
    {
      type: "Block Number Dependence",
      regex: /\bblock\.number\b/g,
      severity: "LOW",
      category: "Chain Assumption Risk",
      recommendation:
        "Review block number assumptions across chains and execution environments."
    },
    {
      type: "Low-Level Assembly",
      regex: /\bassembly\b/g,
      severity: "HIGH",
      category: "Low-Level Code Risk",
      recommendation:
        "Review assembly blocks carefully for memory safety, storage slot correctness, and bypassed Solidity checks."
    },
    {
      type: "Randomness Risk",
      regex: /\bkeccak256\s*\([^)]*(block\.timestamp|block\.number|blockhash|msg\.sender)/g,
      severity: "HIGH",
      category: "Randomness Risk",
      recommendation:
        "Do not use block variables or msg.sender as secure randomness. Use a verifiable randomness source."
    },
    {
      type: "Legacy Solidity Version",
      regex: /pragma\s+solidity\s+(\^?0\.[0-7]\.|>=0\.[0-7]\.|<0\.8)/g,
      severity: "HIGH",
      category: "Compiler Risk",
      recommendation:
        "Review legacy Solidity compiler usage. Consider upgrading to Solidity 0.8+ with modern safety checks."
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
        if (isCommentOnlyLine(line)) return;

        const matches = [...line.matchAll(rule.regex)];

        if (matches.length === 0) return;

        const smartContractContext = smartContractContextEngine(line, fileName);
        const confidence = calculateAuditConfidence(
          line,
          fileName,
          rule,
          smartContractContext
        );

        if (confidence < 35) return;

        const severity = adjustAuditSeverity(
          rule.severity,
          smartContractContext,
          confidence,
          line,
          fileName
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
  const lowFindings = countSeverity(auditFindings, "LOW");
  const infoFindings = countSeverity(auditFindings, "INFO");

  const auditRiskScore = Math.min(
    100,
    criticalFindings * 40 +
      highFindings * 15 +
      mediumFindings * 5 +
      lowFindings * 1
  );

  const auditSecurityScore = Math.max(0, 100 - auditRiskScore);

  return {
    engine: "Smart Contract Audit Engine",
    scannerVersion: "2.1.0",
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
    lowFindings,
    infoFindings,
    totalAuditFindings: auditFindings.length,
    topAuditFindings: auditFindings.slice(0, 10),
    auditFindings
  };
}

function countSeverity(findings = [], severity = "") {
  return findings.filter(finding => finding.severity === severity).length;
}

function adjustAuditSeverity(
  severity,
  smartContractContext = {},
  confidence = 50,
  line = "",
  fileName = ""
) {
  const normalizedLine = line.toLowerCase();
  const normalizedFile = fileName.toLowerCase();

  if (smartContractContext.exploitability === "CRITICAL") {
    return "CRITICAL";
  }

  if (smartContractContext.exploitability === "HIGH" && severity === "MEDIUM") {
    return "HIGH";
  }

  if (
    severity === "MEDIUM" &&
    normalizedFile.includes("/legacy/") &&
    confidence >= 70
  ) {
    return "HIGH";
  }

  if (
    severity === "MEDIUM" &&
    normalizedLine.includes("private constant") &&
    normalizedLine.includes("0x")
  ) {
    return "HIGH";
  }

  if (confidence < 45 && severity === "CRITICAL") {
    return "HIGH";
  }

  if (confidence < 45 && severity === "HIGH") {
    return "MEDIUM";
  }

  return severity;
}

function calculateAuditConfidence(
  line = "",
  fileName = "",
  rule = {},
  smartContractContext = {}
) {
  const normalizedLine = line.toLowerCase();
  const normalizedFile = fileName.toLowerCase();

  let confidence = 60;

  if (rule.severity === "CRITICAL") confidence += 20;
  if (rule.severity === "HIGH") confidence += 12;
  if (smartContractContext.exploitability === "CRITICAL") confidence += 15;
  if (smartContractContext.exploitability === "HIGH") confidence += 10;
  if (smartContractContext.exploitability === "MEDIUM") confidence += 5;

  if (
    normalizedLine.includes("external") ||
    normalizedLine.includes("public") ||
    normalizedLine.includes("payable") ||
    normalizedLine.includes("require(") ||
    normalizedLine.includes("modifier")
  ) {
    confidence += 8;
  }

  if (
    normalizedFile.includes("/legacy/") ||
    normalizedFile.includes("vault") ||
    normalizedFile.includes("bridge") ||
    normalizedFile.includes("router") ||
    normalizedFile.includes("wallet") ||
    normalizedFile.includes("oracle") ||
    normalizedFile.includes("swap") ||
    normalizedFile.includes("uniswap")
  ) {
    confidence += 12;
  }

  if (
    normalizedLine.includes("test") ||
    normalizedLine.includes("mock") ||
    normalizedLine.includes("example") ||
    normalizedLine.includes("todo")
  ) {
    confidence -= 20;
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
