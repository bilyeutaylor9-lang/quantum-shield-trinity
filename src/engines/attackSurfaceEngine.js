import { classifyFile } from "../utils/fileClassifier.js";
import { isProductionFile } from "../utils/isProductionFile.js";

export function attackSurfaceEngine(files = []) {
  const attackFindings = [];

  const rules = [
    {
      type: "Delegatecall Risk",
      regex: /\bdelegatecall\b/g,
      severity: "CRITICAL",
      category: "Dangerous Low-Level Call",
      recommendation:
        "Review delegatecall usage carefully. Ensure target contracts are trusted and access-controlled."
    },
    {
      type: "tx.origin Risk",
      regex: /\btx\.origin\b/g,
      severity: "HIGH",
      category: "Authentication Risk",
      recommendation:
        "Avoid tx.origin for authorization. Use msg.sender and proper access control instead."
    },
    {
      type: "Selfdestruct Risk",
      regex: /\bselfdestruct\b/g,
      severity: "HIGH",
      category: "Destructive Contract Behavior",
      recommendation:
        "Avoid selfdestruct unless absolutely necessary and protected by strict access controls."
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
      type: "Approval Risk",
      regex: /\bapprove\s*\(|\bsetApprovalForAll\s*\(/g,
      severity: "MEDIUM",
      category: "Token Approval Risk",
      recommendation:
        "Review token approval flows for excessive allowances and user safety."
    },
    {
      type: "Upgradeable Contract Risk",
      regex: /\bupgradeTo\b|\bupgradeToAndCall\b|\bUUPSUpgradeable\b|\bTransparentUpgradeableProxy\b/g,
      severity: "HIGH",
      category: "Upgradeability Risk",
      recommendation:
        "Ensure upgrade functions are access-controlled and protected by multisig or timelock."
    },
    {
      type: "Admin Centralization Risk",
      regex: /\bonlyOwner\b|\bDEFAULT_ADMIN_ROLE\b|\bAccessControl\b|\bOwnable\b/g,
      severity: "MEDIUM",
      category: "Admin Control Risk",
      recommendation:
        "Review admin privileges. Consider multisig, timelocks, and role separation."
    },
    {
      type: "Oracle Dependency Risk",
      regex: /\bAggregatorV3Interface\b|\bpriceFeed\b|\boracle\b|\bChainlink\b/g,
      severity: "MEDIUM",
      category: "Oracle Risk",
      recommendation:
        "Validate oracle freshness, decimals, fallback behavior, and manipulation resistance."
    },
    {
      type: "Bridge / Cross-Chain Risk",
      regex: /\bbridge\b|\bcrosschain\b|\bcross-chain\b|\bLayerZero\b|\bWormhole\b/g,
      severity: "HIGH",
      category: "Cross-Chain Risk",
      recommendation:
        "Review trust assumptions, message validation, replay protection, and bridge permissions."
    },
    {
      type: "Hardcoded Address Risk",
      regex: /0x[a-fA-F0-9]{40}/g,
      severity: "MEDIUM",
      category: "Hardcoded Blockchain Address",
      recommendation:
        "Verify hardcoded addresses are intentional, documented, and network-specific."
    }
  ];

  let skippedNonProductionFiles = 0;
  let skippedDocumentationFiles = 0;

  for (const file of files) {
    const fileName = file.name ?? "Unknown File";
    const fileType = classifyFile(fileName);

    if (!isProductionFile(fileName)) {
      skippedNonProductionFiles += 1;
      continue;
    }

    if (fileType === "DOCUMENTATION") {
      skippedDocumentationFiles += 1;
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

        attackFindings.push({
          file: fileName,
          line: index + 1,
          fileType,
          type: rule.type,
          severity: rule.severity,
          category: rule.category,
          recommendation: rule.recommendation,
          occurrences: matches.length,
          context: {
            match: line.trim()
          }
        });
      });
    }
  }

  const criticalAttackPaths = attackFindings.filter(
    finding => finding.severity === "CRITICAL"
  ).length;

  const highAttackPaths = attackFindings.filter(
    finding => finding.severity === "HIGH"
  ).length;

  const mediumAttackPaths = attackFindings.filter(
    finding => finding.severity === "MEDIUM"
  ).length;

  const attackSurfaceScore = Math.min(
    100,
    criticalAttackPaths * 35 +
      highAttackPaths * 15 +
      mediumAttackPaths * 5
  );

  return {
    engine: "Attack Surface Intelligence Engine",
    scannerVersion: "1.7.1",
    skippedNonProductionFiles,
    skippedDocumentationFiles,
    attackSurfaceScore,
    attackSurfaceRiskLevel:
      attackSurfaceScore >= 90
        ? "CRITICAL"
        : attackSurfaceScore >= 70
        ? "HIGH"
        : attackSurfaceScore >= 40
        ? "MEDIUM"
        : "LOW",
    totalAttackFindings: attackFindings.length,
    criticalAttackPaths,
    highAttackPaths,
    mediumAttackPaths,
    attackFindings
  };
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
