import fs from "fs";

export function markdownReportGenerator(
  report = {},
  outputPath = "quantum-shield-report.md"
) {
  const findings = report.copilotGuidance ?? report.findings ?? [];
  const dependencyReport = report.dependencyReport ?? {};
  const attackSurfaceReport = report.attackSurfaceReport ?? {};
  const smartContractAuditReport = report.smartContractAuditReport ?? {};

  const markdown = `# Quantum Shield Trinity Report

## Executive Summary

**Repository Risk Level:** ${report.repositoryRiskLevel ?? "UNKNOWN"}

**Security Score:** ${report.securityScore ?? 0}/100

**Security Grade:** ${report.securityGrade ?? "N/A"}

**Raw Risk Score:** ${report.score ?? 0}/100

**Files Scanned:** ${report.scannedFiles ?? 0}

**Critical Findings:** ${report.criticalFindings ?? 0}

**High Findings:** ${report.highFindings ?? 0}

**Medium Findings:** ${report.mediumFindings ?? 0}

---

## Dependency Intelligence

**Dependency Risk Level:** ${dependencyReport.dependencyRiskLevel ?? "UNKNOWN"}

**Dependency Files Scanned:** ${dependencyReport.scannedDependencyFiles ?? 0}

**High Risk Dependencies:** ${dependencyReport.highRiskDependencies ?? 0}

**Medium Risk Dependencies:** ${dependencyReport.mediumRiskDependencies ?? 0}

${formatDependencyFindings(dependencyReport.dependencyFindings ?? [])}

---

## Attack Surface Intelligence

**Attack Surface Risk Level:** ${attackSurfaceReport.attackSurfaceRiskLevel ?? "UNKNOWN"}

**Attack Surface Score:** ${attackSurfaceReport.attackSurfaceScore ?? 0}/100

**Total Attack Findings:** ${attackSurfaceReport.totalAttackFindings ?? 0}

**Critical Attack Paths:** ${attackSurfaceReport.criticalAttackPaths ?? 0}

**High Attack Paths:** ${attackSurfaceReport.highAttackPaths ?? 0}

**Medium Attack Paths:** ${attackSurfaceReport.mediumAttackPaths ?? 0}

${formatAttackFindings(attackSurfaceReport.attackFindings ?? [])}

---

## Smart Contract Audit

**Audit Risk Level:** ${smartContractAuditReport.auditRiskLevel ?? "UNKNOWN"}

**Audit Score:** ${smartContractAuditReport.auditScore ?? 0}/100

**Audited Contracts:** ${smartContractAuditReport.auditedContracts ?? 0}

**Skipped Non-Production Files:** ${smartContractAuditReport.skippedNonProductionFiles ?? 0}

**Critical Audit Findings:** ${smartContractAuditReport.criticalFindings ?? 0}

**High Audit Findings:** ${smartContractAuditReport.highFindings ?? 0}

**Medium Audit Findings:** ${smartContractAuditReport.mediumFindings ?? 0}

${formatSmartContractFindings(smartContractAuditReport.auditFindings ?? [])}

---

## Security Copilot Recommendations

${formatCopilotFindings(findings)}

---

## Disclaimer

Quantum Shield Trinity is an experimental security research tool. Findings should be reviewed by a qualified developer or security professional before production changes are made.
`;

  fs.writeFileSync(outputPath, markdown, "utf8");

  return {
    reporter: "Markdown Report Generator",
    outputPath,
    generatedAt: new Date().toISOString()
  };
}

function formatCopilotFindings(findings = []) {
  if (!findings.length) {
    return "No security copilot findings detected.";
  }

  return findings
    .slice(0, 25)
    .map((finding, index) => {
      return `### Copilot Finding #${index + 1}

**File:** ${finding.file ?? "Unknown"}

**Line:** ${finding.line ?? "Unknown"}

**Type:** ${finding.type ?? "Unknown"}

**Severity:** ${finding.severity ?? "Unknown"}

**Risk:** ${finding.risk ?? "No risk description available."}

**Business Impact:** ${finding.businessImpact ?? "Not provided."}

**Recommendation:** ${finding.recommendation ?? "Review manually."}

**Migration Path:** ${finding.migrationPath ?? "Manual review required."}

**Estimated Effort:** ${finding.estimatedEffort ?? "Unknown"}

---`;
    })
    .join("\n\n");
}

function formatDependencyFindings(findings = []) {
  if (!findings.length) {
    return "No dependency findings detected.";
  }

  return findings
    .slice(0, 15)
    .map((finding, index) => {
      return `### Dependency Finding #${index + 1}

**Dependency:** ${finding.dependency ?? "Unknown"}

**File:** ${finding.file ?? "Unknown"}

**Severity:** ${finding.severity ?? "Unknown"}

**Category:** ${finding.category ?? "Unknown"}

**Risk:** ${finding.risk ?? "Not provided."}

**Recommendation:** ${finding.recommendation ?? "Review manually."}

---`;
    })
    .join("\n\n");
}

function formatAttackFindings(findings = []) {
  if (!findings.length) {
    return "No attack surface findings detected.";
  }

  return findings
    .slice(0, 15)
    .map((finding, index) => {
      return `### Attack Surface Finding #${index + 1}

**File:** ${finding.file ?? "Unknown"}

**Line:** ${finding.line ?? "Unknown"}

**Type:** ${finding.type ?? "Unknown"}

**Severity:** ${finding.severity ?? "Unknown"}

**Category:** ${finding.category ?? "Unknown"}

**Recommendation:** ${finding.recommendation ?? "Review manually."}

---`;
    })
    .join("\n\n");
}

function formatSmartContractFindings(findings = []) {
  if (!findings.length) {
    return "No smart contract audit findings detected.";
  }

  return findings
    .slice(0, 25)
    .map((finding, index) => {
      return `### Smart Contract Finding #${index + 1}

**File:** ${finding.file ?? "Unknown"}

**Line:** ${finding.line ?? "Unknown"}

**Type:** ${finding.type ?? "Unknown"}

**Severity:** ${finding.severity ?? "Unknown"}

**Category:** ${finding.category ?? "Unknown"}

**Recommendation:** ${finding.recommendation ?? "Review manually."}

**Context Type:** ${finding.smartContractContext?.contextType ?? "Unknown"}

**Exploitability:** ${finding.smartContractContext?.exploitability ?? "Unknown"}

**Review Priority:** ${finding.smartContractContext?.reviewPriority ?? "Unknown"}

**Context Note:** ${finding.smartContractContext?.note ?? "Not provided."}

---`;
    })
    .join("\n\n");
}
