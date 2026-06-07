import fs from "fs";

export function markdownReportGenerator(report = {}, outputPath = "quantum-shield-report.md") {
  const findings = report.copilotGuidance ?? report.findings ?? [];

  const markdown = `# Quantum Shield Trinity Report

## Executive Summary

**Risk Level:** ${report.repositoryRiskLevel ?? "UNKNOWN"}

**Score:** ${report.score ?? 0}/100

**Files Scanned:** ${report.scannedFiles ?? 0}

**Critical Findings:** ${report.criticalFindings ?? 0}

**High Findings:** ${report.highFindings ?? 0}

**Medium Findings:** ${report.mediumFindings ?? 0}

---

## Top Recommendations

${formatFindings(findings)}

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

function formatFindings(findings = []) {
  if (!findings.length) {
    return "No findings detected.";
  }

  return findings
    .slice(0, 25)
    .map((finding, index) => {
      return `### Finding #${index + 1}

**File:** ${finding.file ?? "Unknown"}

**Line:** ${finding.line ?? "Unknown"}

**Type:** ${finding.type ?? "Unknown"}

**Severity:** ${finding.severity ?? "Unknown"}

**Risk:** ${finding.risk ?? finding.description ?? "No risk description available."}

**Business Impact:** ${finding.businessImpact ?? "Not provided."}

**Recommendation:** ${finding.recommendation ?? "Review manually."}

**Migration Path:** ${finding.migrationPath ?? "Manual review required."}

**Estimated Effort:** ${finding.estimatedEffort ?? "Unknown"}

---`;
    })
    .join("\n\n");
}
