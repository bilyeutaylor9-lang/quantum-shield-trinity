import { QUANTUM_RULES } from "../data/quantumRules.js";
import { securityCopilotEngine } from "./securityCopilotEngine.js";

export function repositoryScannerEngine(files = []) {
  const findings = [];

  for (const file of files) {
    const fileName = file.name ?? "Unknown File";
    const content = file.content ?? "";
    const lines = content.split("\n");

    for (const rule of QUANTUM_RULES) {
      lines.forEach((line, index) => {
        const matches = line.match(rule.regex);

        if (matches) {
          findings.push({
            file: fileName,
            line: index + 1,
            ruleId: rule.id,
            type: rule.type,
            severity: rule.severity,
            category: rule.category,
            description: rule.description,
            recommendation: rule.recommendation,
            occurrences: matches.length
          });
        }
      });
    }
  }

  const copilotGuidance = securityCopilotEngine(findings);

  const criticalFindings = findings.filter(
    finding => finding.severity === "CRITICAL"
  ).length;

  const highFindings = findings.filter(
    finding => finding.severity === "HIGH"
  ).length;

  const mediumFindings = findings.filter(
    finding => finding.severity === "MEDIUM"
  ).length;

  const score = Math.min(
    100,
    criticalFindings * 40 +
      highFindings * 15 +
      mediumFindings * 8
  );

  return {
    engine: "Repository Scanner Engine",
    rulesUsed: QUANTUM_RULES.length,
    scannedFiles: files.length,
    findings,
    copilotGuidance,
    criticalFindings,
    highFindings,
    mediumFindings,
    score,
    repositoryRiskLevel:
      score >= 90
        ? "CRITICAL"
        : score >= 70
        ? "HIGH"
        : score >= 40
        ? "MEDIUM"
        : "LOW"
  };
}
