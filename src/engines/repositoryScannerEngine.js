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
            confidence: calculateConfidence(rule, line, fileName),
            occurrences: matches.length,
            context: getLineContext(lines, index)
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
    scannerVersion: "1.2.5",
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

function getLineContext(lines, matchIndex) {
  const before = lines[matchIndex - 1] ?? "";
  const match = lines[matchIndex] ?? "";
  const after = lines[matchIndex + 1] ?? "";

  return {
    before: before.trim(),
    match: maskSensitiveValue(match.trim()),
    after: after.trim()
  };
}

function maskSensitiveValue(value = "") {
  return value
    .replace(/sk-[A-Za-z0-9_-]{10,}/g, "sk-***MASKED***")
    .replace(/ghp_[A-Za-z0-9]{10,}/g, "ghp_***MASKED***")
    .replace(/github_pat_[A-Za-z0-9_]{10,}/g, "github_pat_***MASKED***")
    .replace(/AKIA[0-9A-Z]{12,}/g, "AKIA***MASKED***")
    .replace(/0x[a-fA-F0-9]{64}/g, "0x***MASKED_PRIVATE_KEY***");
}

function calculateConfidence(rule = {}, line = "", fileName = "") {
  const normalizedLine = line.toLowerCase();
  const normalizedFile = fileName.toLowerCase();

  let confidence = 60;

  if (rule.severity === "CRITICAL") {
    confidence += 15;
  }

  if (
    normalizedLine.includes("private") ||
    normalizedLine.includes("secret") ||
    normalizedLine.includes("key") ||
    normalizedLine.includes("token")
  ) {
    confidence += 15;
  }

  if (
    normalizedFile.includes(".env") ||
    normalizedFile.includes("secret") ||
    normalizedFile.includes("config")
  ) {
    confidence += 10;
  }

  if (
    normalizedFile.includes("test") ||
    normalizedFile.includes("mock") ||
    normalizedFile.includes("example") ||
    normalizedFile.includes("demo")
  ) {
    confidence -= 25;
  }

  if (
    normalizedLine.includes("placeholder") ||
    normalizedLine.includes("example") ||
    normalizedLine.includes("dummy") ||
    normalizedLine.includes("fake")
  ) {
    confidence -= 20;
  }

  return Math.max(5, Math.min(100, confidence));
}
