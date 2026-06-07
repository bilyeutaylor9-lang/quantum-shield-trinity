import { QUANTUM_RULES } from "../data/quantumRules.js";
import { securityCopilotEngine } from "./securityCopilotEngine.js";
import { rootCauseEngine } from "./rootCauseEngine.js";
import { isProductionFile } from "../utils/isProductionFile.js";

export function repositoryScannerEngine(files = []) {
  const findings = [];

  let skippedNonProductionFiles = 0;

  for (const file of files) {
    const fileName = file.name ?? "Unknown File";

    if (!isProductionFile(fileName)) {
      skippedNonProductionFiles += 1;
      continue;
    }

    const content = file.content ?? "";
    const lines = content.split("\n");

    for (const rule of QUANTUM_RULES) {
      lines.forEach((line, index) => {
        const matches = line.match(rule.regex);

        if (!matches) {
          return;
        }

        const confidence = calculateConfidence(rule, line, fileName);
        const severity = adjustSeverity(rule.severity, confidence, fileName, line);

        if (confidence < 45) {
          return;
        }

        const rootCause = rootCauseEngine({
          type: rule.type,
          severity
        });

        findings.push({
          file: fileName,
          line: index + 1,
          ruleId: rule.id,
          type: rule.type,
          severity,
          originalSeverity: rule.severity,
          category: rule.category,
          description: rule.description,
          recommendation: rule.recommendation,
          confidence,
          occurrences: matches.length,
          context: getLineContext(lines, index),
          rootCause
        });
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

  const lowFindings = findings.filter(
    finding => finding.severity === "LOW"
  ).length;

  const score = Math.min(
    100,
    criticalFindings * 50 +
      highFindings * 15 +
      mediumFindings * 3
  );

  const repositoryRiskLevel =
    criticalFindings >= 5
      ? "CRITICAL"
      : criticalFindings >= 1
      ? "HIGH"
      : highFindings >= 10
      ? "HIGH"
      : mediumFindings >= 20
      ? "MEDIUM"
      : "LOW";

  return {
    engine: "Repository Scanner Engine",
    scannerVersion: "1.5.1",
    rulesUsed: QUANTUM_RULES.length,
    scannedFiles: files.length,
    skippedNonProductionFiles,
    findings,
    copilotGuidance,
    criticalFindings,
    highFindings,
    mediumFindings,
    lowFindings,
    score,
    securityScore: Math.max(0, 100 - score),
    securityGrade: calculateSecurityGrade(score),
    repositoryRiskLevel,
    summary: {
      totalFindings:
        criticalFindings +
        highFindings +
        mediumFindings +
        lowFindings,
      criticalPercentage:
        findings.length > 0
          ? Math.round((criticalFindings / findings.length) * 100)
          : 0,
      highPercentage:
        findings.length > 0
          ? Math.round((highFindings / findings.length) * 100)
          : 0,
      mediumPercentage:
        findings.length > 0
          ? Math.round((mediumFindings / findings.length) * 100)
          : 0
    }
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
    normalizedLine.includes("placeholder") ||
    normalizedLine.includes("example") ||
    normalizedLine.includes("dummy") ||
    normalizedLine.includes("fake") ||
    normalizedLine.includes("mock") ||
    normalizedLine.includes("test")
  ) {
    confidence -= 25;
  }

  if (
    normalizedLine.includes("import") ||
    normalizedLine.includes("interface") ||
    normalizedLine.includes("contract ") ||
    normalizedLine.includes("library ")
  ) {
    confidence -= 10;
  }

  return Math.max(5, Math.min(100, confidence));
}

function adjustSeverity(severity, confidence, fileName = "", line = "") {
  const normalizedLine = line.toLowerCase();

  if (confidence < 35) {
    return "LOW";
  }

  if (confidence < 55 && severity === "CRITICAL") {
    return "MEDIUM";
  }

  if (confidence < 55 && severity === "HIGH") {
    return "LOW";
  }

  if (
    normalizedLine.includes("example") ||
    normalizedLine.includes("placeholder") ||
    normalizedLine.includes("mock") ||
    normalizedLine.includes("fake")
  ) {
    if (severity === "CRITICAL") return "MEDIUM";
    if (severity === "HIGH") return "LOW";
  }

  return severity;
}

function calculateSecurityGrade(score) {
  if (score >= 95) return "F";
  if (score >= 80) return "D";
  if (score >= 60) return "C";
  if (score >= 40) return "B";
  if (score >= 20) return "A";
  return "A+";
}
