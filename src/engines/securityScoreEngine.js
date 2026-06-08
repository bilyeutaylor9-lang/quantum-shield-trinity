export function securityScoreEngine(reports = {}) {
  const findingCounts = collectFindingCounts(reports);
  const riskPenalty = calculateRiskPenalty(findingCounts);
  const securityScore = Math.max(0, Math.min(100, 100 - riskPenalty));
  const riskLevel = getRiskLevel(securityScore, findingCounts);
  const grade = getGrade(securityScore, findingCounts);
  const topPriority = getTopPriority(findingCounts, securityScore);

  return {
    engine: "Security Score Engine",
    scannerVersion: "2.1.0",
    securityScore,
    riskLevel,
    grade,
    summary: `Security Score: ${securityScore}/100. Risk Level: ${riskLevel}. Critical findings: ${findingCounts.critical}. High findings: ${findingCounts.high}. Medium findings: ${findingCounts.medium}.`,
    topPriority,
    findingCounts,
    penaltyBreakdown: {
      criticalPenalty: findingCounts.critical * 20,
      highPenalty: findingCounts.high * 8,
      mediumPenalty: findingCounts.medium * 3,
      lowPenalty: findingCounts.low * 1,
      totalPenalty: riskPenalty
    }
  };
}

function collectFindingCounts(reports = {}) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  countReportSeverity(counts, reports.repositoryReport);
  countReportSeverity(counts, reports.walletReport);
  countReportSeverity(counts, reports.inventoryReport);
  countReportSeverity(counts, reports.dependencyRiskReport);
  countReportSeverity(counts, reports.dependencyReport);
  countReportSeverity(counts, reports.attackSurfaceReport);
  countReportSeverity(counts, reports.smartContractAuditReport);
  countReportSeverity(counts, reports.migrationReport);
  countReportSeverity(counts, reports.forecastReport);
  countReportSeverity(counts, reports.simulationReport);
  countReportSeverity(counts, reports.exploitSimulationReport);
  countReportSeverity(counts, reports.assessmentReport);

  return counts;
}

function countReportSeverity(counts, report) {
  if (!report) return;

  addExplicitCount(counts, "critical", report.criticalFindings);
  addExplicitCount(counts, "critical", report.criticalAttackPaths);
  addExplicitCount(counts, "critical", report.criticalSimulations);

  addExplicitCount(counts, "high", report.highFindings);
  addExplicitCount(counts, "high", report.highAttackPaths);
  addExplicitCount(counts, "high", report.highSimulations);
  addExplicitCount(counts, "high", report.highRiskDependencies);

  addExplicitCount(counts, "medium", report.mediumFindings);
  addExplicitCount(counts, "medium", report.mediumAttackPaths);
  addExplicitCount(counts, "medium", report.mediumRiskDependencies);

  addExplicitCount(counts, "low", report.lowFindings);
  addExplicitCount(counts, "low", report.lowAttackPaths);
  addExplicitCount(counts, "low", report.lowRiskDependencies);

  countFindingArray(counts, report.findings);
  countFindingArray(counts, report.dependencyFindings);
  countFindingArray(counts, report.attackFindings);
  countFindingArray(counts, report.auditFindings);
  countFindingArray(counts, report.simulations);
  countFindingArray(counts, report.recommendations);
  countFindingArray(counts, report.topRecommendations);
}

function addExplicitCount(counts, severity, value) {
  const number = Number(value);

  if (Number.isFinite(number) && number > 0) {
    counts[severity] += number;
  }
}

function countFindingArray(counts, findings) {
  if (!Array.isArray(findings)) return;

  for (const finding of findings) {
    const severity = normalizeSeverity(
      finding?.severity ??
        finding?.riskLevel ??
        finding?.estimatedImpact ??
        finding?.level
    );

    counts[severity] += 1;
  }
}

function normalizeSeverity(value = "low") {
  const normalized = String(value).toUpperCase();

  if (normalized.includes("CRITICAL")) return "critical";
  if (normalized.includes("HIGH")) return "high";
  if (normalized.includes("MEDIUM")) return "medium";
  if (normalized.includes("LOW")) return "low";

  return "low";
}

function calculateRiskPenalty(counts) {
  const penalty =
    counts.critical * 20 +
    counts.high * 8 +
    counts.medium * 3 +
    counts.low * 1;

  return Math.min(100, penalty);
}

function getRiskLevel(score, counts) {
  if (counts.critical > 0) return "CRITICAL";
  if (counts.high >= 5) return "HIGH";
  if (score >= 90) return "LOW";
  if (score >= 75) return "MEDIUM";
  if (score >= 50) return "HIGH";
  return "CRITICAL";
}

function getGrade(score, counts) {
  if (counts.critical > 0) return "F";
  if (counts.high >= 10) return "D";
  if (score >= 95) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function getTopPriority(counts, score) {
  if (counts.critical > 0) {
    return "Immediately address critical findings before deployment.";
  }

  if (counts.high > 0) {
    return "Prioritize high-risk findings and reduce exposed attack paths.";
  }

  if (counts.medium > 0) {
    return "Review medium-risk findings and strengthen controls before production use.";
  }

  if (score >= 90) {
    return "Maintain current security posture and continue monitoring.";
  }

  return "Review all findings and improve security posture.";
}
