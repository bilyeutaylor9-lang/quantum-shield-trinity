export function summaryFormatter(report = {}) {
  const securityScoreReport = report.securityScoreReport ?? {};

  const securityScore =
    securityScoreReport.securityScore ??
    report.score ??
    0;

  const repositoryRiskLevel =
    securityScoreReport.riskLevel ??
    report.repositoryRiskLevel ??
    "UNKNOWN";

  const findingCounts = securityScoreReport.findingCounts ?? {};

  return {
    title: "Quantum Shield Trinity Scan Summary",
    repositoryRiskLevel,
    score: securityScore,
    grade: securityScoreReport.grade ?? "N/A",
    scannedFiles: report.scannedFiles ?? 0,
    criticalFindings:
      findingCounts.critical ??
      report.criticalFindings ??
      0,
    highFindings:
      findingCounts.high ??
      report.highFindings ??
      0,
    mediumFindings:
      findingCounts.medium ??
      report.mediumFindings ??
      0,
    lowFindings:
      findingCounts.low ??
      report.lowFindings ??
      0,
    topPriority:
      securityScoreReport.topPriority ??
      "Review findings and improve security posture.",
    topRecommendations: (report.copilotGuidance ?? [])
      .slice(0, 5)
      .map((item) => ({
        file: item.file,
        line: item.line,
        type: item.type,
        severity: item.severity,
        recommendation: item.recommendation,
        migrationPath: item.migrationPath
      }))
  };
}
