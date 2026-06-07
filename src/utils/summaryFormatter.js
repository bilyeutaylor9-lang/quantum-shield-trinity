export function summaryFormatter(report = {}) {
  return {
    title: "Quantum Shield Trinity Scan Summary",
    repositoryRiskLevel: report.repositoryRiskLevel ?? "UNKNOWN",
    score: report.score ?? 0,
    scannedFiles: report.scannedFiles ?? 0,
    criticalFindings: report.criticalFindings ?? 0,
    highFindings: report.highFindings ?? 0,
    mediumFindings: report.mediumFindings ?? 0,
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
