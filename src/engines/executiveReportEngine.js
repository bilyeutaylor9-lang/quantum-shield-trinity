export function executiveReportEngine(report = {}) {
  const riskProfile = report.riskProfile ?? {};
  const assessment = report.assessmentReport ?? {};
  const audit = report.auditReport ?? {};
  const securityScoreReport = report.securityScoreReport ?? {};

  const securityScore =
    securityScoreReport.securityScore ??
    assessment.totalScore ??
    assessment.score ??
    0;

  const riskLevel =
    securityScoreReport.riskLevel ??
    assessment.riskLevel ??
    "UNKNOWN";

  const grade =
    securityScoreReport.grade ??
    "N/A";

  return {
    engine: "Executive Report Engine",
    reportType: "Quantum Security Executive Summary",
    generatedAt: new Date().toISOString(),

    headline: `${riskLevel} Quantum Risk Assessment`,

    summary:
      securityScoreReport.summary ??
      assessment.executiveSummary ??
      "Quantum Shield Trinity completed an assessment but no executive summary was available.",

    keyMetrics: {
      securityScore,
      totalScore: securityScore,
      riskLevel,
      grade,
      criticalFindings: securityScoreReport.findingCounts?.critical ?? 0,
      highFindings: securityScoreReport.findingCounts?.high ?? 0,
      mediumFindings: securityScoreReport.findingCounts?.medium ?? 0,
      lowFindings: securityScoreReport.findingCounts?.low ?? 0,
      walletRisk: riskProfile.wallet?.riskLevel ?? "UNKNOWN",
      cryptoInventoryRisk: riskProfile.inventory?.riskLevel ?? "UNKNOWN",
      migrationReady: riskProfile.migration?.ready ?? false,
      auditVerified: audit.verified ?? false
    },

    topFindings:
      assessment.criticalFindings?.length > 0
        ? assessment.criticalFindings
        : securityScoreReport.findingCounts?.critical > 0
          ? [
              "Critical security findings detected. Review full report for remediation details."
            ]
          : [
              "No critical findings identified."
            ],

    recommendedActions:
      assessment.recommendedNextSteps?.length > 0
        ? assessment.recommendedNextSteps
        : [
            securityScoreReport.topPriority ??
              "Review findings and improve security posture.",
            "Prioritize remediation based on severity.",
            "Re-run Quantum Shield Trinity after fixes are applied."
          ],

    closingNote:
      "This report is designed for security planning and does not replace a professional security audit."
  };
}

export default executiveReportEngine;
