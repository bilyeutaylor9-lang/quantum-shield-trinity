export function createQuantumRiskProfile({
  walletReport = {},
  inventoryReport = {},
  migrationReport = {},
  assessmentReport = {},
  forecastReport = {}
}) {
  return {
    generatedAt: new Date().toISOString(),

    wallet: {
      score: walletReport.score ?? 0,
      riskLevel: walletReport.riskLevel ?? "LOW"
    },

    inventory: {
      findings: inventoryReport.findings ?? 0,
      score: inventoryReport.score ?? 0,
      riskLevel: inventoryReport.riskLevel ?? "LOW"
    },

    migration: {
      ready: migrationReport.migrationReady ?? false
    },

    assessment: {
      totalScore: assessmentReport.totalScore ?? 0,
      riskLevel: assessmentReport.riskLevel ?? "LOW"
    },

    forecast: {
      qDayExposure: forecastReport.qDayExposure ?? "UNKNOWN",
      migrationUrgency:
        forecastReport.migrationUrgency ?? "UNKNOWN"
    }
  };
}
