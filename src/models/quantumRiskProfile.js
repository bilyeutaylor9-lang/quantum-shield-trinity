export function createQuantumRiskProfile({
  walletReport = {},
  inventoryReport = {},
  migrationReport = {},
  assessmentReport = {},
  forecastReport = {},
  simulationReport = {}
}) {
  return {
    generatedAt: new Date().toISOString(),

    wallet: {
      score: walletReport.score ?? 0,
      riskLevel: walletReport.riskLevel ?? "LOW",
      address: walletReport.walletAddress ?? "Unknown"
    },

    inventory: {
      findings: inventoryReport.findings ?? 0,
      score: inventoryReport.score ?? 0,
      riskLevel: inventoryReport.riskLevel ?? "LOW",
      vulnerableAlgorithms: inventoryReport.vulnerableAlgorithms ?? []
    },

    migration: {
      ready: migrationReport.migrationReady ?? false,
      recommendations: migrationReport.recommendations ?? []
    },

    assessment: {
      totalScore: assessmentReport.totalScore ?? 0,
      riskLevel: assessmentReport.riskLevel ?? "LOW",
      criticalFindings: assessmentReport.criticalFindings ?? []
    },

    forecast: {
      score: forecastReport.score ?? 0,
      qDayExposure: forecastReport.qDayExposure ?? "UNKNOWN",
      migrationUrgency: forecastReport.migrationUrgency ?? "UNKNOWN",
      harvestNowDecryptLaterRisk:
        forecastReport.harvestNowDecryptLaterRisk ?? "UNKNOWN"
    },

    simulation: {
      attackPath: simulationReport.attackPath ?? [],
      estimatedImpact: simulationReport.estimatedImpact ?? "UNKNOWN",
      businessRisk: simulationReport.businessRisk ?? "UNKNOWN"
    }
  };
}
