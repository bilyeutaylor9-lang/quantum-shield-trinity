export function quantumExposureForecastEngine({
  walletReport = {},
  inventoryReport = {},
  migrationReport = {}
} = {}) {
  const walletScore = walletReport.score ?? 0;
  const inventoryScore = inventoryReport.score ?? 0;
  const migrationReady = migrationReport.migrationReady ?? false;

  const score = Math.min(
    100,
    walletScore + inventoryScore + (migrationReady ? 0 : 15)
  );

  const qDayExposure =
    score >= 90
      ? "CRITICAL"
      : score >= 70
      ? "HIGH"
      : score >= 40
      ? "MEDIUM"
      : "LOW";

  return {
    engine: "Quantum Exposure Forecast Engine",
    score,
    qDayExposure,
    harvestNowDecryptLaterRisk:
      inventoryScore >= 50 ? "HIGH" : "LOW",
    migrationUrgency:
      score >= 90
        ? "Immediate"
        : score >= 70
        ? "90 days"
        : score >= 40
        ? "12 months"
        : "Monitor",
    businessImpact:
      score >= 70
        ? "Critical systems should be prioritized for crypto-agility planning."
        : "Maintain monitoring and continue migration preparation."
  };
}
