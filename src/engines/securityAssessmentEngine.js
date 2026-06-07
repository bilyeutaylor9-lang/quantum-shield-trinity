import { getRiskLevel } from "../models/riskLevels.js";

export function securityAssessmentEngine({
  walletReport = {},
  inventoryReport = {},
  migrationReport = {},
  forecastReport = {}
}) {
  const walletScore = walletReport.score ?? 0;
  const inventoryScore = inventoryReport.score ?? 0;
  const forecastScore = forecastReport.score ?? 0;

  const totalScore = Math.min(
    100,
    Math.round((walletScore + inventoryScore + forecastScore) / 3)
  );

  const criticalFindings = [];

  if (walletScore >= 70) {
    criticalFindings.push("Elevated wallet exposure detected.");
  }

  if ((inventoryReport.findings ?? 0) > 0) {
    criticalFindings.push(
      `${inventoryReport.findings} cryptographic finding(s) detected.`
    );
  }

  if (migrationReport.migrationReady === false) {
    criticalFindings.push("Migration readiness gaps detected.");
  }

  if (forecastReport.qDayExposure === "HIGH") {
    criticalFindings.push("High Q-Day exposure forecast detected.");
  }

  const riskLevel = getRiskLevel(totalScore);

  return {
    engine: "Security Assessment Engine",
    reportType: "Institutional Quantum Risk Assessment",
    totalScore,
    riskLevel,
    criticalFindings,
    executiveSummary:
      riskLevel === "CRITICAL"
        ? "Critical quantum-related exposure detected. Immediate remediation planning is recommended."
        : riskLevel === "HIGH"
        ? "High quantum-related exposure detected. Security teams should prioritize remediation."
        : riskLevel === "MEDIUM"
        ? "Moderate quantum-related exposure detected. Continue monitoring and migration preparation."
        : "Lower current quantum-related exposure detected. Maintain crypto-agility and periodic review.",
    recommendedNextSteps: [
      "Review wallet exposure and signing activity.",
      "Inventory cryptographic dependencies.",
      "Prioritize vulnerable algorithms for migration.",
      "Create a crypto-agility roadmap.",
      "Schedule recurring quantum risk assessments."
    ]
  };
}
