export function securityAssessmentEngine({
  walletReport = {},
  inventoryReport = {},
  migrationReport = {}
}) {
  const totalScore = Math.min(
    100,
    (walletReport.score ?? 0) + (inventoryReport.score ?? 0)
  );

  const criticalFindings = [];

  if ((walletReport.score ?? 0) > 75) {
    criticalFindings.push("High wallet exposure risk detected.");
  }

  if ((inventoryReport.findings ?? 0) > 0) {
    criticalFindings.push(
      `${inventoryReport.findings} cryptographic risk finding(s) detected.`
    );
  }

  if (migrationReport.migrationReady === false) {
    criticalFindings.push("Migration readiness gaps detected.");
  }

  const priorityLevel =
    totalScore > 80
      ? "CRITICAL"
      : totalScore > 60
      ? "HIGH"
      : totalScore > 30
      ? "MEDIUM"
      : "LOW";

  return {
    engine: "Security Assessment Engine",
    institutionalReport: true,
    totalScore,
    priorityLevel,
    criticalFindings,
    executiveSummary:
      priorityLevel === "CRITICAL"
        ? "Immediate security review recommended. Quantum-related exposure and migration gaps are present."
        : priorityLevel === "HIGH"
        ? "Elevated risk detected. Security teams should prioritize remediation planning."
        : priorityLevel === "MEDIUM"
        ? "Moderate risk detected. Continue monitoring and migration preparation."
        : "Lower current exposure. Maintain crypto-agility and periodic reviews.",
    recommendedNextSteps: [
      "Review wallet exposure and signing activity.",
      "Inventory cryptographic dependencies.",
      "Prioritize vulnerable algorithms for migration.",
      "Create a crypto-agility roadmap.",
      "Schedule recurring security assessments."
    ]
  };
}
