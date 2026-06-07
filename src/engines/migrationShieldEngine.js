export function migrationShieldEngine(walletReport = {}, inventoryReport = {}) {
  const recommendations = [];

  if (walletReport.score > 75) {
    recommendations.push(
      "High wallet exposure detected. Review address usage and signing activity."
    );
  }

  if (
    inventoryReport.vulnerableAlgorithms?.includes("RSA")
  ) {
    recommendations.push(
      "Review RSA usage and evaluate migration plans."
    );
  }

  if (
    inventoryReport.vulnerableAlgorithms?.includes("ECDSA")
  ) {
    recommendations.push(
      "Review ECDSA dependencies and create a crypto-agility roadmap."
    );
  }

  if (
    inventoryReport.vulnerableAlgorithms?.includes("SHA1")
  ) {
    recommendations.push(
      "Replace legacy SHA1 implementations."
    );
  }

  if (recommendations.length === 0) {
    recommendations.push(
      "No immediate migration actions identified."
    );
  }

  return {
    engine: "Migration Shield Engine",
    migrationReady: recommendations.length <= 1,
    recommendations
  };
}
