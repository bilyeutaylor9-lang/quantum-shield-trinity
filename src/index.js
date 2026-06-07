export { walletRiskEngine } from "./engines/walletRiskEngine.js";
export { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
export { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
export { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";
export { quantumExposureForecastEngine } from "./engines/quantumExposureForecastEngine.js";
export { quantumAttackSimulationEngine } from "./engines/quantumAttackSimulationEngine.js";
export { securityAuditLoopEngine } from "./engines/securityAuditLoopEngine.js";
export { jsonExportEngine } from "./engines/jsonExportEngine.js";
export { executiveReportEngine } from "./engines/executiveReportEngine.js";
export { dependencyRiskEngine } from "./engines/dependencyRiskEngine.js";
export { securityScoreEngine } from "./engines/securityScoreEngine.js";
export { htmlReportGenerator } from "./reporters/htmlReportGenerator.js";
export { createQuantumRiskProfile } from "./models/quantumRiskProfile.js";

import { walletRiskEngine } from "./engines/walletRiskEngine.js";
import { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
import { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
import { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";
import { quantumExposureForecastEngine } from "./engines/quantumExposureForecastEngine.js";
import { quantumAttackSimulationEngine } from "./engines/quantumAttackSimulationEngine.js";
import { securityAuditLoopEngine } from "./engines/securityAuditLoopEngine.js";
import { jsonExportEngine } from "./engines/jsonExportEngine.js";
import { executiveReportEngine } from "./engines/executiveReportEngine.js";
import { dependencyRiskEngine } from "./engines/dependencyRiskEngine.js";
import { securityScoreEngine } from "./engines/securityScoreEngine.js";
import { htmlReportGenerator } from "./reporters/htmlReportGenerator.js";
import { createQuantumRiskProfile } from "./models/quantumRiskProfile.js";

export function quantumShieldTrinity(wallet, codeSample = "", packageJson = {}) {
  const walletReport = walletRiskEngine(wallet);

  const inventoryReport = cryptoInventoryEngine(codeSample);

  const dependencyRiskReport = dependencyRiskEngine(packageJson);

  const migrationReport = migrationShieldEngine(
    walletReport,
    inventoryReport
  );

  const forecastReport = quantumExposureForecastEngine({
    walletReport,
    inventoryReport,
    migrationReport
  });

  const simulationReport = quantumAttackSimulationEngine({
    walletReport,
    inventoryReport,
    migrationReport,
    forecastReport
  });

  const assessmentReport = securityAssessmentEngine({
    walletReport,
    inventoryReport,
    migrationReport,
    forecastReport,
    dependencyRiskReport
  });

  const securityScoreReport = securityScoreEngine({
    walletReport,
    inventoryReport,
    dependencyRiskReport,
    migrationReport,
    forecastReport,
    simulationReport,
    assessmentReport
  });

  const auditReport = securityAuditLoopEngine({
    systemState: {
      walletReport,
      inventoryReport,
      dependencyRiskReport,
      migrationReport,
      forecastReport,
      simulationReport,
      assessmentReport,
      securityScoreReport
    }
  });

  const riskProfile = createQuantumRiskProfile({
    walletReport,
    inventoryReport,
    dependencyRiskReport,
    migrationReport,
    assessmentReport,
    forecastReport,
    simulationReport,
    auditReport,
    securityScoreReport
  });

  const baseReport = {
    platform: "Quantum Shield Trinity",
    version: "1.1.0",
    riskProfile,
    auditReport,
    assessmentReport,
    securityScoreReport,
    dependencyRiskReport,
    walletReport,
    inventoryReport,
    migrationReport,
    forecastReport,
    simulationReport
  };

  const executiveReport = executiveReportEngine(baseReport);

  const htmlReport = htmlReportGenerator({
    ...baseReport,
    executiveReport
  });

  const exportReport = jsonExportEngine({
    ...baseReport,
    executiveReport,
    htmlReport
  });

  return {
    ...baseReport,
    executiveReport,
    htmlReport,
    exportReport
  };
}
