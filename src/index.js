export { walletRiskEngine } from "./engines/walletRiskEngine.js";
export { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
export { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
export { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";
export { quantumExposureForecastEngine } from "./engines/quantumExposureForecastEngine.js";
export { quantumAttackSimulationEngine } from "./engines/quantumAttackSimulationEngine.js";
export { securityAuditLoopEngine } from "./engines/securityAuditLoopEngine.js";
export { jsonExportEngine } from "./engines/jsonExportEngine.js";
export { createQuantumRiskProfile } from "./models/quantumRiskProfile.js";

import { walletRiskEngine } from "./engines/walletRiskEngine.js";
import { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
import { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
import { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";
import { quantumExposureForecastEngine } from "./engines/quantumExposureForecastEngine.js";
import { quantumAttackSimulationEngine } from "./engines/quantumAttackSimulationEngine.js";
import { securityAuditLoopEngine } from "./engines/securityAuditLoopEngine.js";
import { jsonExportEngine } from "./engines/jsonExportEngine.js";
import { createQuantumRiskProfile } from "./models/quantumRiskProfile.js";

export function quantumShieldTrinity(wallet, codeSample = "") {
  const walletReport = walletRiskEngine(wallet);

  const inventoryReport = cryptoInventoryEngine(codeSample);

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
    forecastReport
  });

  const auditReport = securityAuditLoopEngine({
    systemState: {
      walletReport,
      inventoryReport,
      migrationReport,
      forecastReport,
      simulationReport,
      assessmentReport
    }
  });

  const riskProfile = createQuantumRiskProfile({
    walletReport,
    inventoryReport,
    migrationReport,
    assessmentReport,
    forecastReport,
    simulationReport,
    auditReport
  });

  const baseReport = {
    platform: "Quantum Shield Trinity",
    version: "0.7.0",
    riskProfile,
    auditReport,
    assessmentReport,
    walletReport,
    inventoryReport,
    migrationReport,
    forecastReport,
    simulationReport
  };

  const exportReport = jsonExportEngine(baseReport);

  return {
    ...baseReport,
    exportReport
  };
}
