export { walletRiskEngine } from "./engines/walletRiskEngine.js";
export { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
export { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
export { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";
export { quantumExposureForecastEngine } from "./engines/quantumExposureForecastEngine.js";
export { quantumAttackSimulationEngine } from "./engines/quantumAttackSimulationEngine.js";
export { createQuantumRiskProfile } from "./models/quantumRiskProfile.js";

import { walletRiskEngine } from "./engines/walletRiskEngine.js";
import { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
import { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
import { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";
import { quantumExposureForecastEngine } from "./engines/quantumExposureForecastEngine.js";
import { quantumAttackSimulationEngine } from "./engines/quantumAttackSimulationEngine.js";
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

  const riskProfile = createQuantumRiskProfile({
    walletReport,
    inventoryReport,
    migrationReport,
    assessmentReport,
    forecastReport,
    simulationReport
  });

  return {
    platform: "Quantum Shield Trinity",
    version: "0.5.0",
    riskProfile,
    assessmentReport,
    walletReport,
    inventoryReport,
    migrationReport,
    forecastReport,
    simulationReport
  };
}
