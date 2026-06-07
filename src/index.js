export { walletRiskEngine } from "./engines/walletRiskEngine.js";
export { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
export { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
export { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";

import { walletRiskEngine } from "./engines/walletRiskEngine.js";
import { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
import { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
import { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";

export function quantumShieldTrinity(wallet, codeSample = "") {
  const walletReport = walletRiskEngine(wallet);

  const inventoryReport = cryptoInventoryEngine(codeSample);

  const migrationReport = migrationShieldEngine(
    walletReport,
    inventoryReport
  );

  const assessmentReport = securityAssessmentEngine({
    walletReport,
    inventoryReport,
    migrationReport
  });

  return {
    platform: "Quantum Shield Trinity",
    version: "0.4.0",
    assessmentReport,
    walletReport,
    inventoryReport,
    migrationReport
  };
}
