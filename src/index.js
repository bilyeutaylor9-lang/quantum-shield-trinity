export { walletRiskEngine } from "./engines/walletRiskEngine.js";
export { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
export { migrationShieldEngine } from "./engines/migrationShieldEngine.js";

import { walletRiskEngine } from "./engines/walletRiskEngine.js";
import { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
import { migrationShieldEngine } from "./engines/migrationShieldEngine.js";

export function quantumShieldTrinity(wallet, codeSample = "") {
  const walletReport = walletRiskEngine(wallet);

  const inventoryReport =
    cryptoInventoryEngine(codeSample);

  const migrationReport =
    migrationShieldEngine(
      walletReport,
      inventoryReport
    );

  const totalScore = Math.min(
    100,
    walletReport.score +
      inventoryReport.score
  );

  return {
    platform: "Quantum Shield Trinity",
    version: "0.3.0",
    totalScore,
    walletReport,
    inventoryReport,
    migrationReport
  };
}
