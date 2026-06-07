export { walletRiskEngine } from "./engines/walletRiskEngine.js";
export { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
export { migrationShieldEngine } from "./engines/migrationShieldEngine.js";

export function quantumShieldTrinity(wallet) {
  const walletReport = walletRiskEngine(wallet);
  const inventoryReport = cryptoInventoryEngine();
  const migrationReport = migrationShieldEngine();

  return {
    platform: "Quantum Shield Trinity",
    version: "0.1.0",
    walletReport,
    inventoryReport,
    migrationReport
  };
}
