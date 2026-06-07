import { getRiskLevel } from "../models/riskLevels.js";

export function cryptoInventoryEngine(codeSample = "") {
  const vulnerableAlgorithms = [];

  if (codeSample.includes("RSA")) {
    vulnerableAlgorithms.push("RSA");
  }

  if (codeSample.includes("ECDSA")) {
    vulnerableAlgorithms.push("ECDSA");
  }

  if (codeSample.includes("ECDH")) {
    vulnerableAlgorithms.push("ECDH");
  }

  if (codeSample.includes("SHA1")) {
    vulnerableAlgorithms.push("SHA1");
  }

  const score = Math.min(vulnerableAlgorithms.length * 25, 100);

  return {
    engine: "Crypto Inventory Engine",
    findings: vulnerableAlgorithms.length,
    vulnerableAlgorithms,
    scannedFiles: 1,
    score,
    riskLevel: getRiskLevel(score),
    recommendation:
      score >= 90
        ? "Critical cryptographic exposure detected. Immediate inventory review recommended."
        : score >= 70
        ? "High cryptographic risk detected. Prioritize migration planning."
        : score >= 40
        ? "Moderate crypto risk detected. Continue dependency review."
        : "Lower current crypto exposure detected."
  };
}
