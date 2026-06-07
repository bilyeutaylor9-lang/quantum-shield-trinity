import { calculateRiskScore } from "../utils/riskScore.js";
import { getRiskLevel } from "../models/riskLevels.js";

export function walletRiskEngine(wallet) {
  const transactionCount = wallet?.transactionCount ?? 0;
  const reusedAddress = wallet?.reusedAddress ?? false;
  const signedMessages = wallet?.signedMessages ?? 0;

  const score = calculateRiskScore({
    transactionCount,
    reusedAddress,
    signedMessages
  });

  return {
    engine: "Wallet Quantum Risk Engine",
    walletAddress: wallet?.address ?? "Unknown",
    transactionCount,
    reusedAddress,
    signedMessages,
    score,
    riskLevel: getRiskLevel(score),
    recommendation:
      score >= 90
        ? "Critical exposure detected. Immediate wallet review recommended."
        : score >= 70
        ? "High exposure detected. Reduce signing activity and review wallet reuse."
        : score >= 40
        ? "Moderate exposure detected. Continue monitoring and improve key hygiene."
        : "Lower exposure. Maintain monitoring and avoid unnecessary signing."
  };
}
