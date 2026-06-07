import { calculateRiskScore } from "../utils/riskScore.js";

export function walletRiskEngine(wallet) {
  const transactionCount = 0;
  const reusedAddress = false;
  const signedMessages = 0;

  const score = calculateRiskScore({
    transactionCount,
    reusedAddress,
    signedMessages
  });

  return {
    engine: "Wallet Quantum Risk Engine",
    wallet,
    transactionCount,
    reusedAddress,
    signedMessages,
    score,
    riskLevel:
      score > 75
        ? "HIGH"
        : score > 40
        ? "MEDIUM"
        : "LOW"
  };
}
