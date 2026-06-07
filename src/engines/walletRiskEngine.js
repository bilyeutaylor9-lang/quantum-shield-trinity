export function walletRiskEngine(wallet) {
  return {
    wallet,
    exposedPublicKey: false,
    transactionCount: 0,
    riskLevel: "LOW",
    score: 10
  };
}
