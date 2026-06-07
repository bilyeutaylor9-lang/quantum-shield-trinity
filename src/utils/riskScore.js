export function calculateRiskScore({
  transactionCount = 0,
  reusedAddress = false,
  signedMessages = 0
}) {
  let score = 10;

  score += transactionCount * 2;

  if (reusedAddress) {
    score += 20;
  }

  score += signedMessages * 5;

  if (score > 100) {
    score = 100;
  }

  return score;
}
