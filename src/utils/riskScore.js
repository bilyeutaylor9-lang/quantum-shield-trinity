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

  if (transactionCount > 50) {
    score += 15;
  }

  if (signedMessages > 10) {
    score += 10;
  }

  return Math.min(score, 100);
}
