export const RISK_LEVELS = {
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL"
};

export function getRiskLevel(score = 0) {
  if (score >= 90) return RISK_LEVELS.CRITICAL;
  if (score >= 70) return RISK_LEVELS.HIGH;
  if (score >= 40) return RISK_LEVELS.MEDIUM;
  return RISK_LEVELS.LOW;
}
