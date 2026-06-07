export function securityScoreEngine(reports = {}) {
  const score =
    100 -
    calculateRiskPenalty([
      reports.walletReport,
      reports.inventoryReport,
      reports.migrationReport,
      reports.forecastReport,
      reports.simulationReport,
      reports.assessmentReport
    ]);

  const securityScore = Math.max(0, Math.min(100, Math.round(score)));

  return {
    engine: "Security Score Engine",
    scannerVersion: "2.0.0",
    securityScore,
    riskLevel: getRiskLevel(securityScore),
    grade: getGrade(securityScore),
    summary: `Security Score: ${securityScore}/100. Risk Level: ${getRiskLevel(securityScore)}.`,
    topPriority: getTopPriority(securityScore)
  };
}

function calculateRiskPenalty(reports = []) {
  return reports.reduce((total, report) => {
    if (!report) return total;

    const text = JSON.stringify(report).toUpperCase();

    let penalty = 0;
    penalty += (text.match(/CRITICAL/g) || []).length * 15;
    penalty += (text.match(/HIGH/g) || []).length * 8;
    penalty += (text.match(/MEDIUM/g) || []).length * 4;
    penalty += (text.match(/LOW/g) || []).length * 1;

    return total + penalty;
  }, 0);
}

function getRiskLevel(score) {
  if (score >= 90) return "LOW";
  if (score >= 75) return "MEDIUM";
  if (score >= 50) return "HIGH";
  return "CRITICAL";
}

function getGrade(score) {
  if (score >= 95) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function getTopPriority(score) {
  if (score >= 90) {
    return "Maintain current security posture and continue monitoring.";
  }

  if (score >= 75) {
    return "Review medium and high-risk findings before production use.";
  }

  if (score >= 50) {
    return "Prioritize high-risk findings and reduce exposed attack paths.";
  }

  return "Immediately address critical findings before deployment.";
}
