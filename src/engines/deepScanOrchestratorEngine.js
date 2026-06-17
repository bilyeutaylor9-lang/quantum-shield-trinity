/**
 * Quantum Shield Trinity
 * Deep Scan Orchestrator Engine
 *
 * Purpose:
 * Connects deep scan engines into one unified intelligence layer.
 */

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function countFindings(report = {}) {
  return safeArray(report.findings).length +
    safeArray(report.issues).length +
    safeArray(report.risks).length +
    safeArray(report.attackPaths).length +
    safeArray(report.nodes).length;
}

function normalizeRiskLevel(score = 0) {
  if (score >= 90) return "critical";
  if (score >= 75) return "high";
  if (score >= 50) return "medium";
  if (score >= 25) return "low";
  return "info";
}

export function deepScanOrchestratorEngine(reports = {}) {
  const engines = {
    codeFlow: reports.codeFlowReport,
    routeExposure: reports.routeExposureReport,
    trustBoundary: reports.trustBoundaryReport,
    evidenceGraph: reports.evidenceGraphReport,
    attackChains: reports.attackChainBuilderReport,
    dependencyBehavior: reports.dependencyBehaviorReport,
    semanticConfig: reports.semanticConfigReport
  };

  const engineSummaries = Object.entries(engines).map(([name, report]) => {
    const findings = countFindings(report);

    return {
      engine: name,
      enabled: Boolean(report),
      findings,
      riskContribution: findings * 5
    };
  });

  const totalFindings = engineSummaries.reduce(
    (sum, item) => sum + item.findings,
    0
  );

  const riskScore = Math.min(100, totalFindings * 5);
  const riskLevel = normalizeRiskLevel(riskScore);

  const topSignals = engineSummaries
    .filter((item) => item.findings > 0)
    .sort((a, b) => b.findings - a.findings)
    .slice(0, 10);

  return {
    engine: "deepScanOrchestratorEngine",
    version: "1.0.0",
    status: "complete",
    riskScore,
    riskLevel,
    totalFindings,
    enginesAnalyzed: engineSummaries.length,
    activeEngines: engineSummaries.filter((item) => item.enabled).length,
    engineSummaries,
    topSignals,
    recommendation:
      riskScore >= 75
        ? "Block deployment until deep scan findings are reviewed."
        : riskScore >= 50
          ? "Require security review before production release."
          : "Continue monitoring and improve coverage."
  };
}

export default deepScanOrchestratorEngine;
