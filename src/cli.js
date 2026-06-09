import { fileScanner } from "./scanners/fileScanner.js";
import { repositoryScannerEngine } from "./engines/repositoryScannerEngine.js";
import { dependencyIntelligenceEngine } from "./engines/dependencyIntelligenceEngine.js";
import { dependencyRiskEngine } from "./engines/dependencyRiskEngine.js";
import { attackSurfaceEngine } from "./engines/attackSurfaceEngine.js";
import { smartContractAuditEngine } from "./engines/smartContractAuditEngine.js";
import { exploitSimulationEngine } from "./engines/exploitSimulationEngine.js";
import { securityScoreEngine } from "./engines/securityScoreEngine.js";
import { remediationEngine } from "./engines/remediationEngine.js";
import { quantumReadinessEngine } from "./engines/quantumReadinessEngine.js";
import { cryptoInventoryEngine } from "./engines/cryptoInventoryEngine.js";
import { autoFixEngine } from "./engines/autoFixEngine.js";
import { attackPathGeneratorEngine } from "./engines/attackPathGeneratorEngine.js";
import { complianceMappingEngine } from "./engines/complianceMappingEngine.js";
import { executiveReportEngine } from "./engines/executiveReportEngine.js";
import { jsonExportEngine } from "./engines/jsonExportEngine.js";
import { migrationShieldEngine } from "./engines/migrationShieldEngine.js";
import { quantumAttackSimulationEngine } from "./engines/quantumAttackSimulationEngine.js";
import { quantumExposureForecastEngine } from "./engines/quantumExposureForecastEngine.js";
import { codeFlowScannerEngine } from "./engines/codeFlowScannerEngine.js";
import { routeExposureEngine } from "./engines/routeExposureEngine.js";
import { trustBoundaryEngine } from "./engines/trustBoundaryEngine.js";
import { attackChainBuilderEngine } from "./engines/attackChainBuilderEngine.js";
import { createEvidenceGraph } from "./engines/evidenceGraphEngine.js";
import { htmlReportGenerator } from "./reporters/htmlReportGenerator.js";
import { sarifReportGenerator } from "./reporters/sarifReportGenerator.js";
import { securityBadgeGenerator } from "./reporters/securityBadgeGenerator.js";
import { summaryFormatter } from "./utils/summaryFormatter.js";
import { markdownReportGenerator } from "./reporters/markdownReportGenerator.js";
import fs from "fs";

const targetDirectory = process.argv[2] ?? "src";

const findPackageJson = (files = []) => {
  const packageFile = files.find(file => {
    const filePath = file.path ?? file.file ?? file.name ?? file.filename ?? "";
    return filePath.endsWith("package.json");
  });

  if (!packageFile) return {};

  try {
    const raw = packageFile.content ?? packageFile.text ?? packageFile.source ?? "{}";
    return typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch (error) {
    console.warn("Warning: package.json was found but could not be parsed.");
    console.warn(error.message);
    return {};
  }
};

const normalizeDependencyRiskFinding = (item = {}) => ({
  ...item,
  type: item.type ?? "dependency_risk",
  title: item.title ?? `${item.dependency ?? "Dependency"} risk`,
  description: item.description ?? item.reason ?? item.recommendation ?? "",
  severity: String(item.severity ?? "info").toLowerCase(),
  riskLevel: String(item.severity ?? "info").toLowerCase(),
  file: item.file ?? "package.json",
  line: item.line ?? null,
  category: item.category ?? "Dependency Risk",
  ruleId: item.ruleId ?? `DEPENDENCY_RISK_${String(item.dependency ?? "UNKNOWN").toUpperCase().replace(/[^A-Z0-9]/g, "_")}`,
  confidence: typeof item.confidence === "number" ? item.confidence / 100 : 0.75,
  recommendation: item.recommendation
});


console.log("Quantum Shield Trinity");
console.log("----------------------");
console.log(`Scanning directory: ${targetDirectory}`);
console.log("");

const scanResult = fileScanner(targetDirectory);
const report = repositoryScannerEngine(scanResult.files);
const packageJson = findPackageJson(scanResult.files);
const dependencyRiskReport = dependencyRiskEngine(packageJson);
dependencyRiskReport.findings = dependencyRiskReport.findings.map(normalizeDependencyRiskFinding);

const dependencyReport = dependencyIntelligenceEngine(scanResult.files);
const attackSurfaceReport = attackSurfaceEngine(scanResult.files);
const smartContractAuditReport = smartContractAuditEngine(scanResult.files);
const quantumReadinessReport = quantumReadinessEngine(scanResult.files);
const cryptoInventoryReport = cryptoInventoryEngine(scanResult.files);

const walletMigrationProfile = report.walletRiskReport ?? report.walletReport ?? {
  score: report.walletRiskScore ?? 0,
  riskLevel: report.walletRiskLevel ?? "UNKNOWN"
};

const migrationShieldReport = migrationShieldEngine(
  walletMigrationProfile,
  cryptoInventoryReport
);

const quantumExposureForecastReport = quantumExposureForecastEngine({
  walletReport: walletMigrationProfile,
  inventoryReport: {
    ...cryptoInventoryReport,
    score:
      cryptoInventoryReport.score ??
      cryptoInventoryReport.inventorySecurityScore ??
      cryptoInventoryReport.inventoryRiskScore ??
      0
  },
  migrationReport: migrationShieldReport
});

const quantumAttackSimulationReport = quantumAttackSimulationEngine({
  walletReport: walletMigrationProfile,
  inventoryReport: cryptoInventoryReport,
  migrationReport: migrationShieldReport,
  forecastReport: quantumExposureForecastReport
});

// Deep Scan X engines
const codeFlowReport = codeFlowScannerEngine(scanResult.files);
const routeExposureReport = routeExposureEngine(scanResult.files);
const trustBoundaryReport = trustBoundaryEngine(scanResult.files, {
  codeFlowReport,
  routeExposureReport
});

report.dependencyReport = dependencyReport;
report.dependencyRiskReport = dependencyRiskReport;
report.attackSurfaceReport = attackSurfaceReport;
report.smartContractAuditReport = smartContractAuditReport;
report.quantumReadinessReport = quantumReadinessReport;
report.cryptoInventoryReport = cryptoInventoryReport;
report.inventoryReport = cryptoInventoryReport;
report.migrationShieldReport = migrationShieldReport;
report.migrationReport = migrationShieldReport;
report.quantumExposureForecastReport = quantumExposureForecastReport;
report.forecastReport = quantumExposureForecastReport;
report.quantumAttackSimulationReport = quantumAttackSimulationReport;
report.simulationReport = quantumAttackSimulationReport;
report.codeFlowReport = codeFlowReport;
report.routeExposureReport = routeExposureReport;
report.trustBoundaryReport = trustBoundaryReport;

const exploitSimulationReport = exploitSimulationEngine(report);
report.exploitSimulationReport = exploitSimulationReport;

const securityScoreReport = securityScoreEngine({
  dependencyReport,
  dependencyRiskReport,
  attackSurfaceReport,
  smartContractAuditReport,
  exploitSimulationReport,
  quantumReadinessReport,
  cryptoInventoryReport,
  migrationShieldReport,
  quantumExposureForecastReport,
  quantumAttackSimulationReport,
  codeFlowReport,
  routeExposureReport,
  trustBoundaryReport,
  repositoryReport: report
});

report.securityScoreReport = securityScoreReport;

const remediationReport = remediationEngine(report);
report.remediationReport = remediationReport;

const autoFixReport = autoFixEngine(report);
report.autoFixReport = autoFixReport;

const attackPathReport = attackPathGeneratorEngine(report);
report.attackPathReport = attackPathReport;

const complianceMappingReport = complianceMappingEngine(report);
report.complianceMappingReport = complianceMappingReport;


// Merge Dependency Risk Engine findings into dependencyReport for attack-chain correlation.
const dependencyFindingsForChains = [
  ...(dependencyReport.dependencyFindings ?? []),
  ...(dependencyRiskReport.findings ?? [])
];
report.dependencyReport = {
  ...dependencyReport,
  dependencyFindings: dependencyFindingsForChains
};

// Build advanced attack chains after all major reports exist.
const attackChainBuilderReport = attackChainBuilderEngine(report, {
  maxDepth: 5,
  limit: 50
});
report.attackChainBuilderReport = attackChainBuilderReport;

//============================================================================
// EVIDENCE GRAPH INTEGRATION
//============================================================================

const evidenceGraph = createEvidenceGraph({
  autoLinkByFile: true,
  autoLinkByRule: true,
  autoLinkByAsset: true,
  maxAttackChainDepth: 6
});

const addEvidenceItems = (items = [], engine = "unknown", fallbackCategory = "general") => {
  if (!Array.isArray(items)) return;

  items.forEach((item, index) => {
    evidenceGraph.addFinding({
      id: item.id ?? `${engine}-${index + 1}`,
      type: item.type ?? item.dependency ?? item.simulationName ?? fallbackCategory,
      category: item.category ?? fallbackCategory,
      title: item.title ?? item.type ?? item.dependency ?? item.simulationName ?? "Security Finding",
      description:
        item.description ??
        item.risk ??
        item.whyItMatters ??
        item.potentialImpact ??
        item.recommendation ??
        item.summary ??
        "",
      severity:
        item.severity ??
        item.riskLevel ??
        item.routeExposureRiskLevel ??
        item.trustBoundaryRiskLevel ??
        item.attackChainRiskLevel ??
        "info",
      confidence: item.confidence ?? item.likelihood ?? 0.75,
      file: item.file ?? item.path ?? null,
      line: item.line ?? null,
      ruleId: item.ruleId ?? item.rule ?? item.cwe ?? null,
      engine,
      cwe: item.cwe ? [item.cwe] : [],
      owasp: [
        item.owaspSmartContractTop10,
        item.owaspWebTop10
      ].filter(Boolean),
      snippet:
        item.snippet ??
        item.code ??
        item.evidence?.snippet ??
        item.evidence ??
        "",
      matchedText: item.evidence?.matchedText ?? item.matchedText ?? "",
      attackSurface:
        item.attackSurface ??
        item.affectedArea ??
        item.method ??
        [],
      assets: [
        ...(Array.isArray(item.assets) ? item.assets : []),
        item.dependency,
        item.asset,
        item.contract,
        item.file,
        item.path,
        item.route,
        item.method,
        item.entryPoint,
        item.finalImpact,
        item.sink?.label,
        item.source?.label
      ].filter(Boolean),
      remediation: [
        item.recommendation,
        item.howToFix,
        item.recommendedFix,
        item.recommendedDefense,
        item.migrationPath,
        ...(Array.isArray(item.remediation) ? item.remediation : []),
        ...(Array.isArray(item.recommendations) ? item.recommendations : [])
      ].filter(Boolean),
      metadata: item
    });
  });
};

addEvidenceItems(cryptoInventoryReport.assets, "cryptoInventoryEngine", "crypto_inventory");
addEvidenceItems(
  migrationShieldReport.recommendations.map((recommendation, index) => ({
    id: `migration-shield-${index + 1}`,
    type: "migration_recommendation",
    category: "migration_shield",
    title: "Migration Shield Recommendation",
    description: recommendation,
    severity: migrationShieldReport.migrationReady ? "low" : "medium",
    confidence: 0.8,
    recommendation,
    remediation: [recommendation],
    assets: ["migration", "crypto_agility"]
  })),
  "migrationShieldEngine",
  "migration_shield"
);

addEvidenceItems(
  [
    {
      id: "quantum-exposure-forecast",
      type: "quantum_exposure_forecast",
      category: "quantum_exposure_forecast",
      title: "Quantum Exposure Forecast",
      description: quantumExposureForecastReport.businessImpact,
      severity:
        quantumExposureForecastReport.qDayExposure === "CRITICAL"
          ? "critical"
          : quantumExposureForecastReport.qDayExposure === "HIGH"
            ? "high"
            : quantumExposureForecastReport.qDayExposure === "MEDIUM"
              ? "medium"
              : "low",
      confidence: 0.8,
      recommendation: `Migration urgency: ${quantumExposureForecastReport.migrationUrgency}`,
      remediation: [`Migration urgency: ${quantumExposureForecastReport.migrationUrgency}`],
      assets: ["quantum_exposure", "forecast", "crypto_agility"]
    }
  ],
  "quantumExposureForecastEngine",
  "quantum_exposure_forecast"
);

addEvidenceItems(
  quantumAttackSimulationReport.attackPath.map((step, index) => ({
    id: `quantum-attack-simulation-${index + 1}`,
    type: "quantum_attack_simulation",
    category: "quantum_attack_simulation",
    title: "Quantum Attack Simulation Step",
    description: step,
    severity:
      quantumAttackSimulationReport.estimatedImpact === "HIGH"
        ? "high"
        : quantumAttackSimulationReport.estimatedImpact === "MEDIUM"
          ? "medium"
          : "low",
    confidence: 0.8,
    recommendation: "Review quantum exposure path and prioritize crypto-agility remediation.",
    remediation: ["Review quantum exposure path and prioritize crypto-agility remediation."],
    assets: ["quantum_exposure", "migration", "crypto_inventory"]
  })),
  "quantumAttackSimulationEngine",
  "quantum_attack_simulation"
);
addEvidenceItems(quantumReadinessReport.findings, "quantumReadinessEngine", "quantum_readiness");
addEvidenceItems(dependencyReport.dependencyFindings, "dependencyIntelligenceEngine", "dependency_intelligence");
addEvidenceItems(dependencyRiskReport.findings, "dependencyRiskEngine", "dependency_risk");
addEvidenceItems(attackSurfaceReport.attackFindings, "attackSurfaceEngine", "attack_surface");
addEvidenceItems(smartContractAuditReport.auditFindings, "smartContractAuditEngine", "smart_contract_audit");

// Deep Scan X evidence
addEvidenceItems(codeFlowReport.findings, "codeFlowScannerEngine", "code_flow");
addEvidenceItems(routeExposureReport.findings, "routeExposureEngine", "route_exposure");
addEvidenceItems(trustBoundaryReport.findings, "trustBoundaryEngine", "trust_boundary");
addEvidenceItems(attackChainBuilderReport.attackChains, "attackChainBuilderEngine", "attack_chain_builder");

addEvidenceItems(exploitSimulationReport.simulations, "exploitSimulationEngine", "exploit_simulation");
addEvidenceItems(remediationReport.remediationItems, "remediationEngine", "remediation");
addEvidenceItems(autoFixReport.fixes, "autoFixEngine", "auto_fix");
addEvidenceItems(attackPathReport.attackPaths, "attackPathGeneratorEngine", "attack_path");
addEvidenceItems(complianceMappingReport.mappedFindings, "complianceMappingEngine", "compliance_mapping");

const evidenceGraphReport = evidenceGraph.exportGraph();
report.evidenceGraphReport = evidenceGraphReport;

//============================================================================
// EXECUTIVE REPORT ENGINE
//============================================================================

const executiveReportEngineReport = executiveReportEngine({
  ...report,
  executiveReport: {
    summary: summaryFormatter(report)
  },
  assessmentReport: report.securityAssessmentReport ?? report.assessmentReport ?? {},
  auditReport: report.securityAuditReport ?? report.auditReport ?? smartContractAuditReport,
  riskProfile: {
    wallet: report.walletRiskReport ?? {},
    inventory: {
      riskLevel:
        cryptoInventoryReport.inventoryRiskLevel ??
        cryptoInventoryReport.riskLevel ??
        "UNKNOWN"
    },
    migration: {
      ready:
        quantumReadinessReport.migrationReadiness === "READY" ||
        quantumReadinessReport.migrationReady === true
    }
  }
});

report.executiveReportEngineReport = executiveReportEngineReport;

//============================================================================
// JSON EXPORT ENGINE
//============================================================================

const jsonExportReport = jsonExportEngine({
  platform: "Quantum Shield Trinity",
  version: "2.2.2",
  ...report,
  riskProfile: {
    wallet: report.walletRiskReport ?? {},
    inventory: {
      riskLevel:
        cryptoInventoryReport.inventoryRiskLevel ??
        cryptoInventoryReport.riskLevel ??
        "UNKNOWN",
      totalCryptoAssets: cryptoInventoryReport.totalCryptoAssets,
      quantumExposedAssets: cryptoInventoryReport.quantumExposedAssets
    },
    migration: {
      ready:
        migrationShieldReport.migrationReady === true ||
        quantumReadinessReport.migrationReadiness === "READY" ||
        quantumReadinessReport.migrationReady === true,
      readinessScore: quantumReadinessReport.quantumReadinessScore,
      recommendedPath: quantumReadinessReport.recommendedMigrationPath,
      shieldReady: migrationShieldReport.migrationReady,
      forecastQDayExposure: quantumExposureForecastReport.qDayExposure,
      forecastMigrationUrgency: quantumExposureForecastReport.migrationUrgency,
      shieldRecommendations: migrationShieldReport.recommendations
    },
    dependencyRisk: {
      riskLevel: dependencyRiskReport.riskLevel,
      riskScore: dependencyRiskReport.riskScore
    },
    deepScan: {
      codeFlowRiskLevel: codeFlowReport.riskLevel,
      routeExposureRiskLevel: routeExposureReport.routeExposureRiskLevel,
      trustBoundaryRiskLevel: trustBoundaryReport.trustBoundaryRiskLevel,
      attackChainRiskLevel: attackChainBuilderReport.attackChainRiskLevel,
      quantumForecastExposure: quantumExposureForecastReport.qDayExposure,
      quantumForecastScore: quantumExposureForecastReport.score,
      quantumAttackBusinessRisk: quantumAttackSimulationReport.businessRisk,
      quantumAttackEstimatedImpact: quantumAttackSimulationReport.estimatedImpact,
      evidenceGraphRiskLevel: evidenceGraphReport.summary?.risk?.level
    }
  },
  assessmentReport: report.securityAssessmentReport ?? report.assessmentReport ?? securityScoreReport,
  auditReport: report.securityAuditReport ?? report.auditReport ?? smartContractAuditReport,
  walletReport: report.walletRiskReport ?? {},
  inventoryReport: cryptoInventoryReport,
  migrationReport: { quantumReadinessReport, migrationShieldReport },
  forecastReport: quantumExposureForecastReport,
  simulationReport: { exploitSimulationReport, quantumAttackSimulationReport }
});

report.jsonExportReport = jsonExportReport;

//============================================================================
// REPORT GENERATION
//============================================================================

const summary = summaryFormatter(report);
const markdownReport = markdownReportGenerator(report);

const htmlReport = htmlReportGenerator({
  ...report,
  executiveReport: {
    summary,
    markdownReport
  }
});

const sarifReport = sarifReportGenerator({
  ...report,
  version: "2.0.0"
});

const securityBadgeReport = securityBadgeGenerator(report);

fs.writeFileSync("report.json", JSON.stringify(report, null, 2), "utf8");
fs.writeFileSync("report.html", htmlReport, "utf8");
fs.writeFileSync("evidence-graph.json", JSON.stringify(evidenceGraphReport, null, 2), "utf8");
fs.writeFileSync("dependency-risk-report.json", JSON.stringify(dependencyRiskReport, null, 2), "utf8");
fs.writeFileSync("executive-summary.json", JSON.stringify(executiveReportEngineReport, null, 2), "utf8");
fs.writeFileSync("quantum-risk-export.json", JSON.stringify(jsonExportReport, null, 2), "utf8");
fs.writeFileSync("migration-shield-report.json", JSON.stringify(migrationShieldReport, null, 2), "utf8");
fs.writeFileSync("quantum-exposure-forecast-report.json", JSON.stringify(quantumExposureForecastReport, null, 2), "utf8");
fs.writeFileSync("quantum-attack-simulation-report.json", JSON.stringify(quantumAttackSimulationReport, null, 2), "utf8");
fs.writeFileSync("code-flow-report.json", JSON.stringify(codeFlowReport, null, 2), "utf8");
fs.writeFileSync("route-exposure-report.json", JSON.stringify(routeExposureReport, null, 2), "utf8");
fs.writeFileSync("trust-boundary-report.json", JSON.stringify(trustBoundaryReport, null, 2), "utf8");
fs.writeFileSync("attack-chain-builder-report.json", JSON.stringify(attackChainBuilderReport, null, 2), "utf8");

fs.writeFileSync(
  "executive-report.json",
  JSON.stringify(
    {
      platform: "Quantum Shield Trinity",
      version: "2.2.1",
      summary,
      markdownReport,
      securityScoreReport,
      executiveReportEngineReport,
      jsonExportReport,
      remediationReport,
      quantumReadinessReport,
      cryptoInventoryReport,
      migrationShieldReport,
      quantumExposureForecastReport,
      quantumAttackSimulationReport,
      dependencyRiskReport,
      codeFlowReport,
      routeExposureReport,
      trustBoundaryReport,
      attackChainBuilderReport,
      autoFixReport,
      attackPathReport,
      complianceMappingReport,
      evidenceGraphReport,
      securityBadgeReport
    },
    null,
    2
  ),
  "utf8"
);

fs.writeFileSync("report.sarif", JSON.stringify(sarifReport, null, 2), "utf8");
fs.writeFileSync("badge.svg", securityBadgeReport.svg, "utf8");
fs.writeFileSync("badge.html", securityBadgeReport.html, "utf8");

fs.writeFileSync(
  "badge.json",
  JSON.stringify(securityBadgeReport.badgeData, null, 2),
  "utf8"
);

//============================================================================
// CONSOLE OUTPUT
//============================================================================

console.log("Executive Summary");
console.log("-----------------");
console.log(`Risk Level: ${summary.repositoryRiskLevel}`);
console.log(`Score: ${summary.score}/100`);
console.log(`Scanned Files: ${summary.scannedFiles}`);
console.log(`Critical Findings: ${summary.criticalFindings}`);
console.log(`High Findings: ${summary.highFindings}`);
console.log(`Medium Findings: ${summary.mediumFindings}`);
console.log("");

console.log("Executive Report Engine");
console.log("-----------------------");
console.log(`Headline: ${executiveReportEngineReport.headline}`);
console.log(`Report Type: ${executiveReportEngineReport.reportType}`);
console.log(`Security Score: ${executiveReportEngineReport.keyMetrics?.securityScore ?? "N/A"}`);
console.log(`Risk Level: ${executiveReportEngineReport.keyMetrics?.riskLevel ?? "UNKNOWN"}`);
console.log(`Grade: ${executiveReportEngineReport.keyMetrics?.grade ?? "N/A"}`);
console.log("");

if (executiveReportEngineReport.recommendedActions?.length > 0) {
  console.log("Executive Recommended Actions");
  console.log("-----------------------------");
  executiveReportEngineReport.recommendedActions.slice(0, 5).forEach((action, index) => {
    console.log(`${index + 1}. ${action}`);
  });
  console.log("");
}

console.log("JSON Export Engine");
console.log("------------------");
console.log(`Export Type: ${jsonExportReport.exportType}`);
console.log(`Schema Version: ${jsonExportReport.schemaVersion}`);
console.log(`Exported At: ${jsonExportReport.exportedAt}`);
console.log("");

console.log("Deep Scan X");
console.log("-----------");
console.log(`Code Flow Risk Level: ${codeFlowReport.riskLevel}`);
console.log(`Code Flow Score: ${codeFlowReport.score}/100`);
console.log(`Total Source/Sink Flows: ${codeFlowReport.totalFlows}`);
console.log(`Critical Flows: ${codeFlowReport.criticalFlows}`);
console.log(`High Flows: ${codeFlowReport.highFlows}`);
console.log(`Medium Flows: ${codeFlowReport.mediumFlows}`);
console.log("");
console.log(`Route Exposure Risk Level: ${routeExposureReport.routeExposureRiskLevel}`);
console.log(`Route Exposure Score: ${routeExposureReport.routeExposureScore}/100`);
console.log(`Total Routes: ${routeExposureReport.totalRoutes}`);
console.log(`Public Routes: ${routeExposureReport.publicRoutes}`);
console.log(`Sensitive Routes: ${routeExposureReport.sensitiveRoutes}`);
console.log(`Critical Routes: ${routeExposureReport.criticalRoutes}`);
console.log(`High Routes: ${routeExposureReport.highRoutes}`);
console.log("");
console.log(`Trust Boundary Risk Level: ${trustBoundaryReport.trustBoundaryRiskLevel}`);
console.log(`Trust Boundary Score: ${trustBoundaryReport.trustBoundaryScore}/100`);
console.log(`Total Trust Boundary Findings: ${trustBoundaryReport.totalTrustBoundaryFindings}`);
console.log(`Critical Trust Boundaries: ${trustBoundaryReport.criticalTrustBoundaries}`);
console.log(`High Trust Boundaries: ${trustBoundaryReport.highTrustBoundaries}`);
console.log(`Medium Trust Boundaries: ${trustBoundaryReport.mediumTrustBoundaries}`);
console.log("");
console.log(`Attack Chain Builder Risk Level: ${attackChainBuilderReport.attackChainRiskLevel}`);
console.log(`Attack Chain Builder Score: ${attackChainBuilderReport.attackChainScore}/100`);
console.log(`Total Built Attack Chains: ${attackChainBuilderReport.totalAttackChains}`);
console.log(`Critical Built Chains: ${attackChainBuilderReport.criticalAttackChains}`);
console.log(`High Built Chains: ${attackChainBuilderReport.highAttackChains}`);
console.log("");

console.log("Evidence Graph");
console.log("--------------");
console.log(`Evidence Nodes: ${evidenceGraphReport.nodes.length}`);
console.log(`Evidence Edges: ${evidenceGraphReport.edges.length}`);
console.log(`Graph Risk Score: ${evidenceGraphReport.summary.risk.score}/1000`);
console.log(`Graph Risk Level: ${evidenceGraphReport.summary.risk.level}`);
console.log(`Attack Chains Found: ${evidenceGraphReport.summary.attackChains.length}`);
console.log("");

console.log("Crypto Inventory");
console.log("----------------");
console.log(`Inventory Risk Level: ${cryptoInventoryReport.inventoryRiskLevel}`);
console.log(`Inventory Security Score: ${cryptoInventoryReport.inventorySecurityScore}/100`);
console.log(`Total Crypto Assets: ${cryptoInventoryReport.totalCryptoAssets}`);
console.log(`Quantum Exposed Assets: ${cryptoInventoryReport.quantumExposedAssets}`);
console.log(`Critical Crypto Assets: ${cryptoInventoryReport.criticalAssets}`);
console.log(`High Crypto Assets: ${cryptoInventoryReport.highAssets}`);
console.log(`Summary: ${cryptoInventoryReport.quantumExposureSummary}`);
console.log("");

if (cryptoInventoryReport.recommendedActions.length > 0) {
  console.log("Crypto Inventory Recommended Actions");
  console.log("------------------------------------");
  cryptoInventoryReport.recommendedActions.forEach((action, index) => {
    console.log(`${index + 1}. ${action}`);
  });
  console.log("");
}

console.log("Executive Security Score");
console.log("------------------------");
console.log(`Security Score: ${securityScoreReport.securityScore ?? "N/A"}/100`);
console.log(`Risk Level: ${securityScoreReport.riskLevel ?? "UNKNOWN"}`);
console.log(`Grade: ${securityScoreReport.grade ?? securityScoreReport.securityGrade ?? "N/A"}`);
console.log(`Top Priority: ${securityScoreReport.topPriority ?? "Review high and critical findings."}`);
console.log("");

console.log("Quantum Readiness");
console.log("-----------------");
console.log(`Quantum Readiness Score: ${quantumReadinessReport.quantumReadinessScore}/100`);
console.log(`Quantum Risk Level: ${quantumReadinessReport.quantumRiskLevel}`);
console.log(`Quantum Findings: ${quantumReadinessReport.totalQuantumFindings}`);
console.log(`Migration Readiness: ${quantumReadinessReport.migrationReadiness}`);
console.log(`Recommended Path: ${quantumReadinessReport.recommendedMigrationPath}`);
console.log("");

console.log("Migration Shield");
console.log("----------------");
console.log(`Migration Ready: ${migrationShieldReport.migrationReady}`);
console.log(`Recommendations: ${migrationShieldReport.recommendations.length}`);
migrationShieldReport.recommendations.forEach((item, index) => {
  console.log(`${index + 1}. ${item}`);
});
console.log("");

console.log("Quantum Exposure Forecast");
console.log("-------------------------");
console.log(`Forecast Score: ${quantumExposureForecastReport.score}/100`);
console.log(`Q-Day Exposure: ${quantumExposureForecastReport.qDayExposure}`);
console.log(`Harvest Now Decrypt Later Risk: ${quantumExposureForecastReport.harvestNowDecryptLaterRisk}`);
console.log(`Migration Urgency: ${quantumExposureForecastReport.migrationUrgency}`);
console.log(`Business Impact: ${quantumExposureForecastReport.businessImpact}`);
console.log("");

console.log("Quantum Attack Simulation");
console.log("-------------------------");
console.log(`Estimated Impact: ${quantumAttackSimulationReport.estimatedImpact}`);
console.log(`Business Risk: ${quantumAttackSimulationReport.businessRisk}`);
console.log(`Attack Path Steps: ${quantumAttackSimulationReport.attackPath.length}`);
if (quantumAttackSimulationReport.attackPath.length > 0) {
  quantumAttackSimulationReport.attackPath.forEach((step, index) => {
    console.log(`${index + 1}. ${step}`);
  });
}
console.log(`Note: ${quantumAttackSimulationReport.note}`);
console.log("");

console.log("Dependency Intelligence");
console.log("-----------------------");
console.log(`Dependency Risk Level: ${dependencyReport.dependencyRiskLevel}`);
console.log(`Dependency Files Scanned: ${dependencyReport.scannedDependencyFiles}`);
console.log(`High Risk Dependencies: ${dependencyReport.highRiskDependencies}`);
console.log(`Medium Risk Dependencies: ${dependencyReport.mediumRiskDependencies}`);
console.log("");


console.log("Dependency Risk Engine");
console.log("----------------------");
console.log(`Dependency Risk Level: ${dependencyRiskReport.riskLevel}`);
console.log(`Dependency Risk Score: ${dependencyRiskReport.riskScore}/100`);
console.log(`Scanned Dependencies: ${dependencyRiskReport.scannedDependencies}`);
console.log(`Total Dependency Risk Findings: ${dependencyRiskReport.counts?.totalFindings ?? dependencyRiskReport.findings.length}`);
console.log(`Critical Dependency Risk Findings: ${dependencyRiskReport.counts?.criticalFindings ?? 0}`);
console.log(`High Dependency Risk Findings: ${dependencyRiskReport.counts?.highFindings ?? 0}`);
console.log(`Medium Dependency Risk Findings: ${dependencyRiskReport.counts?.mediumFindings ?? 0}`);
console.log("");

if (dependencyRiskReport.findings.length > 0) {
  console.log("Top Dependency Risk Findings");
  console.log("----------------------------");
  dependencyRiskReport.findings.slice(0, 10).forEach((item, index) => {
    console.log(`${index + 1}. ${item.dependency} (${item.severity})`);
    console.log(` Version: ${item.version}`);
    console.log(` Category: ${item.category}`);
    console.log(` Reason: ${item.reason}`);
    console.log(` Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

console.log("Attack Surface Intelligence");
console.log("---------------------------");
console.log(`Attack Surface Risk Level: ${attackSurfaceReport.attackSurfaceRiskLevel}`);
console.log(`Attack Surface Score: ${attackSurfaceReport.attackSurfaceScore}/100`);
console.log(`Total Attack Findings: ${attackSurfaceReport.totalAttackFindings}`);
console.log(`Critical Attack Paths: ${attackSurfaceReport.criticalAttackPaths}`);
console.log(`High Attack Paths: ${attackSurfaceReport.highAttackPaths}`);
console.log(`Medium Attack Paths: ${attackSurfaceReport.mediumAttackPaths}`);
console.log("");

console.log("Smart Contract Audit");
console.log("--------------------");
console.log(`Audit Risk Level: ${smartContractAuditReport.auditRiskLevel}`);
console.log(`Audit Score: ${smartContractAuditReport.auditSecurityScore}/100`);
console.log(`Audited Contracts: ${smartContractAuditReport.auditedContracts}`);
console.log(`Critical Audit Findings: ${smartContractAuditReport.criticalFindings}`);
console.log(`High Audit Findings: ${smartContractAuditReport.highFindings}`);
console.log(`Medium Audit Findings: ${smartContractAuditReport.mediumFindings}`);
console.log("");

console.log("Exploit Simulation");
console.log("------------------");
console.log(`Simulation Risk Level: ${exploitSimulationReport.simulationRiskLevel}`);
console.log(`Simulation Score: ${exploitSimulationReport.simulationScore}/100`);
console.log(`Total Simulations: ${exploitSimulationReport.totalSimulations}`);
console.log(`Critical Simulations: ${exploitSimulationReport.criticalSimulations}`);
console.log(`High Simulations: ${exploitSimulationReport.highSimulations}`);
console.log("");

console.log("Remediation Guidance");
console.log("--------------------");
console.log(`Total Remediation Items: ${remediationReport.totalRemediationItems}`);
console.log("");

remediationReport.remediationItems.slice(0, 5).forEach((item, index) => {
  console.log(`${index + 1}. ${item.type} (${item.severity})`);
  console.log(` File: ${item.file}`);
  console.log(` Line: ${item.line}`);
  console.log(` Priority: ${item.priority}`);
  console.log(` Why It Matters: ${item.whyItMatters}`);
  console.log(` Fix: ${item.howToFix}`);
  console.log(` Example Fix: ${item.exampleFix}`);
  console.log("");
});

console.log("AutoFix Suggestions");
console.log("-------------------");
console.log(`Total Fixes: ${autoFixReport.totalFixes}`);
console.log(`Safe AutoFixes: ${autoFixReport.safeAutoFixes}`);
console.log(`Manual Review Fixes: ${autoFixReport.manualReviewFixes}`);
console.log("");

autoFixReport.fixes.slice(0, 5).forEach((item, index) => {
  console.log(`${index + 1}. ${item.type} (${item.severity})`);
  console.log(` File: ${item.file}`);
  console.log(` Line: ${item.line}`);
  console.log(` Confidence: ${item.confidence}`);
  console.log(` Recommended Fix: ${item.recommendedFix}`);
  console.log(` Patch Suggestion: ${item.patchSuggestion}`);
  console.log("");
});

console.log("Generated Attack Paths");
console.log("----------------------");
console.log(`Total Attack Paths: ${attackPathReport.totalAttackPaths}`);
console.log(`Critical Attack Paths: ${attackPathReport.criticalAttackPaths}`);
console.log(`High Attack Paths: ${attackPathReport.highAttackPaths}`);
console.log(`Medium Attack Paths: ${attackPathReport.mediumAttackPaths}`);
console.log("");

attackPathReport.attackPaths.slice(0, 5).forEach((item, index) => {
  console.log(`${index + 1}. ${item.title} (${item.severity})`);
  console.log(` File: ${item.file}`);
  console.log(` Line: ${item.line}`);
  console.log(` Entry Point: ${item.entryPoint}`);
  console.log(` Impact: ${item.potentialImpact}`);
  console.log(` Likelihood: ${item.likelihood}`);
  console.log(` Defense: ${item.recommendedDefense}`);
  console.log("");
});

console.log("Built Attack Chains");
console.log("-------------------");
attackChainBuilderReport.attackChains.slice(0, 10).forEach((item, index) => {
  console.log(`${index + 1}. ${item.summary} (${item.severity})`);
  console.log(` Score: ${item.chainScore}`);
  console.log(` Exploitability: ${item.exploitability}`);
  console.log(` Entry Point: ${item.entryPoint}`);
  console.log(` Final Impact: ${item.finalImpact}`);
  console.log(` Files: ${item.files?.join(", ") || "N/A"}`);
  console.log("");
});

console.log("Code Flow Findings");
console.log("------------------");
codeFlowReport.findings.slice(0, 10).forEach((item, index) => {
  console.log(`${index + 1}. ${item.title} (${item.severity})`);
  console.log(` File: ${item.file}`);
  console.log(` Line: ${item.line}`);
  console.log(` Source: ${item.source?.label ?? "Unknown"}`);
  console.log(` Sink: ${item.sink?.label ?? "Unknown"}`);
  console.log(` Sanitized Nearby: ${item.sanitized}`);
  console.log(` Recommendation: ${item.recommendation}`);
  console.log("");
});

console.log("Route Exposure Findings");
console.log("-----------------------");
routeExposureReport.findings.slice(0, 10).forEach((item, index) => {
  console.log(`${index + 1}. ${item.method} ${item.path} (${item.severity})`);
  console.log(` File: ${item.file}`);
  console.log(` Line: ${item.line}`);
  console.log(` Framework: ${item.framework}`);
  console.log(` Auth Detected: ${item.hasAuth}`);
  console.log(` Validation Detected: ${item.hasValidation}`);
  console.log(` Recommendation: ${item.recommendation}`);
  console.log("");
});

console.log("Trust Boundary Findings");
console.log("-----------------------");
trustBoundaryReport.findings.slice(0, 10).forEach((item, index) => {
  console.log(`${index + 1}. ${item.title} (${item.severity})`);
  console.log(` File: ${item.file}`);
  console.log(` Line: ${item.line}`);
  console.log(` Category: ${item.category}`);
  console.log(` Trust Control Detected: ${item.trustControlDetected ?? "N/A"}`);
  console.log(` Recommendation: ${item.recommendation}`);
  console.log("");
});

console.log("CWE / OWASP Mapping");
console.log("-------------------");
console.log(`Mapped Findings: ${complianceMappingReport.totalMappedFindings}`);
console.log("");

complianceMappingReport.mappedFindings.slice(0, 5).forEach((item, index) => {
  console.log(`${index + 1}. ${item.type} (${item.severity})`);
  console.log(` CWE: ${item.cwe}`);
  console.log(` OWASP Smart Contract: ${item.owaspSmartContractTop10}`);
  console.log(` OWASP Web: ${item.owaspWebTop10}`);
  console.log(` Control: ${item.recommendedControl}`);
  console.log("");
});

console.log("Security Badge");
console.log("--------------");
console.log("SVG Badge: badge.svg");
console.log("HTML Badge: badge.html");
console.log("JSON Badge: badge.json");
console.log(`Badge Status: ${securityBadgeReport.badgeData.status}`);
console.log("");

if (cryptoInventoryReport.assets.length > 0) {
  console.log("Top Crypto Inventory Findings");
  console.log("-----------------------------");
  cryptoInventoryReport.assets.slice(0, 5).forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(` File: ${item.file}`);
    console.log(` Line: ${item.line}`);
    console.log(` Quantum Exposure: ${item.quantumExposure}`);
    console.log(` Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (quantumReadinessReport.findings.length > 0) {
  console.log("Top Quantum Readiness Findings");
  console.log("------------------------------");
  quantumReadinessReport.findings.slice(0, 5).forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(` File: ${item.file}`);
    console.log(` Line: ${item.line}`);
    console.log(` Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (exploitSimulationReport.simulations.length > 0) {
  console.log("Top Exploit Simulations");
  console.log("-----------------------");
  exploitSimulationReport.simulations.slice(0, 5).forEach((item, index) => {
    console.log(`${index + 1}. ${item.simulationName}`);
    console.log(` Impact: ${item.estimatedImpact}`);
    console.log(` Exploitability: ${item.exploitability}`);
    console.log(` Affected Area: ${item.affectedArea}`);
    console.log(` First Attack Step: ${item.attackPath?.[0] ?? "Not provided"}`);
    console.log("");
  });
}

if (smartContractAuditReport.auditFindings.length > 0) {
  console.log("Top Smart Contract Findings");
  console.log("---------------------------");
  smartContractAuditReport.auditFindings.slice(0, 10).forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(` File: ${item.file}`);
    console.log(` Line: ${item.line}`);
    console.log(` Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (attackSurfaceReport.attackFindings.length > 0) {
  console.log("Top Attack Surface Findings");
  console.log("---------------------------");
  attackSurfaceReport.attackFindings.slice(0, 10).forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(` File: ${item.file}`);
    console.log(` Line: ${item.line}`);
    console.log(` Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (dependencyReport.dependencyFindings.length > 0) {
  console.log("Dependency Findings");
  console.log("-------------------");
  dependencyReport.dependencyFindings.slice(0, 10).forEach((item, index) => {
    console.log(`${index + 1}. ${item.dependency} (${item.severity})`);
    console.log(` File: ${item.file}`);
    console.log(` Risk: ${item.risk}`);
    console.log(` Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (summary.topRecommendations.length > 0) {
  console.log("Top Recommendations");
  console.log("-------------------");
  summary.topRecommendations.forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(` File: ${item.file}`);
    console.log(` Line: ${item.line}`);
    console.log(` Recommendation: ${item.recommendation}`);
    console.log(` Migration Path: ${item.migrationPath}`);
    console.log("");
  });
} else {
  console.log("No major findings detected.");
  console.log("");
}

console.log("Report Generated");
console.log("----------------");
console.log(`Markdown Report: ${markdownReport.outputPath}`);
console.log("HTML Report: report.html");
console.log("JSON Report: report.json");
console.log("Evidence Graph: evidence-graph.json");
console.log("Dependency Risk Report: dependency-risk-report.json");
console.log("Code Flow Report: code-flow-report.json");
console.log("Route Exposure Report: route-exposure-report.json");
console.log("Trust Boundary Report: trust-boundary-report.json");
console.log("Attack Chain Builder Report: attack-chain-builder-report.json");
console.log("Executive Report: executive-report.json");
console.log("Executive Summary: executive-summary.json");
console.log("Quantum Risk Export: quantum-risk-export.json");
console.log("Migration Shield Report: migration-shield-report.json");
console.log("Quantum Exposure Forecast Report: quantum-exposure-forecast-report.json");
console.log("Quantum Attack Simulation Report: quantum-attack-simulation-report.json");
console.log("SARIF Report: report.sarif");
console.log("Security Badge SVG: badge.svg");
console.log("Security Badge HTML: badge.html");
console.log("Security Badge JSON: badge.json");
console.log("");

console.log("Full JSON Report");
console.log("----------------");
console.log(JSON.stringify(report, null, 2));
