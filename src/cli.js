import { fileScanner } from "./scanners/fileScanner.js";
import { repositoryScannerEngine } from "./engines/repositoryScannerEngine.js";
import { dependencyIntelligenceEngine } from "./engines/dependencyIntelligenceEngine.js";
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
import { createEvidenceGraph } from "./engines/evidenceGraphEngine.js";
import { htmlReportGenerator } from "./reporters/htmlReportGenerator.js";
import { sarifReportGenerator } from "./reporters/sarifReportGenerator.js";
import { securityBadgeGenerator } from "./reporters/securityBadgeGenerator.js";
import { summaryFormatter } from "./utils/summaryFormatter.js";
import { markdownReportGenerator } from "./reporters/markdownReportGenerator.js";
import fs from "fs";

const targetDirectory = process.argv[2] ?? "src";

console.log("Quantum Shield Trinity");
console.log("----------------------");
console.log(`Scanning directory: ${targetDirectory}`);
console.log("");

const scanResult = fileScanner(targetDirectory);
const report = repositoryScannerEngine(scanResult.files);

const dependencyReport = dependencyIntelligenceEngine(scanResult.files);
const attackSurfaceReport = attackSurfaceEngine(scanResult.files);
const smartContractAuditReport = smartContractAuditEngine(scanResult.files);
const quantumReadinessReport = quantumReadinessEngine(scanResult.files);
const cryptoInventoryReport = cryptoInventoryEngine(scanResult.files);

report.dependencyReport = dependencyReport;
report.attackSurfaceReport = attackSurfaceReport;
report.smartContractAuditReport = smartContractAuditReport;
report.quantumReadinessReport = quantumReadinessReport;
report.cryptoInventoryReport = cryptoInventoryReport;
report.inventoryReport = cryptoInventoryReport;

const exploitSimulationReport = exploitSimulationEngine(report);
report.exploitSimulationReport = exploitSimulationReport;

const securityScoreReport = securityScoreEngine({
  dependencyReport,
  attackSurfaceReport,
  smartContractAuditReport,
  exploitSimulationReport,
  quantumReadinessReport,
  cryptoInventoryReport,
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

//============================================================================
// EVIDENCE GRAPH INTEGRATION
//============================================================================

const evidenceGraph = createEvidenceGraph({
  autoLinkByFile: true,
  autoLinkByRule: true,
  autoLinkByAsset: true,
  maxAttackChainDepth: 5
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
        "",
      severity: item.severity ?? item.riskLevel ?? "info",
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
      snippet: item.snippet ?? item.code ?? item.evidence ?? "",
      attackSurface: item.attackSurface ?? item.affectedArea ?? [],
      assets: [
        item.dependency,
        item.asset,
        item.contract,
        item.file
      ].filter(Boolean),
      remediation: [
        item.recommendation,
        item.howToFix,
        item.recommendedFix,
        item.recommendedDefense,
        item.migrationPath
      ].filter(Boolean),
      metadata: item
    });
  });
};

addEvidenceItems(cryptoInventoryReport.assets, "cryptoInventoryEngine", "crypto_inventory");
addEvidenceItems(quantumReadinessReport.findings, "quantumReadinessEngine", "quantum_readiness");
addEvidenceItems(dependencyReport.dependencyFindings, "dependencyIntelligenceEngine", "dependency_risk");
addEvidenceItems(attackSurfaceReport.attackFindings, "attackSurfaceEngine", "attack_surface");
addEvidenceItems(smartContractAuditReport.auditFindings, "smartContractAuditEngine", "smart_contract_audit");
addEvidenceItems(exploitSimulationReport.simulations, "exploitSimulationEngine", "exploit_simulation");
addEvidenceItems(remediationReport.remediationItems, "remediationEngine", "remediation");
addEvidenceItems(autoFixReport.fixes, "autoFixEngine", "auto_fix");
addEvidenceItems(attackPathReport.attackPaths, "attackPathGeneratorEngine", "attack_path");
addEvidenceItems(complianceMappingReport.mappedFindings, "complianceMappingEngine", "compliance_mapping");

const evidenceGraphReport = evidenceGraph.exportGraph();
report.evidenceGraphReport = evidenceGraphReport;

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

fs.writeFileSync(
  "executive-report.json",
  JSON.stringify(
    {
      platform: "Quantum Shield Trinity",
      version: "2.0.0",
      summary,
      markdownReport,
      securityScoreReport,
      remediationReport,
      quantumReadinessReport,
      cryptoInventoryReport,
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

console.log("Executive Summary");
console.log("-----------------");
console.log(`Risk Level: ${summary.repositoryRiskLevel}`);
console.log(`Score: ${summary.score}/100`);
console.log(`Scanned Files: ${summary.scannedFiles}`);
console.log(`Critical Findings: ${summary.criticalFindings}`);
console.log(`High Findings: ${summary.highFindings}`);
console.log(`Medium Findings: ${summary.mediumFindings}`);
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

console.log("Dependency Intelligence");
console.log("-----------------------");
console.log(`Dependency Risk Level: ${dependencyReport.dependencyRiskLevel}`);
console.log(`Dependency Files Scanned: ${dependencyReport.scannedDependencyFiles}`);
console.log(`High Risk Dependencies: ${dependencyReport.highRiskDependencies}`);
console.log(`Medium Risk Dependencies: ${dependencyReport.mediumRiskDependencies}`);
console.log("");

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
console.log("Executive Report: executive-report.json");
console.log("SARIF Report: report.sarif");
console.log("Security Badge SVG: badge.svg");
console.log("Security Badge HTML: badge.html");
console.log("Security Badge JSON: badge.json");
console.log("");

console.log("Full JSON Report");
console.log("----------------");
console.log(JSON.stringify(report, null, 2));
