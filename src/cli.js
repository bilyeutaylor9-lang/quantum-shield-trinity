import { fileScanner } from "./scanners/fileScanner.js";
import { repositoryScannerEngine } from "./engines/repositoryScannerEngine.js";
import { dependencyIntelligenceEngine } from "./engines/dependencyIntelligenceEngine.js";
import { attackSurfaceEngine } from "./engines/attackSurfaceEngine.js";
import { smartContractAuditEngine } from "./engines/smartContractAuditEngine.js";
import { exploitSimulationEngine } from "./engines/exploitSimulationEngine.js";
import { securityScoreEngine } from "./engines/securityScoreEngine.js";
import { remediationEngine } from "./engines/remediationEngine.js";
import { quantumReadinessEngine } from "./engines/quantumReadinessEngine.js";
import { htmlReportGenerator } from "./reporters/htmlReportGenerator.js";
import { sarifReportGenerator } from "./reporters/sarifReportGenerator.js";
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

report.dependencyReport = dependencyReport;
report.attackSurfaceReport = attackSurfaceReport;
report.smartContractAuditReport = smartContractAuditReport;
report.quantumReadinessReport = quantumReadinessReport;

const exploitSimulationReport = exploitSimulationEngine(report);

report.exploitSimulationReport = exploitSimulationReport;

const securityScoreReport = securityScoreEngine({
  dependencyReport,
  attackSurfaceReport,
  smartContractAuditReport,
  exploitSimulationReport,
  quantumReadinessReport,
  repositoryReport: report
});

report.securityScoreReport = securityScoreReport;

const remediationReport = remediationEngine(report);

report.remediationReport = remediationReport;

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
  version: "1.5.0"
});

fs.writeFileSync("report.json", JSON.stringify(report, null, 2), "utf8");
fs.writeFileSync("report.html", htmlReport, "utf8");
fs.writeFileSync(
  "executive-report.json",
  JSON.stringify(
    {
      platform: "Quantum Shield Trinity",
      version: "1.5.0",
      summary,
      markdownReport,
      securityScoreReport,
      remediationReport,
      quantumReadinessReport
    },
    null,
    2
  ),
  "utf8"
);
fs.writeFileSync("report.sarif", JSON.stringify(sarifReport, null, 2), "utf8");

console.log("Executive Summary");
console.log("-----------------");
console.log(`Risk Level: ${summary.repositoryRiskLevel}`);
console.log(`Score: ${summary.score}/100`);
console.log(`Scanned Files: ${summary.scannedFiles}`);
console.log(`Critical Findings: ${summary.criticalFindings}`);
console.log(`High Findings: ${summary.highFindings}`);
console.log(`Medium Findings: ${summary.mediumFindings}`);
console.log("");

console.log("Executive Security Score");
console.log("------------------------");
console.log(`Security Score: ${securityScoreReport.securityScore ?? "N/A"}/100`);
console.log(`Risk Level: ${securityScoreReport.riskLevel ?? "UNKNOWN"}`);
console.log(`Grade: ${securityScoreReport.grade ?? securityScoreReport.securityGrade ?? "N/A"}`);
console.log(`Top Priority: ${securityScoreReport.topPriority ?? "Review high and critical findings."}`);
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

console.log("Quantum Readiness");
console.log("-----------------");
console.log(`Quantum Readiness Score: ${quantumReadinessReport.quantumReadinessScore}/100`);
console.log(`Quantum Risk Level: ${quantumReadinessReport.quantumRiskLevel}`);
console.log(`Quantum Findings: ${quantumReadinessReport.totalQuantumFindings}`);
console.log(`Migration Readiness: ${quantumReadinessReport.migrationReadiness}`);
console.log(`Recommended Path: ${quantumReadinessReport.recommendedMigrationPath}`);
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
  console.log(`   File: ${item.file}`);
  console.log(`   Line: ${item.line}`);
  console.log(`   Priority: ${item.priority}`);
  console.log(`   Why It Matters: ${item.whyItMatters}`);
  console.log(`   Fix: ${item.howToFix}`);
  console.log(`   Example Fix: ${item.exampleFix}`);
  console.log("");
});

if (quantumReadinessReport.findings.length > 0) {
  console.log("Top Quantum Readiness Findings");
  console.log("------------------------------");

  quantumReadinessReport.findings.slice(0, 5).forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(`   File: ${item.file}`);
    console.log(`   Line: ${item.line}`);
    console.log(`   Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (exploitSimulationReport.simulations.length > 0) {
  console.log("Top Exploit Simulations");
  console.log("-----------------------");

  exploitSimulationReport.simulations.slice(0, 5).forEach((item, index) => {
    console.log(`${index + 1}. ${item.simulationName}`);
    console.log(`   Impact: ${item.estimatedImpact}`);
    console.log(`   Exploitability: ${item.exploitability}`);
    console.log(`   Affected Area: ${item.affectedArea}`);
    console.log(`   First Attack Step: ${item.attackPath?.[0] ?? "Not provided"}`);
    console.log("");
  });
}

if (smartContractAuditReport.auditFindings.length > 0) {
  console.log("Top Smart Contract Findings");
  console.log("---------------------------");

  smartContractAuditReport.auditFindings.slice(0, 10).forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(`   File: ${item.file}`);
    console.log(`   Line: ${item.line}`);
    console.log(`   Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (attackSurfaceReport.attackFindings.length > 0) {
  console.log("Top Attack Surface Findings");
  console.log("---------------------------");

  attackSurfaceReport.attackFindings.slice(0, 10).forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(`   File: ${item.file}`);
    console.log(`   Line: ${item.line}`);
    console.log(`   Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (dependencyReport.dependencyFindings.length > 0) {
  console.log("Dependency Findings");
  console.log("-------------------");

  dependencyReport.dependencyFindings.slice(0, 10).forEach((item, index) => {
    console.log(`${index + 1}. ${item.dependency} (${item.severity})`);
    console.log(`   File: ${item.file}`);
    console.log(`   Risk: ${item.risk}`);
    console.log(`   Recommendation: ${item.recommendation}`);
    console.log("");
  });
}

if (summary.topRecommendations.length > 0) {
  console.log("Top Recommendations");
  console.log("-------------------");

  summary.topRecommendations.forEach((item, index) => {
    console.log(`${index + 1}. ${item.type} (${item.severity})`);
    console.log(`   File: ${item.file}`);
    console.log(`   Line: ${item.line}`);
    console.log(`   Recommendation: ${item.recommendation}`);
    console.log(`   Migration Path: ${item.migrationPath}`);
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
console.log("Executive Report: executive-report.json");
console.log("SARIF Report: report.sarif");
console.log("");

console.log("Full JSON Report");
console.log("----------------");
console.log(JSON.stringify(report, null, 2));
