import { fileScanner } from "./scanners/fileScanner.js";
import { repositoryScannerEngine } from "./engines/repositoryScannerEngine.js";
import { dependencyIntelligenceEngine } from "./engines/dependencyIntelligenceEngine.js";
import { attackSurfaceEngine } from "./engines/attackSurfaceEngine.js";
import { summaryFormatter } from "./utils/summaryFormatter.js";
import { markdownReportGenerator } from "./reporters/markdownReportGenerator.js";

const targetDirectory = process.argv[2] ?? "src";

console.log("Quantum Shield Trinity");
console.log("----------------------");
console.log(`Scanning directory: ${targetDirectory}`);
console.log("");

const scanResult = fileScanner(targetDirectory);

const report = repositoryScannerEngine(scanResult.files);

const dependencyReport = dependencyIntelligenceEngine(scanResult.files);
const attackSurfaceReport = attackSurfaceEngine(scanResult.files);

report.dependencyReport = dependencyReport;
report.attackSurfaceReport = attackSurfaceReport;

const summary = summaryFormatter(report);

const markdownReport = markdownReportGenerator(report);

console.log("Executive Summary");
console.log("-----------------");
console.log(`Risk Level: ${summary.repositoryRiskLevel}`);
console.log(`Score: ${summary.score}/100`);
console.log(`Scanned Files: ${summary.scannedFiles}`);
console.log(`Critical Findings: ${summary.criticalFindings}`);
console.log(`High Findings: ${summary.highFindings}`);
console.log(`Medium Findings: ${summary.mediumFindings}`);
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
console.log("");

console.log("Full JSON Report");
console.log("----------------");
console.log(JSON.stringify(report, null, 2));
