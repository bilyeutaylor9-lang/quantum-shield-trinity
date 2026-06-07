import { fileScanner } from "./scanners/fileScanner.js";
import { repositoryScannerEngine } from "./engines/repositoryScannerEngine.js";
import { summaryFormatter } from "./utils/summaryFormatter.js";
import { markdownReportGenerator } from "./reporters/markdownReportGenerator.js";

const targetDirectory = process.argv[2] ?? "src";

console.log("Quantum Shield Trinity");
console.log("----------------------");
console.log(`Scanning directory: ${targetDirectory}`);
console.log("");

const scanResult = fileScanner(targetDirectory);

const report = repositoryScannerEngine(scanResult.files);

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
