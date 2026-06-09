#!/usr/bin/env node

import fs from "fs";
import { runQuantumShieldScan } from "./index.js";
import {
  isGitHubUrl,
  cloneGitHubRepo,
  cleanupClonedRepo
} from "./utils/githubCloneScanner.js";

const inputTarget = process.argv[2] ?? "src";

let targetDirectory = inputTarget;
let clonedRepo = null;

console.log("Quantum Shield Trinity");
console.log("----------------------");

try {
  if (isGitHubUrl(inputTarget)) {
    clonedRepo = cloneGitHubRepo(inputTarget);
    targetDirectory = clonedRepo.targetPath;
  }

  console.log(`Scanning target: ${inputTarget}`);
  console.log(`Resolved directory: ${targetDirectory}`);
  console.log("");

  const report = runQuantumShieldScan(targetDirectory);

  fs.writeFileSync("report.json", JSON.stringify(report, null, 2), "utf8");
  fs.writeFileSync("report.html", report.htmlReport, "utf8");
  fs.writeFileSync("report.sarif", JSON.stringify(report.sarifReport, null, 2), "utf8");
  fs.writeFileSync("badge.svg", report.securityBadgeReport.svg, "utf8");
  fs.writeFileSync("badge.html", report.securityBadgeReport.html, "utf8");
  fs.writeFileSync("badge.json", JSON.stringify(report.securityBadgeReport.badgeData, null, 2), "utf8");

  fs.writeFileSync("evidence-graph.json", JSON.stringify(report.evidenceGraphReport, null, 2), "utf8");
  fs.writeFileSync("wallet-risk-report.json", JSON.stringify(report.walletReport, null, 2), "utf8");
  fs.writeFileSync("dependency-risk-report.json", JSON.stringify(report.dependencyRiskReport, null, 2), "utf8");
  fs.writeFileSync("executive-summary.json", JSON.stringify(report.executiveReportEngineReport, null, 2), "utf8");
  fs.writeFileSync("quantum-risk-export.json", JSON.stringify(report.jsonExportReport, null, 2), "utf8");
  fs.writeFileSync("migration-shield-report.json", JSON.stringify(report.migrationShieldReport, null, 2), "utf8");
  fs.writeFileSync("smart-contract-context-report.json", JSON.stringify(report.smartContractContextReport, null, 2), "utf8");
  fs.writeFileSync("quantum-exposure-forecast-report.json", JSON.stringify(report.quantumExposureForecastReport, null, 2), "utf8");
  fs.writeFileSync("quantum-attack-simulation-report.json", JSON.stringify(report.quantumAttackSimulationReport, null, 2), "utf8");
  fs.writeFileSync("root-cause-report.json", JSON.stringify(report.rootCauseReport, null, 2), "utf8");
  fs.writeFileSync("security-assessment-report.json", JSON.stringify(report.securityAssessmentReport, null, 2), "utf8");
  fs.writeFileSync("security-audit-loop-report.json", JSON.stringify(report.securityAuditLoopReport, null, 2), "utf8");
  fs.writeFileSync("security-copilot-report.json", JSON.stringify(report.securityCopilotReport, null, 2), "utf8");
  fs.writeFileSync("code-flow-report.json", JSON.stringify(report.codeFlowReport, null, 2), "utf8");
  fs.writeFileSync("route-exposure-report.json", JSON.stringify(report.routeExposureReport, null, 2), "utf8");
  fs.writeFileSync("trust-boundary-report.json", JSON.stringify(report.trustBoundaryReport, null, 2), "utf8");
  fs.writeFileSync("attack-chain-builder-report.json", JSON.stringify(report.attackChainBuilderReport, null, 2), "utf8");

  fs.writeFileSync(
    "executive-report.json",
    JSON.stringify(
      {
        platform: "Quantum Shield Trinity",
        version: report.version,
        scannedTarget: inputTarget,
        resolvedDirectory: targetDirectory,
        summary: report.summary,
        markdownReport: report.markdownReport,
        securityScoreReport: report.securityScoreReport,
        executiveReportEngineReport: report.executiveReportEngineReport,
        jsonExportReport: report.jsonExportReport,
        remediationReport: report.remediationReport,
        quantumReadinessReport: report.quantumReadinessReport,
        walletReport: report.walletReport,
        cryptoInventoryReport: report.cryptoInventoryReport,
        smartContractContextReport: report.smartContractContextReport,
        migrationShieldReport: report.migrationShieldReport,
        quantumExposureForecastReport: report.quantumExposureForecastReport,
        quantumAttackSimulationReport: report.quantumAttackSimulationReport,
        securityAssessmentReport: report.securityAssessmentReport,
        securityAuditLoopReport: report.securityAuditLoopReport,
        securityCopilotReport: report.securityCopilotReport,
        rootCauseReport: report.rootCauseReport,
        dependencyRiskReport: report.dependencyRiskReport,
        codeFlowReport: report.codeFlowReport,
        routeExposureReport: report.routeExposureReport,
        trustBoundaryReport: report.trustBoundaryReport,
        attackChainBuilderReport: report.attackChainBuilderReport,
        autoFixReport: report.autoFixReport,
        attackPathReport: report.attackPathReport,
        complianceMappingReport: report.complianceMappingReport,
        evidenceGraphReport: report.evidenceGraphReport,
        securityBadgeReport: report.securityBadgeReport
      },
      null,
      2
    ),
    "utf8"
  );

  const summary = report.summary ?? {};

  console.log("Executive Summary");
  console.log("-----------------");
  console.log(`Risk Level: ${summary.repositoryRiskLevel ?? "UNKNOWN"}`);
  console.log(`Score: ${summary.score ?? "N/A"}/100`);
  console.log(`Scanned Files: ${summary.scannedFiles ?? report.scannedFiles ?? "N/A"}`);
  console.log(`Critical Findings: ${summary.criticalFindings ?? 0}`);
  console.log(`High Findings: ${summary.highFindings ?? 0}`);
  console.log(`Medium Findings: ${summary.mediumFindings ?? 0}`);
  console.log("");

  console.log("Deep Scan X");
  console.log("-----------");
  console.log(`Code Flow Risk Level: ${report.codeFlowReport?.riskLevel ?? "UNKNOWN"}`);
  console.log(`Route Exposure Risk Level: ${report.routeExposureReport?.routeExposureRiskLevel ?? "UNKNOWN"}`);
  console.log(`Trust Boundary Risk Level: ${report.trustBoundaryReport?.trustBoundaryRiskLevel ?? "UNKNOWN"}`);
  console.log(`Attack Chain Risk Level: ${report.attackChainBuilderReport?.attackChainRiskLevel ?? "UNKNOWN"}`);
  console.log("");

  console.log("Evidence Graph");
  console.log("--------------");
  console.log(`Evidence Nodes: ${report.evidenceGraphReport?.nodes?.length ?? 0}`);
  console.log(`Evidence Edges: ${report.evidenceGraphReport?.edges?.length ?? 0}`);
  console.log(`Graph Risk Level: ${report.evidenceGraphReport?.summary?.risk?.level ?? "UNKNOWN"}`);
  console.log("");

  console.log("Wallet Quantum Risk");
  console.log("-------------------");
  console.log(`Wallet Address: ${report.walletReport?.walletAddress ?? "Unknown"}`);
  console.log(`Risk Score: ${report.walletReport?.score ?? "N/A"}/100`);
  console.log(`Risk Level: ${report.walletReport?.riskLevel ?? "UNKNOWN"}`);
  console.log(`Recommendation: ${report.walletReport?.recommendation ?? "Review wallet exposure."}`);
  console.log("");

  console.log("Executive Security Score");
  console.log("------------------------");
  console.log(`Security Score: ${report.securityScoreReport?.securityScore ?? "N/A"}/100`);
  console.log(`Risk Level: ${report.securityScoreReport?.riskLevel ?? "UNKNOWN"}`);
  console.log(`Grade: ${report.securityScoreReport?.grade ?? report.securityScoreReport?.securityGrade ?? "N/A"}`);
  console.log(`Top Priority: ${report.securityScoreReport?.topPriority ?? "Review high and critical findings."}`);
  console.log("");

  console.log("Quantum Readiness");
  console.log("-----------------");
  console.log(`Quantum Readiness Score: ${report.quantumReadinessReport?.quantumReadinessScore ?? "N/A"}/100`);
  console.log(`Quantum Risk Level: ${report.quantumReadinessReport?.quantumRiskLevel ?? "UNKNOWN"}`);
  console.log(`Migration Readiness: ${report.quantumReadinessReport?.migrationReadiness ?? "UNKNOWN"}`);
  console.log("");

  console.log("Report Generated");
  console.log("----------------");
  console.log("Markdown Report:", report.markdownReport?.outputPath ?? "Generated by markdownReportGenerator");
  console.log("HTML Report: report.html");
  console.log("JSON Report: report.json");
  console.log("Evidence Graph: evidence-graph.json");
  console.log("Wallet Risk Report: wallet-risk-report.json");
  console.log("Dependency Risk Report: dependency-risk-report.json");
  console.log("Code Flow Report: code-flow-report.json");
  console.log("Route Exposure Report: route-exposure-report.json");
  console.log("Trust Boundary Report: trust-boundary-report.json");
  console.log("Attack Chain Builder Report: attack-chain-builder-report.json");
  console.log("Executive Report: executive-report.json");
  console.log("Executive Summary: executive-summary.json");
  console.log("Quantum Risk Export: quantum-risk-export.json");
  console.log("SARIF Report: report.sarif");
  console.log("Security Badge SVG: badge.svg");
  console.log("Security Badge HTML: badge.html");
  console.log("Security Badge JSON: badge.json");
  console.log("");

  console.log("GitHub Clone Mode");
  console.log("-----------------");
  console.log(`Input Target: ${inputTarget}`);
  console.log(`Was GitHub URL: ${isGitHubUrl(inputTarget)}`);
  console.log("");

  console.log("Full JSON Report");
  console.log("----------------");
  console.log(JSON.stringify(report, null, 2));
} catch (error) {
  console.error("");
  console.error("Quantum Shield Trinity scan failed.");
  console.error("-----------------------------------");
  console.error(error.message);
  console.error("");

  process.exitCode = 1;
} finally {
  if (clonedRepo?.tempRoot) {
    cleanupClonedRepo(clonedRepo.tempRoot);
  }
}
