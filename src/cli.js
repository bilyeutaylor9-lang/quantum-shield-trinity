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
    console.log(`GitHub URL detected: ${inputTarget}`);
    console.log("Clone mode: shallow + blobless optimized clone");
    console.log("");

    clonedRepo = cloneGitHubRepo(inputTarget, {
      depth: 1,
      singleBranch: true,
      blobless: true
    });

    targetDirectory = clonedRepo.targetPath;
  }

  console.log(`Scanning target: ${inputTarget}`);
  console.log(`Resolved directory: ${targetDirectory}`);
  console.log("");

  const report = runQuantumShieldScan(targetDirectory);

  const safeWriteJson = (fileName, data) => {
    fs.writeFileSync(fileName, JSON.stringify(data ?? {}, null, 2), "utf8");
  };

  const safeWriteText = (fileName, data) => {
    fs.writeFileSync(fileName, data ?? "", "utf8");
  };

  safeWriteJson("report.json", report);
  safeWriteText("report.html", report.htmlReport);
  safeWriteJson("report.sarif", report.sarifReport);
  safeWriteText("badge.svg", report.securityBadgeReport?.svg);
  safeWriteText("badge.html", report.securityBadgeReport?.html);
  safeWriteJson("badge.json", report.securityBadgeReport?.badgeData);

  safeWriteJson("evidence-graph.json", report.evidenceGraphReport);
  safeWriteJson("wallet-risk-report.json", report.walletReport);
  safeWriteJson("dependency-risk-report.json", report.dependencyRiskReport);
  safeWriteJson("executive-summary.json", report.executiveReportEngineReport);
  safeWriteJson("quantum-risk-export.json", report.jsonExportReport);
  safeWriteJson("migration-shield-report.json", report.migrationShieldReport);
  safeWriteJson("smart-contract-context-report.json", report.smartContractContextReport);
  safeWriteJson("quantum-exposure-forecast-report.json", report.quantumExposureForecastReport);
  safeWriteJson("quantum-attack-simulation-report.json", report.quantumAttackSimulationReport);
  safeWriteJson("root-cause-report.json", report.rootCauseReport);
  safeWriteJson("security-assessment-report.json", report.securityAssessmentReport);
  safeWriteJson("security-audit-loop-report.json", report.securityAuditLoopReport);
  safeWriteJson("security-copilot-report.json", report.securityCopilotReport);
  safeWriteJson("code-flow-report.json", report.codeFlowReport);
  safeWriteJson("route-exposure-report.json", report.routeExposureReport);
  safeWriteJson("trust-boundary-report.json", report.trustBoundaryReport);
  safeWriteJson("attack-chain-builder-report.json", report.attackChainBuilderReport);

  safeWriteJson("executive-report.json", {
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
  });

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
  console.log("HTML Report: report.html");
  console.log("JSON Report: report.json");
  console.log("SARIF Report: report.sarif");
  console.log("Executive Report: executive-report.json");
  console.log("");
} catch (error) {
  console.error("");
  console.error("Quantum Shield Trinity scan failed.");
  console.error("-----------------------------------");
  console.error(error?.stack ?? error?.message ?? error);
  console.error("");

  process.exitCode = 1;
} finally {
  if (clonedRepo?.tempRoot) {
    cleanupClonedRepo(clonedRepo.tempRoot);
  }
}
