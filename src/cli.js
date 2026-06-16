#!/usr/bin/env node

import fs from "fs";
import path from "path";
import { runQuantumShieldScan } from "./index.js";
import {
  isGitHubUrl,
  cloneGitHubRepo,
  cleanupClonedRepo
} from "./utils/githubCloneScanner.js";

function parseArgs(argv = []) {
  const args = {
    target: "src",
    profile: "deep",
    outDir: ".",
    failOn: "none"
  };

  const positional = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === "--profile") args.profile = argv[++i] ?? "deep";
    else if (arg === "--out") args.outDir = argv[++i] ?? ".";
    else if (arg === "--fail-on") args.failOn = argv[++i] ?? "none";
    else positional.push(arg);
  }

  if (positional[0]) args.target = positional[0];

  return args;
}

const cli = parseArgs(process.argv.slice(2));

let targetDirectory = cli.target;
let clonedRepo = null;

const scanOptions = {
  profile: cli.profile,
  maxEvidenceItems: 100,
  attackChain: {
    maxDepth: cli.profile === "quick" ? 2 : 3,
    limit: cli.profile === "quick" ? 10 : 25,
    maxNodes: cli.profile === "quick" ? 100 : 250,
    maxEdges: cli.profile === "quick" ? 250 : 750,
    maxStarts: cli.profile === "quick" ? 20 : 50,
    maxNeighborsPerNode: cli.profile === "quick" ? 10 : 20,
    maxChainsToExplore: cli.profile === "quick" ? 150 : 500
  }
};

function ensureOutDir(outDir) {
  fs.mkdirSync(outDir, { recursive: true });
}

function outPath(fileName) {
  return path.join(cli.outDir, fileName);
}

function safeWriteJson(fileName, data) {
  if (data === undefined || data === null) return;
  fs.writeFileSync(outPath(fileName), JSON.stringify(data, null, 2), "utf8");
}

function safeWriteText(fileName, data) {
  if (data === undefined || data === null) return;
  fs.writeFileSync(outPath(fileName), String(data), "utf8");
}

function getSeverityCounts(report = {}) {
  const summary = report.summary ?? {};
  const score = report.securityScoreReport ?? {};

  return {
    critical:
      summary.criticalFindings ??
      score.findingCounts?.critical ??
      report.criticalFindings ??
      0,
    high:
      summary.highFindings ??
      score.findingCounts?.high ??
      report.highFindings ??
      0,
    medium:
      summary.mediumFindings ??
      score.findingCounts?.medium ??
      report.mediumFindings ??
      0,
    low:
      summary.lowFindings ??
      score.findingCounts?.low ??
      report.lowFindings ??
      0
  };
}

function shouldFailBuild(report = {}, failOn = "none") {
  const counts = getSeverityCounts(report);

  if (failOn === "critical") return counts.critical > 0;
  if (failOn === "high") return counts.critical > 0 || counts.high > 0;
  if (failOn === "medium") {
    return counts.critical > 0 || counts.high > 0 || counts.medium > 0;
  }

  return false;
}

function writeArtifacts(report, inputTarget, resolvedDirectory) {
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
  safeWriteJson("auto-fix-report.json", report.autoFixReport);
  safeWriteJson("attack-path-report.json", report.attackPathReport);
  safeWriteJson("compliance-mapping-report.json", report.complianceMappingReport);
  safeWriteJson("crypto-inventory-report.json", report.cryptoInventoryReport);
  safeWriteText("markdown-report.md", report.markdownReport);

  safeWriteJson("executive-report.json", {
    platform: "Quantum Shield Trinity",
    version: report.version,
    scannedTarget: inputTarget,
    resolvedDirectory,
    profile: cli.profile,
    generatedAt: new Date().toISOString(),
    summary: report.summary,
    securityScoreReport: report.securityScoreReport,
    executiveReportEngineReport: report.executiveReportEngineReport,
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

  const counts = getSeverityCounts(report);

  safeWriteJson("scan-summary.json", {
    platform: "Quantum Shield Trinity",
    target: inputTarget,
    resolvedDirectory,
    profile: cli.profile,
    generatedAt: new Date().toISOString(),
    score: report.summary?.score ?? report.securityScoreReport?.securityScore ?? null,
    riskLevel:
      report.summary?.repositoryRiskLevel ??
      report.securityScoreReport?.riskLevel ??
      "UNKNOWN",
    findings: counts,
    quantum: {
      score: report.quantumReadinessReport?.quantumReadinessScore ?? null,
      riskLevel: report.quantumReadinessReport?.quantumRiskLevel ?? "UNKNOWN",
      migrationReadiness:
        report.quantumReadinessReport?.migrationReadiness ?? "UNKNOWN"
    },
    evidenceGraph: {
      nodes: report.evidenceGraphReport?.nodes?.length ?? 0,
      edges: report.evidenceGraphReport?.edges?.length ?? 0,
      riskLevel: report.evidenceGraphReport?.summary?.risk?.level ?? "UNKNOWN"
    }
  });
}

function printConsoleSummary(report = {}) {
  const summary = report.summary ?? {};
  const counts = getSeverityCounts(report);

  console.log("Executive Summary");
  console.log("-----------------");
  console.log(`Risk Level: ${summary.repositoryRiskLevel ?? report.securityScoreReport?.riskLevel ?? "UNKNOWN"}`);
  console.log(`Score: ${summary.score ?? report.securityScoreReport?.securityScore ?? "N/A"}/100`);
  console.log(`Scanned Files: ${summary.scannedFiles ?? report.scannedFiles ?? "N/A"}`);
  console.log(`Critical Findings: ${counts.critical}`);
  console.log(`High Findings: ${counts.high}`);
  console.log(`Medium Findings: ${counts.medium}`);
  console.log(`Low Findings: ${counts.low}`);
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

  console.log("Reports Generated");
  console.log("-----------------");
  console.log(`Output Directory: ${cli.outDir}`);
  console.log("HTML Report: report.html");
  console.log("JSON Report: report.json");
  console.log("SARIF Report: report.sarif");
  console.log("Executive Report: executive-report.json");
  console.log("Scan Summary: scan-summary.json");
  console.log("");
}

console.log("Quantum Shield Trinity");
console.log("----------------------");
console.log(`Profile: ${cli.profile}`);
console.log(`Output Directory: ${cli.outDir}`);
console.log(`Fail On: ${cli.failOn}`);
console.log("");

try {
  ensureOutDir(cli.outDir);

  if (isGitHubUrl(cli.target)) {
    console.log(`GitHub URL detected: ${cli.target}`);
    console.log("Clone mode: shallow + blobless optimized clone");
    console.log("");

    clonedRepo = cloneGitHubRepo(cli.target, {
      depth: 1,
      singleBranch: true,
      blobless: true
    });

    targetDirectory = clonedRepo.targetPath;
  }

  console.log(`Scanning target: ${cli.target}`);
  console.log(`Resolved directory: ${targetDirectory}`);
  console.log("");

  const report = runQuantumShieldScan(targetDirectory, scanOptions);

  writeArtifacts(report, cli.target, targetDirectory);
  printConsoleSummary(report);

  if (shouldFailBuild(report, cli.failOn)) {
    console.error(`Build failed because --fail-on=${cli.failOn} threshold was met.`);
    process.exitCode = 2;
  }
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
