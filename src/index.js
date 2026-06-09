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
import { rootCauseEngine } from "./engines/rootCauseEngine.js";
import { securityAssessmentEngine } from "./engines/securityAssessmentEngine.js";
import { securityAuditLoopEngine } from "./engines/securityAuditLoopEngine.js";
import { securityCopilotEngine } from "./engines/securityCopilotEngine.js";
import { smartContractContextEngine } from "./engines/smartContractContextEngine.js";
import { walletRiskEngine } from "./engines/walletRiskEngine.js";
import { codeFlowScannerEngine } from "./engines/codeFlowScannerEngine.js";
import { routeExposureEngine } from "./engines/routeExposureEngine.js";
import { trustBoundaryEngine } from "./engines/trustBoundaryEngine.js";
import { attackChainBuilderEngine } from "./engines/attackChainBuilderEngine.js";
import { createEvidenceGraph } from "./engines/evidenceGraphEngine.js";

import { htmlReportGenerator } from "./reporters/htmlReportGenerator.js";
import { sarifReportGenerator } from "./reporters/sarifReportGenerator.js";
import { securityBadgeGenerator } from "./reporters/securityBadgeGenerator.js";
import { markdownReportGenerator } from "./reporters/markdownReportGenerator.js";
import { summaryFormatter } from "./utils/summaryFormatter.js";

export {
  fileScanner,
  repositoryScannerEngine,
  dependencyIntelligenceEngine,
  dependencyRiskEngine,
  attackSurfaceEngine,
  smartContractAuditEngine,
  exploitSimulationEngine,
  securityScoreEngine,
  remediationEngine,
  quantumReadinessEngine,
  cryptoInventoryEngine,
  autoFixEngine,
  attackPathGeneratorEngine,
  complianceMappingEngine,
  executiveReportEngine,
  jsonExportEngine,
  migrationShieldEngine,
  quantumAttackSimulationEngine,
  quantumExposureForecastEngine,
  rootCauseEngine,
  securityAssessmentEngine,
  securityAuditLoopEngine,
  securityCopilotEngine,
  smartContractContextEngine,
  walletRiskEngine,
  codeFlowScannerEngine,
  routeExposureEngine,
  trustBoundaryEngine,
  attackChainBuilderEngine,
  createEvidenceGraph,
  htmlReportGenerator,
  sarifReportGenerator,
  securityBadgeGenerator,
  markdownReportGenerator,
  summaryFormatter
};

const timedStep = (label, fn) => {
  const started = Date.now();
  console.log(`[QST] START ${label}`);

  try {
    const result = fn();
    const elapsed = ((Date.now() - started) / 1000).toFixed(2);
    console.log(`[QST] DONE  ${label} in ${elapsed}s`);
    return result;
  } catch (error) {
    const elapsed = ((Date.now() - started) / 1000).toFixed(2);
    console.error(`[QST] FAIL  ${label} after ${elapsed}s`);
    console.error(error?.stack ?? error?.message ?? error);
    throw error;
  }
};

const findPackageJson = (files = []) => {
  const packageFile = files.find((file) => {
    const filePath = file.path ?? file.file ?? file.name ?? file.filename ?? "";
    return filePath.endsWith("package.json");
  });

  if (!packageFile) return {};

  try {
    const raw = packageFile.content ?? packageFile.text ?? packageFile.source ?? "{}";
    return typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
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
  ruleId:
    item.ruleId ??
    `DEPENDENCY_RISK_${String(item.dependency ?? "UNKNOWN")
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "_")}`,
  confidence: typeof item.confidence === "number" ? item.confidence / 100 : 0.75,
  recommendation: item.recommendation
});

const buildWalletInputFromReports = (report = {}, cryptoInventoryReport = {}) => {
  const existingWallet = report.walletRiskReport ?? report.walletReport ?? report.wallet ?? {};

  return {
    address: existingWallet.address ?? existingWallet.walletAddress ?? "Unknown",
    transactionCount:
      existingWallet.transactionCount ??
      cryptoInventoryReport.totalCryptoAssets ??
      cryptoInventoryReport.assets?.length ??
      0,
    reusedAddress: existingWallet.reusedAddress ?? false,
    signedMessages: existingWallet.signedMessages ?? cryptoInventoryReport.quantumExposedAssets ?? 0
  };
};

const buildSmartContractContextReport = (files = []) => {
  const supportedExtensions = [".sol", ".vy", ".js", ".ts", ".tsx", ".jsx"];
  const contexts = [];

  files.forEach((file) => {
    const fileName = file.path ?? file.file ?? file.name ?? file.filename ?? "unknown";
    const lowerFileName = String(fileName).toLowerCase();
    const isSupported = supportedExtensions.some((ext) => lowerFileName.endsWith(ext));

    if (!isSupported) return;

    const content = file.content ?? file.text ?? file.source ?? "";
    if (!content) return;

    String(content)
      .split("\n")
      .forEach((line, index) => {
        const trimmed = line.trim();
        if (!trimmed) return;

        const context = smartContractContextEngine(trimmed, fileName);

        const shouldKeep =
          context.contextType !== "General Smart Contract Context" ||
          lowerFileName.endsWith(".sol") ||
          lowerFileName.endsWith(".vy");

        if (!shouldKeep) return;

        contexts.push({
          id: `smart-contract-context-${contexts.length + 1}`,
          type: "smart_contract_context",
          category: context.contextType,
          title: context.contextType,
          description: context.note,
          severity:
            context.exploitability === "CRITICAL"
              ? "critical"
              : context.exploitability === "HIGH"
                ? "high"
                : context.exploitability === "MEDIUM"
                  ? "medium"
                  : "low",
          confidence: 0.78,
          file: fileName,
          line: index + 1,
          riskWeight: context.riskWeight,
          exploitability: context.exploitability,
          reviewPriority: context.reviewPriority,
          note: context.note,
          recommendation:
            context.reviewPriority <= 2
              ? "Prioritize immediate manual smart contract review."
              : "Review this smart contract context during audit triage.",
          remediation: [
            context.reviewPriority <= 2
              ? "Prioritize immediate manual smart contract review."
              : "Review this smart contract context during audit triage."
          ],
          evidence: {
            snippet: trimmed.slice(0, 260),
            matchedText: trimmed.slice(0, 260),
            source: "smartContractContextEngine"
          },
          attackSurface: ["smart_contract"],
          assets: [fileName, context.contextType],
          metadata: context
        });
      });
  });

  const sortedContexts = [...contexts].sort(
    (a, b) => (a.reviewPriority ?? 99) - (b.reviewPriority ?? 99)
  );

  return {
    engine: "Smart Contract Context Engine",
    generatedAt: new Date().toISOString(),
    totalContexts: sortedContexts.length,
    criticalContexts: sortedContexts.filter((item) => item.exploitability === "CRITICAL").length,
    highContexts: sortedContexts.filter((item) => item.exploitability === "HIGH").length,
    mediumContexts: sortedContexts.filter((item) => item.exploitability === "MEDIUM").length,
    topContexts: sortedContexts.slice(0, 10),
    contexts: sortedContexts
  };
};

const buildRootCauseReport = (findingGroups = []) => {
  const rootCauses = [];

  findingGroups.forEach(({ items = [], engine = "unknown" }) => {
    if (!Array.isArray(items)) return;

    items.forEach((finding, index) => {
      const rootCause = rootCauseEngine(finding);

      rootCauses.push({
        id: `root-cause-${engine}-${index + 1}`,
        engine,
        findingType:
          finding.type ?? finding.title ?? finding.dependency ?? finding.simulationName ?? "Unknown Finding",
        findingSeverity: finding.severity ?? finding.riskLevel ?? "LOW",
        file: finding.file ?? finding.path ?? null,
        line: finding.line ?? null,
        rootCause,
        source: rootCause.source,
        reason: rootCause.reason,
        attackSurface: rootCause.attackSurface,
        exploitability: rootCause.exploitability,
        likelihood: rootCause.likelihood,
        impact: rootCause.impact,
        remediationPriority: rootCause.remediationPriority,
        recommendation:
          finding.recommendation ??
          finding.recommendedDefense ??
          finding.howToFix ??
          "Review root cause and apply targeted remediation."
      });
    });
  });

  const prioritySorted = [...rootCauses].sort(
    (a, b) => (a.remediationPriority ?? 99) - (b.remediationPriority ?? 99)
  );

  return {
    engine: "Root Cause Engine",
    generatedAt: new Date().toISOString(),
    totalRootCauses: rootCauses.length,
    criticalRootCauses: rootCauses.filter((item) => item.exploitability === "CRITICAL").length,
    highRootCauses: rootCauses.filter((item) => item.exploitability === "HIGH").length,
    mediumRootCauses: rootCauses.filter((item) => item.exploitability === "MEDIUM").length,
    topRootCauses: prioritySorted.slice(0, 10),
    rootCauses: prioritySorted
  };
};

const buildSecurityCopilotReport = (findingGroups = []) => {
  const allFindings = [];

  findingGroups.forEach(({ items = [], engine = "unknown" }) => {
    if (!Array.isArray(items)) return;

    items.forEach((item, index) => {
      allFindings.push({
        ...item,
        id: item.id ?? `copilot-source-${engine}-${index + 1}`,
        sourceEngine: engine,
        type:
          item.type ??
          item.findingType ??
          item.dependency ??
          item.simulationName ??
          item.title ??
          "Unknown",
        severity: item.severity ?? item.riskLevel ?? item.exploitability ?? "LOW",
        category: item.category ?? item.sourceEngine ?? engine,
        file: item.file ?? item.path ?? null,
        line: item.line ?? null,
        confidence: item.confidence ?? "MEDIUM",
        recommendation:
          item.recommendation ??
          item.recommendedDefense ??
          item.howToFix ??
          item.rootCause?.reason ??
          "Review manually."
      });
    });
  });

  const guidance = securityCopilotEngine(allFindings);

  const severityRank = (value) => {
    const s = String(value ?? "").toUpperCase();
    if (s === "CRITICAL") return 5;
    if (s === "HIGH") return 4;
    if (s === "MEDIUM") return 3;
    if (s === "LOW") return 2;
    return 1;
  };

  const sortedGuidance = [...guidance].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity)
  );

  return {
    engine: "Security Copilot Engine",
    generatedAt: new Date().toISOString(),
    totalGuidanceItems: sortedGuidance.length,
    criticalGuidanceItems: sortedGuidance.filter(
      (item) => String(item.severity).toUpperCase() === "CRITICAL"
    ).length,
    highGuidanceItems: sortedGuidance.filter(
      (item) => String(item.severity).toUpperCase() === "HIGH"
    ).length,
    mediumGuidanceItems: sortedGuidance.filter(
      (item) => String(item.severity).toUpperCase() === "MEDIUM"
    ).length,
    topGuidance: sortedGuidance.slice(0, 10),
    guidance: sortedGuidance
  };
};

const addEvidenceItemsToGraph = (evidenceGraph, items = [], engine = "unknown", fallbackCategory = "general") => {
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
      owasp: [item.owaspSmartContractTop10, item.owaspWebTop10].filter(Boolean),
      snippet: item.snippet ?? item.code ?? item.evidence?.snippet ?? item.evidence ?? "",
      matchedText: item.evidence?.matchedText ?? item.matchedText ?? "",
      attackSurface: item.attackSurface ?? item.affectedArea ?? item.method ?? [],
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

export function runQuantumShieldScan(targetDirectory = "src", options = {}) {
  console.log("");
  console.log("Quantum Shield Trinity Deep Scan");
  console.log("--------------------------------");
  console.log(`[QST] Scan booted for: ${targetDirectory}`);
  console.log("");

  const scanResult = timedStep("fileScanner", () => fileScanner(targetDirectory));

  console.log(`[QST] Files discovered: ${scanResult.files?.length ?? 0}`);

  const report = timedStep("repositoryScannerEngine", () =>
    repositoryScannerEngine(scanResult.files)
  );

  const packageJson = timedStep("findPackageJson", () => findPackageJson(scanResult.files));

  const dependencyRiskReport = timedStep("dependencyRiskEngine", () =>
    dependencyRiskEngine(packageJson)
  );

  dependencyRiskReport.findings = (dependencyRiskReport.findings ?? []).map(
    normalizeDependencyRiskFinding
  );

  const dependencyReport = timedStep("dependencyIntelligenceEngine", () =>
    dependencyIntelligenceEngine(scanResult.files)
  );

  const attackSurfaceReport = timedStep("attackSurfaceEngine", () =>
    attackSurfaceEngine(scanResult.files)
  );

  const smartContractAuditReport = timedStep("smartContractAuditEngine", () =>
    smartContractAuditEngine(scanResult.files)
  );

  const quantumReadinessReport = timedStep("quantumReadinessEngine", () =>
    quantumReadinessEngine(scanResult.files)
  );

  const cryptoInventoryReport = timedStep("cryptoInventoryEngine", () =>
    cryptoInventoryEngine(scanResult.files)
  );

  const smartContractContextReport = timedStep("buildSmartContractContextReport", () =>
    buildSmartContractContextReport(scanResult.files)
  );

  const walletInput = options.wallet ?? buildWalletInputFromReports(report, cryptoInventoryReport);

  const walletReport = timedStep("walletRiskEngine", () => walletRiskEngine(walletInput));

  const migrationShieldReport = timedStep("migrationShieldEngine", () =>
    migrationShieldEngine(walletReport, cryptoInventoryReport)
  );

  const quantumExposureForecastReport = timedStep("quantumExposureForecastEngine", () =>
    quantumExposureForecastEngine({
      walletReport,
      inventoryReport: {
        ...cryptoInventoryReport,
        score:
          cryptoInventoryReport.score ??
          cryptoInventoryReport.inventorySecurityScore ??
          cryptoInventoryReport.inventoryRiskScore ??
          0
      },
      migrationReport: migrationShieldReport
    })
  );

  const quantumAttackSimulationReport = timedStep("quantumAttackSimulationEngine", () =>
    quantumAttackSimulationEngine({
      walletReport,
      inventoryReport: cryptoInventoryReport,
      migrationReport: migrationShieldReport,
      forecastReport: quantumExposureForecastReport
    })
  );

  const securityAssessmentReport = timedStep("securityAssessmentEngine", () =>
    securityAssessmentEngine({
      walletReport,
      inventoryReport: {
        ...cryptoInventoryReport,
        score:
          cryptoInventoryReport.score ??
          cryptoInventoryReport.inventorySecurityScore ??
          cryptoInventoryReport.inventoryRiskScore ??
          0,
        findings:
          cryptoInventoryReport.findings ??
          cryptoInventoryReport.totalCryptoAssets ??
          cryptoInventoryReport.assets?.length ??
          0
      },
      migrationReport: migrationShieldReport,
      forecastReport: quantumExposureForecastReport
    })
  );

  const codeFlowReport = timedStep("codeFlowScannerEngine", () =>
    codeFlowScannerEngine(scanResult.files)
  );

  const routeExposureReport = timedStep("routeExposureEngine", () =>
    routeExposureEngine(scanResult.files)
  );

  const trustBoundaryReport = timedStep("trustBoundaryEngine", () =>
    trustBoundaryEngine(scanResult.files, {
      codeFlowReport,
      routeExposureReport
    })
  );

  Object.assign(report, {
    platform: "Quantum Shield Trinity",
    version: "2.3.0",
    targetDirectory,
    scannedAt: new Date().toISOString(),
    scannedFiles: scanResult.files.length,

    dependencyReport,
    dependencyRiskReport,
    attackSurfaceReport,
    smartContractAuditReport,
    smartContractContextReport,
    quantumReadinessReport,
    cryptoInventoryReport,
    inventoryReport: cryptoInventoryReport,
    walletReport,
    walletRiskReport: walletReport,
    migrationShieldReport,
    migrationReport: migrationShieldReport,
    quantumExposureForecastReport,
    forecastReport: quantumExposureForecastReport,
    quantumAttackSimulationReport,
    simulationReport: quantumAttackSimulationReport,
    securityAssessmentReport,
    assessmentReport: securityAssessmentReport,
    codeFlowReport,
    routeExposureReport,
    trustBoundaryReport
  });

  const exploitSimulationReport = timedStep("exploitSimulationEngine", () =>
    exploitSimulationEngine(report)
  );

  report.exploitSimulationReport = exploitSimulationReport;

  const securityScoreReport = timedStep("securityScoreEngine", () =>
    securityScoreEngine({
      dependencyReport,
      dependencyRiskReport,
      attackSurfaceReport,
      smartContractAuditReport,
      smartContractContextReport,
      exploitSimulationReport,
      quantumReadinessReport,
      cryptoInventoryReport,
      migrationShieldReport,
      quantumExposureForecastReport,
      quantumAttackSimulationReport,
      securityAssessmentReport,
      codeFlowReport,
      routeExposureReport,
      trustBoundaryReport,
      repositoryReport: report
    })
  );

  report.securityScoreReport = securityScoreReport;

  const remediationReport = timedStep("remediationEngine", () => remediationEngine(report));
  const autoFixReport = timedStep("autoFixEngine", () => autoFixEngine(report));
  const attackPathReport = timedStep("attackPathGeneratorEngine", () =>
    attackPathGeneratorEngine(report)
  );
  const complianceMappingReport = timedStep("complianceMappingEngine", () =>
    complianceMappingEngine(report)
  );

  Object.assign(report, {
    remediationReport,
    autoFixReport,
    attackPathReport,
    complianceMappingReport
  });

  const rootCauseReport = timedStep("buildRootCauseReport", () =>
    buildRootCauseReport([
      { engine: "cryptoInventoryEngine", items: cryptoInventoryReport.assets },
      { engine: "quantumReadinessEngine", items: quantumReadinessReport.findings },
      { engine: "dependencyIntelligenceEngine", items: dependencyReport.dependencyFindings },
      { engine: "dependencyRiskEngine", items: dependencyRiskReport.findings },
      { engine: "attackSurfaceEngine", items: attackSurfaceReport.attackFindings },
      { engine: "smartContractAuditEngine", items: smartContractAuditReport.auditFindings },
      { engine: "smartContractContextEngine", items: smartContractContextReport.contexts },
      { engine: "codeFlowScannerEngine", items: codeFlowReport.findings },
      { engine: "routeExposureEngine", items: routeExposureReport.findings },
      { engine: "trustBoundaryEngine", items: trustBoundaryReport.findings },
      { engine: "exploitSimulationEngine", items: exploitSimulationReport.simulations },
      { engine: "attackPathGeneratorEngine", items: attackPathReport.attackPaths },
      { engine: "complianceMappingEngine", items: complianceMappingReport.mappedFindings }
    ])
  );

  report.rootCauseReport = rootCauseReport;

  report.dependencyReport = {
    ...dependencyReport,
    dependencyFindings: [
      ...(dependencyReport.dependencyFindings ?? []),
      ...(dependencyRiskReport.findings ?? [])
    ]
  };

  const attackChainBuilderReport = timedStep("attackChainBuilderEngine", () =>
    attackChainBuilderEngine(report, {
      maxDepth: 5,
      limit: 50
    })
  );

  report.attackChainBuilderReport = attackChainBuilderReport;

  const securityAuditLoopReport = timedStep("securityAuditLoopEngine", () =>
    securityAuditLoopEngine({
      previousHash:
        process.env.QST_PREVIOUS_AUDIT_HASH ?? report.previousAuditHash ?? "GENESIS",
      entropySeed: `${Date.now()}-${targetDirectory}-${scanResult.files.length}`,
      systemState: {
        platform: "Quantum Shield Trinity",
        version: "2.3.0",
        targetDirectory,
        scannedFiles: scanResult.files.length,
        walletRiskLevel: walletReport.riskLevel,
        walletRiskScore: walletReport.score,
        securityScore:
          securityScoreReport.securityScore ?? securityAssessmentReport.totalScore ?? 0,
        securityRiskLevel:
          securityScoreReport.riskLevel ?? securityAssessmentReport.riskLevel ?? "UNKNOWN",
        dependencyRiskLevel: dependencyRiskReport.riskLevel,
        codeFlowRiskLevel: codeFlowReport.riskLevel,
        routeExposureRiskLevel: routeExposureReport.routeExposureRiskLevel,
        trustBoundaryRiskLevel: trustBoundaryReport.trustBoundaryRiskLevel,
        attackChainRiskLevel: attackChainBuilderReport.attackChainRiskLevel,
        quantumExposure: quantumExposureForecastReport.qDayExposure,
        quantumBusinessRisk: quantumAttackSimulationReport.businessRisk,
        rootCauseCriticalCount: rootCauseReport.criticalRootCauses
      }
    })
  );

  report.securityAuditLoopReport = securityAuditLoopReport;
  report.auditLoopReport = securityAuditLoopReport;

  const securityCopilotReport = timedStep("buildSecurityCopilotReport", () =>
    buildSecurityCopilotReport([
      { engine: "cryptoInventoryEngine", items: cryptoInventoryReport.assets },
      { engine: "quantumReadinessEngine", items: quantumReadinessReport.findings },
      { engine: "dependencyIntelligenceEngine", items: report.dependencyReport.dependencyFindings },
      { engine: "dependencyRiskEngine", items: dependencyRiskReport.findings },
      { engine: "attackSurfaceEngine", items: attackSurfaceReport.attackFindings },
      { engine: "smartContractAuditEngine", items: smartContractAuditReport.auditFindings },
      { engine: "smartContractContextEngine", items: smartContractContextReport.contexts },
      { engine: "codeFlowScannerEngine", items: codeFlowReport.findings },
      { engine: "routeExposureEngine", items: routeExposureReport.findings },
      { engine: "trustBoundaryEngine", items: trustBoundaryReport.findings },
      { engine: "exploitSimulationEngine", items: exploitSimulationReport.simulations },
      { engine: "attackPathGeneratorEngine", items: attackPathReport.attackPaths },
      { engine: "attackChainBuilderEngine", items: attackChainBuilderReport.attackChains },
      { engine: "rootCauseEngine", items: rootCauseReport.rootCauses },
      {
        engine: "securityAssessmentEngine",
        items: (securityAssessmentReport.criticalFindings ?? []).map((finding, index) => ({
          id: `security-assessment-copilot-${index + 1}`,
          type: "Security Assessment",
          title: "Security Assessment Finding",
          description: finding,
          severity: securityAssessmentReport.riskLevel,
          category: "Security Assessment",
          recommendation:
            securityAssessmentReport.recommendedNextSteps?.[index] ??
            "Review assessment finding."
        }))
      }
    ])
  );

  report.securityCopilotReport = securityCopilotReport;

  const evidenceGraph = timedStep("createEvidenceGraph", () =>
    createEvidenceGraph({
      autoLinkByFile: true,
      autoLinkByRule: true,
      autoLinkByAsset: true,
      maxAttackChainDepth: 6
    })
  );

  timedStep("evidenceGraph.add.walletRiskEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      [
        {
          id: "wallet-risk",
          type: "wallet_risk",
          category: "wallet_quantum_risk",
          title: "Wallet Quantum Risk",
          description: walletReport.recommendation,
          severity:
            walletReport.riskLevel === "CRITICAL"
              ? "critical"
              : walletReport.riskLevel === "HIGH"
                ? "high"
                : walletReport.riskLevel === "MEDIUM"
                  ? "medium"
                  : "low",
          confidence: 0.8,
          recommendation: walletReport.recommendation,
          remediation: [walletReport.recommendation],
          assets: [walletReport.walletAddress, "wallet", "signing_activity"].filter(Boolean),
          metadata: walletReport
        }
      ],
      "walletRiskEngine",
      "wallet_risk"
    )
  );

  timedStep("evidenceGraph.add.cryptoInventoryEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, cryptoInventoryReport.assets, "cryptoInventoryEngine", "crypto_inventory")
  );
  timedStep("evidenceGraph.add.quantumReadinessEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, quantumReadinessReport.findings, "quantumReadinessEngine", "quantum_readiness")
  );
  timedStep("evidenceGraph.add.dependencyIntelligenceEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, report.dependencyReport.dependencyFindings, "dependencyIntelligenceEngine", "dependency_intelligence")
  );
  timedStep("evidenceGraph.add.dependencyRiskEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, dependencyRiskReport.findings, "dependencyRiskEngine", "dependency_risk")
  );
  timedStep("evidenceGraph.add.attackSurfaceEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, attackSurfaceReport.attackFindings, "attackSurfaceEngine", "attack_surface")
  );
  timedStep("evidenceGraph.add.smartContractAuditEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, smartContractAuditReport.auditFindings, "smartContractAuditEngine", "smart_contract_audit")
  );
  timedStep("evidenceGraph.add.smartContractContextEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, smartContractContextReport.contexts, "smartContractContextEngine", "smart_contract_context")
  );
  timedStep("evidenceGraph.add.codeFlowScannerEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, codeFlowReport.findings, "codeFlowScannerEngine", "code_flow")
  );
  timedStep("evidenceGraph.add.routeExposureEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, routeExposureReport.findings, "routeExposureEngine", "route_exposure")
  );
  timedStep("evidenceGraph.add.trustBoundaryEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, trustBoundaryReport.findings, "trustBoundaryEngine", "trust_boundary")
  );
  timedStep("evidenceGraph.add.rootCauseEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, rootCauseReport.rootCauses, "rootCauseEngine", "root_cause")
  );
  timedStep("evidenceGraph.add.securityCopilotEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, securityCopilotReport.guidance, "securityCopilotEngine", "security_copilot")
  );
  timedStep("evidenceGraph.add.attackChainBuilderEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, attackChainBuilderReport.attackChains, "attackChainBuilderEngine", "attack_chain_builder")
  );
  timedStep("evidenceGraph.add.exploitSimulationEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, exploitSimulationReport.simulations, "exploitSimulationEngine", "exploit_simulation")
  );
  timedStep("evidenceGraph.add.remediationEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, remediationReport.remediationItems, "remediationEngine", "remediation")
  );
  timedStep("evidenceGraph.add.autoFixEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, autoFixReport.fixes, "autoFixEngine", "auto_fix")
  );
  timedStep("evidenceGraph.add.attackPathGeneratorEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, attackPathReport.attackPaths, "attackPathGeneratorEngine", "attack_path")
  );
  timedStep("evidenceGraph.add.complianceMappingEngine", () =>
    addEvidenceItemsToGraph(evidenceGraph, complianceMappingReport.mappedFindings, "complianceMappingEngine", "compliance_mapping")
  );

  const evidenceGraphReport = timedStep("evidenceGraph.exportGraph", () =>
    evidenceGraph.exportGraph()
  );

  report.evidenceGraphReport = evidenceGraphReport;

  const summary = timedStep("summaryFormatter", () => summaryFormatter(report));
  const markdownReport = timedStep("markdownReportGenerator", () =>
    markdownReportGenerator(report)
  );

  const executiveReportEngineReport = timedStep("executiveReportEngine", () =>
    executiveReportEngine({
      ...report,
      executiveReport: { summary },
      assessmentReport: report.securityAssessmentReport ?? report.assessmentReport ?? {},
      auditReport: { smartContractAuditReport, securityAuditLoopReport },
      riskProfile: {
        wallet: walletReport,
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
    })
  );

  report.executiveReportEngineReport = executiveReportEngineReport;

  const jsonExportReport = timedStep("jsonExportEngine", () =>
    jsonExportEngine({
      platform: "Quantum Shield Trinity",
      version: "2.3.0",
      ...report,
      riskProfile: {
        wallet: walletReport,
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
          evidenceGraphRiskLevel: evidenceGraphReport.summary?.risk?.level
        }
      }
    })
  );

  report.jsonExportReport = jsonExportReport;

  const htmlReport = timedStep("htmlReportGenerator", () =>
    htmlReportGenerator({
      ...report,
      executiveReport: {
        summary,
        markdownReport
      }
    })
  );

  const sarifReport = timedStep("sarifReportGenerator", () =>
    sarifReportGenerator({
      ...report,
      version: "2.0.0"
    })
  );

  const securityBadgeReport = timedStep("securityBadgeGenerator", () =>
    securityBadgeGenerator(report)
  );

  Object.assign(report, {
    summary,
    markdownReport,
    htmlReport,
    sarifReport,
    securityBadgeReport
  });

  console.log("");
  console.log("[QST] Scan completed successfully.");
  console.log("");

  return report;
}
