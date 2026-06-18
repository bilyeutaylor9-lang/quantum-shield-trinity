// src/index.js
// Quantum Shield Trinity v2.5.0
// Upgraded with Reactive Security Engine wiring

import { fileScanner } from "./scanners/fileScanner.js";
import { repositoryScannerEngine } from "./engines/repositoryScannerEngine.js";
import { dependencyIntelligenceEngine } from "./engines/dependencyIntelligenceEngine.js";
import { dependencyRiskEngine } from "./engines/dependencyRiskEngine.js";
import { attackSurfaceEngine } from "./engines/attackSurfaceEngine.js";
import { smartContractAuditEngine } from "./engines/smartContractAuditEngine.js";
import { reactiveSecurityEngine } from "./engines/reactiveSecurityEngine.js";
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
import { deepScanOrchestratorEngine } from "./engines/deepScanOrchestratorEngine.js";
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
  reactiveSecurityEngine,
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
  deepScanOrchestratorEngine,
  createEvidenceGraph,
  htmlReportGenerator,
  sarifReportGenerator,
  securityBadgeGenerator,
  markdownReportGenerator,
  summaryFormatter
};

const QST_VERSION = "2.5.0";

const DEFAULT_IGNORE_PATHS = [
  "node_modules/",
  "dist/",
  "build/",
  ".git/",
  "coverage/",
  "docs/results/",
  "reports/",
  "src/data/",
  "test/",
  "tests/",
  "__fixtures__/"
];

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

const limitEvidenceItems = (items = [], limit = 100) => {
  if (!Array.isArray(items)) return [];
  return items.slice(0, limit);
};

const normalizeSeverity = (value = "info") => {
  const severity = String(value ?? "info").toLowerCase();

  if (["critical", "high", "medium", "low", "info"].includes(severity)) {
    return severity;
  }

  if (severity === "severe") return "critical";
  if (severity === "moderate") return "medium";

  return "info";
};

const severityRank = (value = "info") => {
  const severity = normalizeSeverity(value);

  if (severity === "critical") return 5;
  if (severity === "high") return 4;
  if (severity === "medium") return 3;
  if (severity === "low") return 2;

  return 1;
};

const shouldIgnoreFinding = (finding = {}, options = {}) => {
  const file = String(finding.file ?? finding.path ?? "").replaceAll("\\", "/");
  const ignoredPaths = options.ignorePaths ?? DEFAULT_IGNORE_PATHS;

  if (!file) return false;

  return ignoredPaths.some((ignored) => file.includes(ignored));
};

const filterFindings = (items = [], options = {}) => {
  if (!Array.isArray(items)) return [];
  return items.filter((item) => !shouldIgnoreFinding(item, options));
};

const normalizeFindingShape = (item = {}, engine = "unknown") => ({
  id:
    item.id ??
    `${engine}:${item.file ?? item.path ?? "unknown"}:${item.line ?? 0}:${
      item.title ?? item.type ?? item.finding ?? item.issue ?? "finding"
    }`,
  engine,
  severity: normalizeSeverity(item.severity ?? item.riskLevel ?? item.exploitability),
  title: item.title ?? item.type ?? item.finding ?? item.issue ?? "Security Finding",
  file: item.file ?? item.path ?? null,
  line: item.line ?? null,
  description:
    item.description ??
    item.reason ??
    item.summary ??
    item.risk ??
    item.whyItMatters ??
    item.potentialImpact ??
    "",
  evidence: item.evidence ?? item.snippet ?? item.code ?? item.matchedText ?? "",
  confidence: item.confidence ?? "medium",
  cwe: item.cwe ?? null,
  owasp: item.owasp ?? item.owaspWebTop10 ?? item.owaspSmartContractTop10 ?? null,
  recommendation:
    item.recommendation ??
    item.recommendedFix ??
    item.recommendedDefense ??
    item.howToFix ??
    "Review finding manually.",
  raw: item
});

const buildNormalizedFindingsReport = (report = {}, runtimeOptions = {}) => {
  const normalizedFindings = [
    ...(report.dependencyRiskReport?.findings ?? []).map((item) =>
      normalizeFindingShape(item, "dependencyRiskEngine")
    ),
    ...(report.attackSurfaceReport?.attackFindings ?? []).map((item) =>
      normalizeFindingShape(item, "attackSurfaceEngine")
    ),
    ...(report.smartContractAuditReport?.auditFindings ?? []).map((item) =>
      normalizeFindingShape(item, "smartContractAuditEngine")
    ),
    ...(report.reactiveSecurityReport?.findings ?? []).map((item) =>
      normalizeFindingShape(item, "reactiveSecurityEngine")
    ),
    ...(report.smartContractContextReport?.contexts ?? []).map((item) =>
      normalizeFindingShape(item, "smartContractContextEngine")
    ),
    ...(report.quantumReadinessReport?.findings ?? []).map((item) =>
      normalizeFindingShape(item, "quantumReadinessEngine")
    ),
    ...(report.codeFlowReport?.findings ?? []).map((item) =>
      normalizeFindingShape(item, "codeFlowScannerEngine")
    ),
    ...(report.routeExposureReport?.findings ?? []).map((item) =>
      normalizeFindingShape(item, "routeExposureEngine")
    ),
    ...(report.trustBoundaryReport?.findings ?? []).map((item) =>
      normalizeFindingShape(item, "trustBoundaryEngine")
    ),
    ...(report.attackChainBuilderReport?.attackChains ?? []).map((item) =>
      normalizeFindingShape(item, "attackChainBuilderEngine")
    ),
    ...(report.attackPathReport?.attackPaths ?? []).map((item) =>
      normalizeFindingShape(item, "attackPathGeneratorEngine")
    ),
    ...(report.rootCauseReport?.rootCauses ?? []).map((item) =>
      normalizeFindingShape(item, "rootCauseEngine")
    ),
    ...(report.securityCopilotReport?.guidance ?? []).map((item) =>
      normalizeFindingShape(item, "securityCopilotEngine")
    ),
    ...(report.deepScanOrchestratorReport?.topSignals ?? []).map((item) =>
      normalizeFindingShape(
        {
          ...item,
          title: `Deep Scan Signal: ${item.engine}`,
          severity: report.deepScanOrchestratorReport?.riskLevel ?? "info",
          description: `${item.engine} contributed ${item.findings} finding(s).`,
          recommendation: report.deepScanOrchestratorReport?.recommendation
        },
        "deepScanOrchestratorEngine"
      )
    )
  ];

  const filtered = filterFindings(normalizedFindings, runtimeOptions).sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity)
  );

  return {
    engine: "Normalized Findings Layer",
    generatedAt: new Date().toISOString(),
    profile: runtimeOptions.profile,
    totalFindingsBeforeFilter: normalizedFindings.length,
    totalFindingsAfterFilter: filtered.length,
    ignoredFindings: normalizedFindings.length - filtered.length,
    counts: {
      critical: filtered.filter((item) => item.severity === "critical").length,
      high: filtered.filter((item) => item.severity === "high").length,
      medium: filtered.filter((item) => item.severity === "medium").length,
      low: filtered.filter((item) => item.severity === "low").length,
      info: filtered.filter((item) => item.severity === "info").length
    },
    topFindings: filtered.slice(0, 15),
    findings: filtered
  };
};

const buildRuntimeOptions = (options = {}) => ({
  profile: options.profile ?? "deep",
  ignorePaths: options.ignorePaths ?? DEFAULT_IGNORE_PATHS,
  maxEvidenceItems: options.maxEvidenceItems ?? 100,
  attackChain: {
    maxDepth: options.attackChain?.maxDepth ?? 3,
    limit: options.attackChain?.limit ?? 25,
    maxNodes: options.attackChain?.maxNodes ?? 250,
    maxEdges: options.attackChain?.maxEdges ?? 750,
    maxStarts: options.attackChain?.maxStarts ?? 50,
    maxNeighborsPerNode: options.attackChain?.maxNeighborsPerNode ?? 20,
    maxChainsToExplore: options.attackChain?.maxChainsToExplore ?? 500
  }
});

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
  severity: normalizeSeverity(item.severity ?? "info"),
  riskLevel: normalizeSeverity(item.severity ?? "info"),
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
    signedMessages:
      existingWallet.signedMessages ?? cryptoInventoryReport.quantumExposedAssets ?? 0
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
          finding.type ??
          finding.title ??
          finding.dependency ??
          finding.simulationName ??
          "Unknown Finding",
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
          rootCause.recommendation ??
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

const addEvidenceItemsToGraph = (
  evidenceGraph,
  items = [],
  engine = "unknown",
  fallbackCategory = "general"
) => {
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
  const runtimeOptions = buildRuntimeOptions(options);

  console.log("");
  console.log("Quantum Shield Trinity Deep Scan");
  console.log("--------------------------------");
  console.log(`[QST] Version: ${QST_VERSION}`);
  console.log(`[QST] Profile: ${runtimeOptions.profile}`);
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

  const reactiveSecurityReport = timedStep("reactiveSecurityEngine", () =>
    reactiveSecurityEngine({
      files: scanResult.files,
      smartContractAuditReport
    })
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
    version: QST_VERSION,
    profile: runtimeOptions.profile,
    targetDirectory,
    scannedAt: new Date().toISOString(),
    scannedFiles: scanResult.files.length,
    dependencyReport,
    dependencyRiskReport,
    attackSurfaceReport,
    smartContractAuditReport,
    reactiveSecurityReport,
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
      reactiveSecurityReport,
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
      { engine: "reactiveSecurityEngine", items: reactiveSecurityReport.findings },
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
    attackChainBuilderEngine(report, runtimeOptions.attackChain)
  );

  report.attackChainBuilderReport = attackChainBuilderReport;

  const securityAuditLoopReport = timedStep("securityAuditLoopEngine", () =>
    securityAuditLoopEngine({
      previousHash:
        process.env.QST_PREVIOUS_AUDIT_HASH ?? report.previousAuditHash ?? "GENESIS",
      entropySeed: `${Date.now()}-${targetDirectory}-${scanResult.files.length}`,
      systemState: {
        platform: "Quantum Shield Trinity",
        version: QST_VERSION,
        profile: runtimeOptions.profile,
        targetDirectory,
        scannedFiles: scanResult.files.length,
        walletRiskLevel: walletReport.riskLevel,
        walletRiskScore: walletReport.score,
        securityScore:
          securityScoreReport.securityScore ?? securityAssessmentReport.totalScore ?? 0,
        securityRiskLevel:
          securityScoreReport.riskLevel ?? securityAssessmentReport.riskLevel ?? "UNKNOWN",
        dependencyRiskLevel: dependencyRiskReport.riskLevel,
        reactiveSecurityRiskLevel: reactiveSecurityReport.summary?.riskLevel ?? "UNKNOWN",
        reactiveSecurityRiskScore: reactiveSecurityReport.summary?.riskScore ?? null,
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
      { engine: "reactiveSecurityEngine", items: reactiveSecurityReport.findings },
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
      maxAttackChainDepth: 4
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
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(cryptoInventoryReport.assets, runtimeOptions.maxEvidenceItems),
      "cryptoInventoryEngine",
      "crypto_inventory"
    )
  );

  timedStep("evidenceGraph.add.quantumReadinessEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(quantumReadinessReport.findings, runtimeOptions.maxEvidenceItems),
      "quantumReadinessEngine",
      "quantum_readiness"
    )
  );

  timedStep("evidenceGraph.add.dependencyIntelligenceEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(report.dependencyReport.dependencyFindings, runtimeOptions.maxEvidenceItems),
      "dependencyIntelligenceEngine",
      "dependency_intelligence"
    )
  );

  timedStep("evidenceGraph.add.dependencyRiskEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(dependencyRiskReport.findings, runtimeOptions.maxEvidenceItems),
      "dependencyRiskEngine",
      "dependency_risk"
    )
  );

  timedStep("evidenceGraph.add.attackSurfaceEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(attackSurfaceReport.attackFindings, runtimeOptions.maxEvidenceItems),
      "attackSurfaceEngine",
      "attack_surface"
    )
  );

  timedStep("evidenceGraph.add.smartContractAuditEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(smartContractAuditReport.auditFindings, runtimeOptions.maxEvidenceItems),
      "smartContractAuditEngine",
      "smart_contract_audit"
    )
  );

  timedStep("evidenceGraph.add.reactiveSecurityEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(reactiveSecurityReport.findings, runtimeOptions.maxEvidenceItems),
      "reactiveSecurityEngine",
      "reactive_security"
    )
  );

  timedStep("evidenceGraph.add.smartContractContextEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(smartContractContextReport.contexts, runtimeOptions.maxEvidenceItems),
      "smartContractContextEngine",
      "smart_contract_context"
    )
  );

  timedStep("evidenceGraph.add.codeFlowScannerEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(codeFlowReport.findings, runtimeOptions.maxEvidenceItems),
      "codeFlowScannerEngine",
      "code_flow"
    )
  );

  timedStep("evidenceGraph.add.routeExposureEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(routeExposureReport.findings, runtimeOptions.maxEvidenceItems),
      "routeExposureEngine",
      "route_exposure"
    )
  );

  timedStep("evidenceGraph.add.trustBoundaryEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(trustBoundaryReport.findings, runtimeOptions.maxEvidenceItems),
      "trustBoundaryEngine",
      "trust_boundary"
    )
  );

  timedStep("evidenceGraph.add.rootCauseEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(rootCauseReport.rootCauses, runtimeOptions.maxEvidenceItems),
      "rootCauseEngine",
      "root_cause"
    )
  );

  timedStep("evidenceGraph.add.securityCopilotEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(securityCopilotReport.guidance, runtimeOptions.maxEvidenceItems),
      "securityCopilotEngine",
      "security_copilot"
    )
  );

  timedStep("evidenceGraph.add.attackChainBuilderEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(attackChainBuilderReport.attackChains, 50),
      "attackChainBuilderEngine",
      "attack_chain_builder"
    )
  );

  timedStep("evidenceGraph.add.exploitSimulationEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(exploitSimulationReport.simulations, 50),
      "exploitSimulationEngine",
      "exploit_simulation"
    )
  );

  timedStep("evidenceGraph.add.remediationEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(remediationReport.remediationItems, runtimeOptions.maxEvidenceItems),
      "remediationEngine",
      "remediation"
    )
  );

  timedStep("evidenceGraph.add.autoFixEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(autoFixReport.fixes, runtimeOptions.maxEvidenceItems),
      "autoFixEngine",
      "auto_fix"
    )
  );

  timedStep("evidenceGraph.add.attackPathGeneratorEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(attackPathReport.attackPaths, 50),
      "attackPathGeneratorEngine",
      "attack_path"
    )
  );

  timedStep("evidenceGraph.add.complianceMappingEngine", () =>
    addEvidenceItemsToGraph(
      evidenceGraph,
      limitEvidenceItems(complianceMappingReport.mappedFindings, runtimeOptions.maxEvidenceItems),
      "complianceMappingEngine",
      "compliance_mapping"
    )
  );

  const evidenceGraphReport = timedStep("evidenceGraph.exportGraph", () =>
    evidenceGraph.exportGraph()
  );

  report.evidenceGraphReport = evidenceGraphReport;

  const deepScanOrchestratorReport = timedStep("deepScanOrchestratorEngine", () =>
    deepScanOrchestratorEngine({
      codeFlowReport,
      routeExposureReport,
      trustBoundaryReport,
      evidenceGraphReport,
      attackChainBuilderReport,
      reactiveSecurityReport,
      dependencyBehaviorReport: report.dependencyBehaviorReport,
      semanticConfigReport: report.semanticConfigReport
    })
  );

  report.deepScanOrchestratorReport = deepScanOrchestratorReport;

  const normalizedFindingsReport = timedStep("buildNormalizedFindingsReport", () =>
    buildNormalizedFindingsReport(report, runtimeOptions)
  );

  report.normalizedFindingsReport = normalizedFindingsReport;

  const summary = timedStep("summaryFormatter", () => summaryFormatter(report));

  const markdownReport = timedStep("markdownReportGenerator", () =>
    markdownReportGenerator(report)
  );

  const executiveReportEngineReport = timedStep("executiveReportEngine", () =>
    executiveReportEngine({
      ...report,
      executiveReport: { summary },
      assessmentReport: report.securityAssessmentReport ?? report.assessmentReport ?? {},
      auditReport: { smartContractAuditReport, reactiveSecurityReport, securityAuditLoopReport },
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
        },
        reactiveSecurity: {
          riskLevel: reactiveSecurityReport.summary?.riskLevel ?? "UNKNOWN",
          riskScore: reactiveSecurityReport.summary?.riskScore ?? null,
          totalFindings: reactiveSecurityReport.summary?.totalFindings ?? 0
        },
        normalizedFindings: {
          total: normalizedFindingsReport.totalFindingsAfterFilter,
          ignored: normalizedFindingsReport.ignoredFindings,
          counts: normalizedFindingsReport.counts
        },
        deepScanOrchestrator: {
          riskScore: deepScanOrchestratorReport.riskScore,
          riskLevel: deepScanOrchestratorReport.riskLevel,
          totalFindings: deepScanOrchestratorReport.totalFindings,
          activeEngines: deepScanOrchestratorReport.activeEngines,
          recommendation: deepScanOrchestratorReport.recommendation
        }
      }
    })
  );

  report.executiveReportEngineReport = executiveReportEngineReport;

  const jsonExportReport = timedStep("jsonExportEngine", () =>
    jsonExportEngine({
      platform: "Quantum Shield Trinity",
      version: QST_VERSION,
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
        reactiveSecurity: {
          riskLevel: reactiveSecurityReport.summary?.riskLevel ?? "UNKNOWN",
          riskScore: reactiveSecurityReport.summary?.riskScore ?? null,
          findings: reactiveSecurityReport.summary?.totalFindings ?? 0,
          high: reactiveSecurityReport.summary?.high ?? 0,
          medium: reactiveSecurityReport.summary?.medium ?? 0,
          low: reactiveSecurityReport.summary?.low ?? 0
        },
        deepScan: {
          codeFlowRiskLevel: codeFlowReport.riskLevel,
          routeExposureRiskLevel: routeExposureReport.routeExposureRiskLevel,
          trustBoundaryRiskLevel: trustBoundaryReport.trustBoundaryRiskLevel,
          attackChainRiskLevel: attackChainBuilderReport.attackChainRiskLevel,
          evidenceGraphRiskLevel: evidenceGraphReport.summary?.risk?.level,
          orchestratorRiskScore: deepScanOrchestratorReport.riskScore,
          orchestratorRiskLevel: deepScanOrchestratorReport.riskLevel,
          orchestratorTotalFindings: deepScanOrchestratorReport.totalFindings,
          orchestratorActiveEngines: deepScanOrchestratorReport.activeEngines,
          orchestratorRecommendation: deepScanOrchestratorReport.recommendation
        },
        normalizedFindings: {
          total: normalizedFindingsReport.totalFindingsAfterFilter,
          ignored: normalizedFindingsReport.ignoredFindings,
          counts: normalizedFindingsReport.counts
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
    securityBadgeReport,
    normalizedFindingsReport,
    deepScanOrchestratorReport,
    reactiveSecurityReport,
    profile: runtimeOptions.profile
  });

  console.log("");
  console.log("[QST] Reactive Security");
  console.log("-----------------------");
  console.log(`[QST] Risk Score: ${reactiveSecurityReport.summary?.riskScore ?? "N/A"}`);
  console.log(`[QST] Risk Level: ${reactiveSecurityReport.summary?.riskLevel ?? "UNKNOWN"}`);
  console.log(`[QST] Findings: ${reactiveSecurityReport.summary?.totalFindings ?? 0}`);

  console.log("");
  console.log("[QST] Normalized Findings");
  console.log("-------------------------");
  console.log(`[QST] Before Filter: ${normalizedFindingsReport.totalFindingsBeforeFilter}`);
  console.log(`[QST] After Filter: ${normalizedFindingsReport.totalFindingsAfterFilter}`);
  console.log(`[QST] Ignored: ${normalizedFindingsReport.ignoredFindings}`);

  console.log("");
  console.log("[QST] Deep Scan Orchestrator");
  console.log("----------------------------");
  console.log(`[QST] Risk Score: ${deepScanOrchestratorReport.riskScore}`);
  console.log(`[QST] Risk Level: ${deepScanOrchestratorReport.riskLevel}`);
  console.log(`[QST] Active Engines: ${deepScanOrchestratorReport.activeEngines}`);
  console.log(`[QST] Total Findings: ${deepScanOrchestratorReport.totalFindings}`);

  console.log("");
  console.log("[QST] Scan completed successfully.");
  console.log("");

  return report;
}
