// src/engines/attackChainBuilderEngine.js

/**
 * Quantum Shield Trinity
 * Attack Chain Builder Engine
 *
 * Optimized:
 * - Prevents O(n²) edge explosion from hanging GitHub Actions
 * - Adds hard caps for nodes, edges, starts, neighbors, and chains
 * - Builds indexed relationships instead of comparing every finding to every other finding
 * - Keeps the same report shape your index.js expects
 */

const SEVERITY_WEIGHT = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 2,
  info: 1
};

const CATEGORY_WEIGHT = {
  route_exposure: 5,
  code_flow: 6,
  trust_boundary: 7,
  dependency_risk: 5,
  attack_surface: 6,
  smart_contract_audit: 7,
  crypto_inventory: 8,
  quantum_readiness: 5,
  exploit_simulation: 8,
  wallet_signing_flow: 10,
  command_injection: 10,
  ssrf: 8,
  path_traversal: 7,
  sql_injection: 8,
  xss: 6,
  web3_contract_flow: 8,
  public_to_internal: 7,
  user_input_to_signing: 10,
  user_input_to_execution: 10,
  secret_to_public_surface: 9,
  ci_to_deployment: 9
};

const DEFAULT_OPTIONS = {
  maxDepth: 3,
  limit: 25,
  maxNodes: 250,
  maxEdges: 750,
  maxStarts: 50,
  maxNeighborsPerNode: 20,
  maxChainsToExplore: 500
};

function safeArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function severityRank(severity = "info") {
  return SEVERITY_WEIGHT[String(severity).toLowerCase()] || 1;
}

function categoryRank(category = "general") {
  return CATEGORY_WEIGHT[String(category).toLowerCase()] || 3;
}

function normalizeText(value = "") {
  return String(value).trim().toLowerCase();
}

function normalizeFinding(item = {}, sourceEngine = "unknown", fallbackCategory = "general") {
  const type = item.type ?? item.dependency ?? item.simulationName ?? fallbackCategory;
  const category = item.category ?? fallbackCategory;
  const title = item.title ?? item.type ?? item.dependency ?? item.simulationName ?? "Security Finding";
  const severity = String(item.severity ?? item.riskLevel ?? "info").toLowerCase();

  return {
    id: item.id ?? `${sourceEngine}-${title}-${item.file ?? item.path ?? "unknown"}-${item.line ?? 0}`
      .replace(/[^a-zA-Z0-9_-]/g, "_")
      .slice(0, 180),
    sourceEngine,
    type,
    category,
    title,
    description:
      item.description ??
      item.risk ??
      item.whyItMatters ??
      item.potentialImpact ??
      item.recommendation ??
      "",
    severity,
    confidence: item.confidence ?? item.likelihood ?? 0.75,
    file: item.file ?? item.path ?? null,
    line: item.line ?? null,
    ruleId: item.ruleId ?? item.rule ?? item.cwe ?? null,
    attackSurface: safeArray(item.attackSurface ?? item.affectedArea).map(normalizeText).filter(Boolean),
    assets: [
      ...safeArray(item.assets),
      item.dependency,
      item.asset,
      item.contract,
      item.file,
      item.path,
      item.route,
      item.method,
      item.sink?.label,
      item.source?.label
    ].filter(Boolean).map(String),
    tags: safeArray(item.tags).map(normalizeText).filter(Boolean),
    remediation: [
      ...safeArray(item.remediation),
      item.recommendation,
      item.howToFix,
      item.recommendedFix,
      item.recommendedDefense,
      item.migrationPath
    ].filter(Boolean),
    evidence: item.evidence ?? {},
    raw: item
  };
}

function dedupeFindings(findings = []) {
  const seen = new Set();
  const output = [];

  for (const item of findings) {
    const key = `${item.sourceEngine}:${item.file}:${item.line}:${item.title}:${item.category}`;
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(item);
  }

  return output;
}

function collectFindings(report = {}, options = {}) {
  const findings = [];

  const add = (items, engine, category) => {
    for (const item of items || []) {
      findings.push(normalizeFinding(item, engine, category));
    }
  };

  add(report.routeExposureReport?.findings, "routeExposureEngine", "route_exposure");
  add(report.codeFlowReport?.findings, "codeFlowScannerEngine", "code_flow");
  add(report.trustBoundaryReport?.findings, "trustBoundaryEngine", "trust_boundary");
  add(report.attackSurfaceReport?.attackFindings, "attackSurfaceEngine", "attack_surface");
  add(report.smartContractAuditReport?.auditFindings, "smartContractAuditEngine", "smart_contract_audit");
  add(report.cryptoInventoryReport?.assets, "cryptoInventoryEngine", "crypto_inventory");
  add(report.quantumReadinessReport?.findings, "quantumReadinessEngine", "quantum_readiness");
  add(report.dependencyReport?.dependencyFindings, "dependencyIntelligenceEngine", "dependency_risk");
  add(report.exploitSimulationReport?.simulations, "exploitSimulationEngine", "exploit_simulation");

  for (const node of report.evidenceGraphReport?.nodes || []) {
    findings.push(normalizeFinding(node, "evidenceGraphEngine", node.category ?? "evidence_graph"));
  }

  return dedupeFindings(findings)
    .sort((a, b) => {
      const aScore = severityRank(a.severity) + categoryRank(a.category);
      const bScore = severityRank(b.severity) + categoryRank(b.category);
      return bScore - aScore;
    })
    .slice(0, options.maxNodes);
}

function addIndex(index, key, node) {
  if (!key) return;

  const normalized = normalizeText(key);
  if (!normalized) return;

  if (!index.has(normalized)) {
    index.set(normalized, []);
  }

  index.get(normalized).push(node);
}

function buildIndexes(findings = []) {
  const byFile = new Map();
  const byAsset = new Map();
  const bySurface = new Map();
  const byCategory = new Map();

  for (const node of findings) {
    addIndex(byFile, node.file, node);

    for (const asset of node.assets || []) {
      const assetText = String(asset);
      if (assetText.length > 120) continue;
      addIndex(byAsset, assetText, node);
    }

    for (const surface of node.attackSurface || []) {
      addIndex(bySurface, surface, node);
    }

    addIndex(byCategory, node.category, node);
  }

  return {
    byFile,
    byAsset,
    bySurface,
    byCategory
  };
}

function uniqueNodes(nodes = [], selfId = null, limit = 20) {
  const seen = new Set();
  const output = [];

  for (const node of nodes) {
    if (!node || node.id === selfId || seen.has(node.id)) continue;

    seen.add(node.id);
    output.push(node);

    if (output.length >= limit) break;
  }

  return output;
}

function routeToBoundary(a, b) {
  return a.category === "route_exposure" && (
    b.category === "trust_boundary" ||
    String(b.category).includes("user_input") ||
    b.category === "code_flow"
  );
}

function boundaryToHighValue(a, b) {
  const highValue = [
    "crypto_inventory",
    "smart_contract_audit",
    "wallet_signing_flow",
    "web3_contract_flow",
    "crypto",
    "secret_to_public_surface",
    "user_input_to_signing",
    "user_input_to_execution",
    "ci_to_deployment"
  ];

  const aIsBoundary =
    a.category === "trust_boundary" ||
    String(a.category).includes("user_input") ||
    a.category === "code_flow";

  const bIsHighValue =
    highValue.includes(b.category) ||
    b.tags?.some(tag => highValue.includes(tag)) ||
    b.assets?.some(asset => /wallet|private|secret|contract|database|runtime|deployment/i.test(String(asset)));

  return aIsBoundary && bIsHighValue;
}

function dependencyToExploit(a, b) {
  return a.category === "dependency_risk" && (
    b.category === "exploit_simulation" ||
    b.category === "attack_surface" ||
    b.category === "code_flow"
  );
}

function smartContractToCrypto(a, b) {
  return a.category === "smart_contract_audit" && (
    b.category === "crypto_inventory" ||
    b.category === "quantum_readiness" ||
    b.category === "web3_contract_flow"
  );
}

function connectionReason(a, b) {
  if (a.file && b.file && a.file === b.file) return "same_file";

  const aAssets = new Set(a.assets || []);
  if ((b.assets || []).some(asset => aAssets.has(asset))) return "shared_asset";

  const aSurface = new Set(a.attackSurface || []);
  if ((b.attackSurface || []).some(surface => aSurface.has(surface))) return "shared_attack_surface";

  if (routeToBoundary(a, b)) return "route_to_boundary";
  if (boundaryToHighValue(a, b)) return "boundary_to_high_value_asset";
  if (dependencyToExploit(a, b)) return "dependency_to_exploit";
  if (smartContractToCrypto(a, b)) return "contract_to_crypto_risk";

  return "related";
}

function buildTargetedCandidates(node, indexes, options) {
  const candidates = [];

  if (node.file) {
    candidates.push(...(indexes.byFile.get(normalizeText(node.file)) || []));
  }

  for (const asset of node.assets || []) {
    const assetText = String(asset);
    if (assetText.length > 120) continue;
    candidates.push(...(indexes.byAsset.get(normalizeText(assetText)) || []));
  }

  for (const surface of node.attackSurface || []) {
    candidates.push(...(indexes.bySurface.get(normalizeText(surface)) || []));
  }

  if (node.category === "route_exposure") {
    candidates.push(...(indexes.byCategory.get("trust_boundary") || []));
    candidates.push(...(indexes.byCategory.get("code_flow") || []));
  }

  if (node.category === "trust_boundary" || String(node.category).includes("user_input") || node.category === "code_flow") {
    candidates.push(...(indexes.byCategory.get("crypto_inventory") || []));
    candidates.push(...(indexes.byCategory.get("smart_contract_audit") || []));
    candidates.push(...(indexes.byCategory.get("exploit_simulation") || []));
  }

  if (node.category === "dependency_risk") {
    candidates.push(...(indexes.byCategory.get("exploit_simulation") || []));
    candidates.push(...(indexes.byCategory.get("attack_surface") || []));
    candidates.push(...(indexes.byCategory.get("code_flow") || []));
  }

  if (node.category === "smart_contract_audit") {
    candidates.push(...(indexes.byCategory.get("crypto_inventory") || []));
    candidates.push(...(indexes.byCategory.get("quantum_readiness") || []));
  }

  return uniqueNodes(candidates, node.id, options.maxNeighborsPerNode);
}

function shouldConnect(a, b) {
  if (!a || !b || a.id === b.id) return false;

  if (a.file && b.file && a.file === b.file) return true;

  const aAssets = new Set(a.assets || []);
  if ((b.assets || []).some(asset => aAssets.has(asset))) return true;

  const aSurface = new Set(a.attackSurface || []);
  if ((b.attackSurface || []).some(surface => aSurface.has(surface))) return true;

  if (routeToBoundary(a, b)) return true;
  if (boundaryToHighValue(a, b)) return true;
  if (dependencyToExploit(a, b)) return true;
  if (smartContractToCrypto(a, b)) return true;

  return false;
}

function buildGraph(findings = [], options = {}) {
  const indexes = buildIndexes(findings);
  const edges = [];
  const seenEdges = new Set();

  for (const node of findings) {
    const candidates = buildTargetedCandidates(node, indexes, options);

    for (const candidate of candidates) {
      if (edges.length >= options.maxEdges) break;
      if (!shouldConnect(node, candidate)) continue;

      const key = `${node.id}->${candidate.id}`;
      if (seenEdges.has(key)) continue;

      seenEdges.add(key);

      edges.push({
        from: node.id,
        to: candidate.id,
        relationship: connectionReason(node, candidate)
      });
    }

    if (edges.length >= options.maxEdges) break;
  }

  return {
    nodes: findings,
    edges
  };
}

function buildNeighborMap(graph) {
  const nodeById = new Map(graph.nodes.map(node => [node.id, node]));
  const neighbors = new Map();

  for (const edge of graph.edges) {
    if (!neighbors.has(edge.from)) {
      neighbors.set(edge.from, []);
    }

    const target = nodeById.get(edge.to);
    if (target) {
      neighbors.get(edge.from).push(target);
    }
  }

  return neighbors;
}

function isEntryNode(node) {
  return (
    node.category === "route_exposure" ||
    node.category === "attack_surface" ||
    node.attackSurface.includes("api") ||
    node.attackSurface.includes("web") ||
    node.type === "route_exposure"
  );
}

function isHighValueEndNode(node) {
  return (
    node.severity === "critical" ||
    [
      "crypto_inventory",
      "smart_contract_audit",
      "wallet_signing_flow",
      "web3_contract_flow",
      "user_input_to_signing",
      "user_input_to_execution",
      "secret_to_public_surface",
      "ci_to_deployment",
      "exploit_simulation"
    ].includes(node.category) ||
    node.assets.some(asset => /wallet|private|secret|database|contract|runtime|deployment/i.test(String(asset)))
  );
}

function scoreChain(path = []) {
  const severityScore = path.reduce((sum, node) => sum + severityRank(node.severity), 0);
  const categoryScore = path.reduce((sum, node) => sum + categoryRank(node.category), 0);
  const confidenceAvg =
    path.reduce((sum, node) => sum + Number(node.confidence || 0.5), 0) /
    Math.max(path.length, 1);

  const lengthBonus = Math.min(20, path.length * 4);
  const raw = (severityScore * 1.4 + categoryScore * 0.9) * confidenceAvg + lengthBonus;
  const score = Math.max(1, Math.min(100, Math.round(raw)));

  let severity = "low";
  if (score >= 85) severity = "critical";
  else if (score >= 70) severity = "high";
  else if (score >= 45) severity = "medium";

  let exploitability = "low";
  if (score >= 80) exploitability = "critical";
  else if (score >= 65) exploitability = "high";
  else if (score >= 40) exploitability = "medium";

  return {
    score,
    severity,
    exploitability
  };
}

function summarizeChain(path = []) {
  if (path.length === 0) return "No attack chain path available.";

  const entry = path[0];
  const end = path[path.length - 1];

  return `Potential chain from ${entry.title} to ${end.title}. This suggests an attacker may be able to move across ${path.length} connected risk nodes.`;
}

function buildChainRecommendations(path = []) {
  const recs = [];

  const hasRoute = path.some(node => node.category === "route_exposure");
  const hasBoundary = path.some(node => node.category === "trust_boundary" || String(node.category).includes("user_input"));
  const hasSigning = path.some(node => /sign|wallet|private/i.test(`${node.category} ${node.title} ${node.assets.join(" ")}`));
  const hasCommand = path.some(node => /command|execution|exec/i.test(`${node.category} ${node.title}`));
  const hasCi = path.some(node => /ci|deployment|supply/i.test(`${node.category} ${node.title}`));

  if (hasRoute) recs.push("Add explicit authentication, authorization, validation, and rate limiting at the route entry point.");
  if (hasBoundary) recs.push("Add trust-boundary controls before sensitive sinks and document the boundary owner.");
  if (hasSigning) recs.push("Require explicit user consent, transaction simulation, chain validation, and signing limits.");
  if (hasCommand) recs.push("Remove command execution or isolate it with strict allowlists and non-shell execution.");
  if (hasCi) recs.push("Restrict CI/CD permissions, protect environments, and require approval before deployment/publishing.");

  if (recs.length === 0) {
    recs.push("Break the chain by remediating the earliest high-severity node first.");
  }

  return recs;
}

function buildChainObject(path = [], graph) {
  const scored = scoreChain(path);
  const chainId = `CHAIN-${path.map(node => node.id).join("-")}`
    .replace(/[^a-zA-Z0-9_-]/g, "_")
    .slice(0, 180);

  const relationships = [];

  for (let i = 0; i < path.length - 1; i++) {
    const from = path[i].id;
    const to = path[i + 1].id;
    const edge = graph.edges.find(item => item.from === from && item.to === to);

    relationships.push({
      from,
      to,
      relationship: edge?.relationship ?? "related"
    });
  }

  return {
    id: chainId,
    type: "attack_chain",
    title: path.map(node => node.title).join(" -> "),
    summary: summarizeChain(path),
    severity: scored.severity,
    chainScore: scored.score,
    exploitability: scored.exploitability,
    length: path.length,
    entryPoint: path[0]?.title ?? "Unknown entry",
    finalImpact: path[path.length - 1]?.title ?? "Unknown impact",
    files: [...new Set(path.map(node => node.file).filter(Boolean))],
    assets: [...new Set(path.flatMap(node => node.assets || []))],
    attackSurface: [...new Set(path.flatMap(node => node.attackSurface || []))],
    path: path.map(node => ({
      id: node.id,
      sourceEngine: node.sourceEngine,
      category: node.category,
      title: node.title,
      severity: node.severity,
      file: node.file,
      line: node.line
    })),
    relationships,
    recommendations: buildChainRecommendations(path)
  };
}

function dedupeChains(chains = []) {
  const seen = new Set();
  const output = [];

  for (const chain of chains) {
    const key = chain.path.map(node => node.id).join(">");
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(chain);
  }

  return output;
}

function findChains(graph, options = {}) {
  const maxDepth = options.maxDepth;
  const limit = options.limit;
  const chains = [];
  const neighborMap = buildNeighborMap(graph);

  const starts = graph.nodes
    .filter(isEntryNode)
    .sort((a, b) => {
      const aScore = severityRank(a.severity) + categoryRank(a.category);
      const bScore = severityRank(b.severity) + categoryRank(b.category);
      return bScore - aScore;
    })
    .slice(0, options.maxStarts);

  let explored = 0;

  const walk = (node, path, visited, depth) => {
    if (depth >= maxDepth) return;
    if (chains.length >= limit) return;
    if (explored >= options.maxChainsToExplore) return;

    explored += 1;

    const neighbors = (neighborMap.get(node.id) || [])
      .slice(0, options.maxNeighborsPerNode);

    for (const next of neighbors) {
      if (chains.length >= limit) break;
      if (visited.has(next.id)) continue;

      const nextPath = [...path, next];
      const nextVisited = new Set(visited);
      nextVisited.add(next.id);

      if (nextPath.length >= 2 && isHighValueEndNode(next)) {
        chains.push(buildChainObject(nextPath, graph));
      }

      walk(next, nextPath, nextVisited, depth + 1);
    }
  };

  for (const start of starts) {
    if (chains.length >= limit) break;
    if (explored >= options.maxChainsToExplore) break;

    walk(start, [start], new Set([start.id]), 1);
  }

  return dedupeChains(chains)
    .sort((a, b) => b.chainScore - a.chainScore)
    .slice(0, limit);
}

function summarizeChains(chains = []) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };

  for (const chain of chains) {
    counts[chain.severity] = (counts[chain.severity] || 0) + 1;
  }

  const weighted =
    counts.critical * 30 +
    counts.high * 18 +
    counts.medium * 9 +
    counts.low * 3;

  const score = Math.max(0, Math.min(100, 100 - weighted));

  let riskLevel = "LOW";
  if (counts.critical > 0 || weighted >= 90) riskLevel = "CRITICAL";
  else if (counts.high > 1 || weighted >= 55) riskLevel = "HIGH";
  else if (counts.high > 0 || counts.medium > 2 || weighted >= 25) riskLevel = "MEDIUM";

  return {
    ...counts,
    weighted,
    score,
    riskLevel
  };
}

function buildTopRecommendations(chains = []) {
  const recommendations = [];

  const critical = chains.find(chain => chain.severity === "critical");
  if (critical) {
    recommendations.push({
      severity: "critical",
      recommendation: "Immediately break the highest-scoring critical attack chain at its earliest public entry point.",
      chain: critical.id
    });
  }

  const signing = chains.find(chain =>
    chain.assets.some(asset => /wallet|private|sign/i.test(String(asset)))
  );

  if (signing) {
    recommendations.push({
      severity: "critical",
      recommendation: "Prioritize chains that reach wallet/private-key/signing assets.",
      chain: signing.id
    });
  }

  const ci = chains.find(chain =>
    chain.assets.some(asset => /deploy|pipeline|ci/i.test(String(asset))) ||
    chain.attackSurface.some(surface => /ci|supply/i.test(String(surface)))
  );

  if (ci) {
    recommendations.push({
      severity: "high",
      recommendation: "Prioritize CI/CD and supply-chain attack chains because they can impact production releases.",
      chain: ci.id
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      severity: "info",
      recommendation: "No major attack chains were generated. Continue improving evidence coverage with deeper engines."
    });
  }

  return recommendations.slice(0, 10);
}

export function attackChainBuilderEngine(report = {}, options = {}) {
  const config = {
    ...DEFAULT_OPTIONS,
    ...options
  };

  const findings = collectFindings(report, config);
  const graph = buildGraph(findings, config);
  const chains = findChains(graph, config);
  const summary = summarizeChains(chains);

  return {
    engine: "attackChainBuilderEngine",
    optimized: true,
    limits: config,
    totalEvidenceNodes: graph.nodes.length,
    totalEvidenceEdges: graph.edges.length,
    totalAttackChains: chains.length,
    criticalAttackChains: summary.critical,
    highAttackChains: summary.high,
    mediumAttackChains: summary.medium,
    lowAttackChains: summary.low,
    attackChainScore: summary.score,
    attackChainRiskLevel: summary.riskLevel,
    attackChains: chains,
    graphPreview: {
      nodes: graph.nodes.slice(0, 100).map(node => ({
        id: node.id,
        category: node.category,
        title: node.title,
        severity: node.severity,
        file: node.file,
        line: node.line
      })),
      edges: graph.edges.slice(0, 250)
    },
    recommendations: buildTopRecommendations(chains)
  };
}

export default attackChainBuilderEngine;
