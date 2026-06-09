// src/engines/evidenceGraphEngine.js

/**
 * Quantum Shield Trinity
 * Evidence Graph Engine
 *
 * Purpose:
 * Converts flat scanner findings into a connected evidence graph.
 *
 * This becomes the core layer for:
 * - deep scan evidence
 * - attack paths
 * - trust boundaries
 * - route exposure
 * - exploit chains
 * - confidence scoring
 * - remediation priority
 */

const SEVERITY_WEIGHT = {
  info: 1,
  low: 2,
  medium: 4,
  high: 7,
  critical: 10
};

const CONFIDENCE_WEIGHT = {
  low: 0.4,
  medium: 0.65,
  high: 0.85,
  certain: 1.0
};

function normalizeSeverity(severity = "info") {
  const s = String(severity).toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(s)) return s;
  return "info";
}

function normalizeConfidence(confidence = 0.5) {
  if (typeof confidence === "number") {
    return Math.max(0, Math.min(1, confidence));
  }

  const c = String(confidence).toLowerCase();
  return CONFIDENCE_WEIGHT[c] ?? 0.5;
}

function makeId(prefix = "QS-EVIDENCE") {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function safeArray(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function cleanSnippet(snippet = "", maxLength = 220) {
  if (!snippet) return "";
  return String(snippet).replace(/\s+/g, " ").slice(0, maxLength);
}

export class EvidenceNode {
  constructor(data = {}) {
    this.id = data.id || makeId("QS-NODE");
    this.type = data.type || "finding";
    this.category = data.category || "general";
    this.title = data.title || data.name || "Untitled Evidence";
    this.description = data.description || "";
    this.severity = normalizeSeverity(data.severity);
    this.confidence = normalizeConfidence(data.confidence);

    this.file = data.file || data.path || null;
    this.line = data.line ?? null;
    this.column = data.column ?? null;

    this.ruleId = data.ruleId || data.rule || null;
    this.engine = data.engine || "unknown";
    this.cwe = safeArray(data.cwe);
    this.owasp = safeArray(data.owasp);
    this.tags = safeArray(data.tags);

    this.evidence = {
      snippet: cleanSnippet(data.snippet || data.evidence?.snippet || ""),
      matchedText: cleanSnippet(data.matchedText || data.evidence?.matchedText || ""),
      pattern: data.pattern || data.evidence?.pattern || null,
      source: data.source || data.evidence?.source || null
    };

    this.attackSurface = safeArray(data.attackSurface);
    this.assets = safeArray(data.assets);
    this.remediation = safeArray(data.remediation || data.fix);

    this.metadata = data.metadata || {};
    this.createdAt = data.createdAt || new Date().toISOString();
  }

  getRiskScore() {
    const severityScore = SEVERITY_WEIGHT[this.severity] || 1;
    return Math.round(severityScore * this.confidence * 10);
  }

  toJSON() {
    return {
      id: this.id,
      type: this.type,
      category: this.category,
      title: this.title,
      description: this.description,
      severity: this.severity,
      confidence: this.confidence,
      riskScore: this.getRiskScore(),
      file: this.file,
      line: this.line,
      column: this.column,
      ruleId: this.ruleId,
      engine: this.engine,
      cwe: this.cwe,
      owasp: this.owasp,
      tags: this.tags,
      evidence: this.evidence,
      attackSurface: this.attackSurface,
      assets: this.assets,
      remediation: this.remediation,
      metadata: this.metadata,
      createdAt: this.createdAt
    };
  }
}

export class EvidenceEdge {
  constructor(from, to, relationship = "related_to", metadata = {}) {
    this.id = makeId("QS-EDGE");
    this.from = from;
    this.to = to;
    this.relationship = relationship;
    this.metadata = metadata;
    this.createdAt = new Date().toISOString();
  }

  toJSON() {
    return {
      id: this.id,
      from: this.from,
      to: this.to,
      relationship: this.relationship,
      metadata: this.metadata,
      createdAt: this.createdAt
    };
  }
}

export class EvidenceGraphEngine {
  constructor(options = {}) {
    this.nodes = new Map();
    this.edges = [];
    this.options = {
      autoLinkByFile: true,
      autoLinkByRule: true,
      autoLinkByAsset: true,
      maxAttackChainDepth: 5,
      ...options
    };
  }

  addNode(data = {}) {
    const node = data instanceof EvidenceNode ? data : new EvidenceNode(data);

    this.nodes.set(node.id, node);

    if (this.options.autoLinkByFile || this.options.autoLinkByRule || this.options.autoLinkByAsset) {
      this.autoLinkNode(node);
    }

    return node;
  }

  addFinding(finding = {}) {
    return this.addNode({
      ...finding,
      type: finding.type || "finding"
    });
  }

  addAsset(asset = {}) {
    return this.addNode({
      ...asset,
      type: "asset",
      severity: asset.severity || "info",
      confidence: asset.confidence ?? 0.8
    });
  }

  addRoute(route = {}) {
    return this.addNode({
      ...route,
      type: "route",
      category: route.category || "route_exposure",
      severity: route.severity || "info",
      confidence: route.confidence ?? 0.8
    });
  }

  addEdge(from, to, relationship = "related_to", metadata = {}) {
    if (!from || !to || from === to) return null;

    const exists = this.edges.some(
      edge => edge.from === from && edge.to === to && edge.relationship === relationship
    );

    if (exists) return null;

    const edge = new EvidenceEdge(from, to, relationship, metadata);
    this.edges.push(edge);
    return edge;
  }

  autoLinkNode(node) {
    for (const existing of this.nodes.values()) {
      if (existing.id === node.id) continue;

      if (this.options.autoLinkByFile && node.file && existing.file === node.file) {
        this.addEdge(existing.id, node.id, "same_file", { file: node.file });
      }

      if (this.options.autoLinkByRule && node.ruleId && existing.ruleId === node.ruleId) {
        this.addEdge(existing.id, node.id, "same_rule", { ruleId: node.ruleId });
      }

      if (this.options.autoLinkByAsset) {
        const sharedAssets = node.assets.filter(asset => existing.assets.includes(asset));
        if (sharedAssets.length > 0) {
          this.addEdge(existing.id, node.id, "shared_asset", { assets: sharedAssets });
        }
      }
    }
  }

  getNode(id) {
    return this.nodes.get(id) || null;
  }

  getNodes() {
    return [...this.nodes.values()];
  }

  getEdges() {
    return this.edges;
  }

  getConnectedNodes(id) {
    const connectedIds = this.edges
      .filter(edge => edge.from === id || edge.to === id)
      .map(edge => (edge.from === id ? edge.to : edge.from));

    return connectedIds
      .map(nodeId => this.getNode(nodeId))
      .filter(Boolean);
  }

  getFindingsBySeverity(severity) {
    const target = normalizeSeverity(severity);
    return this.getNodes().filter(node => node.severity === target);
  }

  getFindingsByFile(file) {
    return this.getNodes().filter(node => node.file === file);
  }

  getFindingsByEngine(engine) {
    return this.getNodes().filter(node => node.engine === engine);
  }

  getHighestRiskNodes(limit = 10) {
    return this.getNodes()
      .sort((a, b) => b.getRiskScore() - a.getRiskScore())
      .slice(0, limit);
  }

  calculateGraphRiskScore() {
    const nodes = this.getNodes();

    if (nodes.length === 0) {
      return {
        score: 0,
        level: "none",
        totalNodes: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      };
    }

    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    let rawScore = 0;

    for (const node of nodes) {
      counts[node.severity] += 1;
      rawScore += node.getRiskScore();
    }

    const connectionMultiplier = 1 + Math.min(this.edges.length / 50, 1.5);
    const score = Math.min(1000, Math.round(rawScore * connectionMultiplier));

    let level = "low";
    if (score >= 750) level = "critical";
    else if (score >= 500) level = "high";
    else if (score >= 250) level = "medium";

    return {
      score,
      level,
      totalNodes: nodes.length,
      totalEdges: this.edges.length,
      ...counts
    };
  }

  findAttackChains(options = {}) {
    const maxDepth = options.maxDepth || this.options.maxAttackChainDepth;
    const chains = [];

    const highValueTypes = new Set([
      "secret",
      "credential",
      "private_key",
      "wallet",
      "database",
      "admin_route",
      "signing_flow",
      "critical_finding"
    ]);

    const startNodes = this.getNodes().filter(node =>
      node.type === "route" ||
      node.category.includes("exposure") ||
      node.attackSurface.includes("public") ||
      node.attackSurface.includes("web") ||
      node.attackSurface.includes("api")
    );

    const walk = (node, path, visited, depth) => {
      if (depth > maxDepth) return;

      const connected = this.getConnectedNodes(node.id);

      for (const next of connected) {
        if (visited.has(next.id)) continue;

        const nextPath = [...path, next];
        const nextVisited = new Set(visited);
        nextVisited.add(next.id);

        const isHighValue =
          highValueTypes.has(next.type) ||
          highValueTypes.has(next.category) ||
          next.severity === "critical" ||
          next.tags.some(tag => highValueTypes.has(tag));

        if (isHighValue && nextPath.length >= 2) {
          chains.push(this.scoreAttackChain(nextPath));
        }

        walk(next, nextPath, nextVisited, depth + 1);
      }
    };

    for (const start of startNodes) {
      walk(start, [start], new Set([start.id]), 1);
    }

    return chains
      .sort((a, b) => b.chainScore - a.chainScore)
      .slice(0, options.limit || 25);
  }

  scoreAttackChain(path = []) {
    const severitySum = path.reduce(
      (sum, node) => sum + (SEVERITY_WEIGHT[node.severity] || 1),
      0
    );

    const confidenceAvg =
      path.reduce((sum, node) => sum + node.confidence, 0) / Math.max(path.length, 1);

    const chainScore = Math.min(
      100,
      Math.round(severitySum * confidenceAvg * (1 + path.length / 5))
    );

    let exploitability = "low";
    if (chainScore >= 80) exploitability = "critical";
    else if (chainScore >= 60) exploitability = "high";
    else if (chainScore >= 35) exploitability = "medium";

    return {
      id: makeId("QS-CHAIN"),
      chainScore,
      exploitability,
      length: path.length,
      path: path.map(node => ({
        id: node.id,
        type: node.type,
        category: node.category,
        title: node.title,
        severity: node.severity,
        file: node.file,
        line: node.line
      })),
      summary: path.map(node => node.title).join(" → ")
    };
  }

  buildSummary() {
    const risk = this.calculateGraphRiskScore();
    const topNodes = this.getHighestRiskNodes(10).map(node => node.toJSON());
    const attackChains = this.findAttackChains({ limit: 10 });

    return {
      engine: "evidenceGraphEngine",
      generatedAt: new Date().toISOString(),
      risk,
      topNodes,
      attackChains,
      recommendations: this.generateRecommendations(risk, attackChains)
    };
  }

  generateRecommendations(risk, attackChains = []) {
    const recommendations = [];

    if (risk.critical > 0) {
      recommendations.push("Immediately review and remediate all critical evidence nodes.");
    }

    if (attackChains.length > 0) {
      recommendations.push("Prioritize findings that participate in attack chains.");
    }

    if (risk.high > 3) {
      recommendations.push("Create a high-risk remediation sprint focused on clustered findings.");
    }

    if (this.edges.length === 0 && this.nodes.size > 0) {
      recommendations.push("Add route, data-flow, and trust-boundary engines to improve evidence relationships.");
    }

    if (recommendations.length === 0) {
      recommendations.push("No urgent graph-level remediation detected. Continue monitoring.");
    }

    return recommendations;
  }

  exportGraph() {
    return {
      nodes: this.getNodes().map(node => node.toJSON()),
      edges: this.edges.map(edge => edge.toJSON()),
      summary: this.buildSummary()
    };
  }

  importFindings(findings = [], options = {}) {
    const engine = options.engine || "imported";

    for (const finding of findings) {
      this.addFinding({
        engine,
        ...finding
      });
    }

    return this.buildSummary();
  }

  reset() {
    this.nodes.clear();
    this.edges = [];
  }
}

export function createEvidenceGraph(options = {}) {
  return new EvidenceGraphEngine(options);
}

export function buildEvidenceGraphFromFindings(findings = [], options = {}) {
  const graph = new EvidenceGraphEngine(options);
  graph.importFindings(findings, options);
  return graph.exportGraph();
}

export default EvidenceGraphEngine;
