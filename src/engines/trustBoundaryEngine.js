/**
 * Quantum Shield Trinity
 * Trust Boundary Engine
 *
 * Purpose:
 * Detects risky trust-boundary crossings across API, browser, filesystem,
 * network, CI/CD, secrets, wallet/signing, and smart-contract flows.
 *
 * This engine works best after:
 * - codeFlowScannerEngine
 * - routeExposureEngine
 * - evidenceGraphEngine
 *
 * It accepts either:
 *   trustBoundaryEngine(scanResult.files, report)
 * or:
 *   trustBoundaryEngine(files, { codeFlowReport, routeExposureReport, ... })
 */

const BOUNDARY_TYPES = {
  PUBLIC_TO_INTERNAL: "public_to_internal",
  USER_INPUT_TO_FILESYSTEM: "user_input_to_filesystem",
  USER_INPUT_TO_NETWORK: "user_input_to_network",
  USER_INPUT_TO_DATABASE: "user_input_to_database",
  USER_INPUT_TO_EXECUTION: "user_input_to_execution",
  USER_INPUT_TO_SIGNING: "user_input_to_signing",
  FRONTEND_TO_BACKEND: "frontend_to_backend",
  BACKEND_TO_BLOCKCHAIN: "backend_to_blockchain",
  SECRET_TO_PUBLIC_SURFACE: "secret_to_public_surface",
  CI_TO_DEPLOYMENT: "ci_to_deployment",
  REPO_SCANNER_TO_OUTPUT: "repo_scanner_to_output",
  CONFIG_TO_RUNTIME: "config_to_runtime"
};

const EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yml",
  ".yaml",
  ".env",
  ".toml",
  ".config"
]);

const PUBLIC_INPUT_PATTERNS = [
  {
    id: "REQ_BODY",
    label: "Request Body",
    regex: /\b(req|request)\.body\b/g
  },
  {
    id: "REQ_QUERY",
    label: "Request Query",
    regex: /\b(req|request)\.query\b/g
  },
  {
    id: "REQ_PARAMS",
    label: "Request Params",
    regex: /\b(req|request)\.params\b/g
  },
  {
    id: "REQ_HEADERS",
    label: "Request Headers",
    regex: /\b(req|request)\.headers\b/g
  },
  {
    id: "FORM_DATA",
    label: "Form Data",
    regex: /\bFormData\b|\.get\s*\(\s*["'`][a-zA-Z0-9_-]+["'`]\s*\)/g
  },
  {
    id: "URL_PARAMS",
    label: "URL Params",
    regex: /\bURLSearchParams\b|\bsearchParams\.get\s*\(/g
  },
  {
    id: "LOCAL_STORAGE",
    label: "Local Storage",
    regex: /\blocalStorage\.getItem\s*\(/g
  }
];

const TRUSTED_CONTROL_PATTERNS = [
  /\bauthenticate\b/i,
  /\bauthorize\b/i,
  /\brequireAuth\b/i,
  /\bverifyToken\b/i,
  /\bjwt\.verify\b/i,
  /\bpassport\.authenticate\b/i,
  /\bwithAuth\b/i,
  /\badminOnly\b/i,
  /\brequireRole\b/i,
  /\bvalidate\w*\s*\(/i,
  /\bsanitize\w*\s*\(/i,
  /\bzod\b/i,
  /\bjoi\b/i,
  /\byup\b/i,
  /\bsafeParse\b/i,
  /\ballowlist\b/i,
  /\bwhitelist\b/i,
  /\bdenylist\b/i
];

const SENSITIVE_SINK_PATTERNS = [
  {
    id: "FILESYSTEM_READ",
    boundaryType: BOUNDARY_TYPES.USER_INPUT_TO_FILESYSTEM,
    label: "Filesystem Read",
    regex: /\bfs\.readFileSync\s*\(|\bfs\.readFile\s*\(|\breadFileSync\s*\(|\breadFile\s*\(/g,
    severityBase: 7
  },
  {
    id: "FILESYSTEM_WRITE",
    boundaryType: BOUNDARY_TYPES.USER_INPUT_TO_FILESYSTEM,
    label: "Filesystem Write",
    regex: /\bfs\.writeFileSync\s*\(|\bfs\.writeFile\s*\(|\bwriteFileSync\s*\(|\bwriteFile\s*\(/g,
    severityBase: 7
  },
  {
    id: "NETWORK_REQUEST",
    boundaryType: BOUNDARY_TYPES.USER_INPUT_TO_NETWORK,
    label: "Outbound Network Request",
    regex: /\bfetch\s*\(|\baxios\.\w+\s*\(|\bhttp\.request\s*\(|\bhttps\.request\s*\(/g,
    severityBase: 7
  },
  {
    id: "DATABASE_QUERY",
    boundaryType: BOUNDARY_TYPES.USER_INPUT_TO_DATABASE,
    label: "Database Query",
    regex: /\bquery\s*\(|\bexecute\s*\(|\braw\s*\(|\bknex\.raw\s*\(|\bprisma\./g,
    severityBase: 7
  },
  {
    id: "COMMAND_EXEC",
    boundaryType: BOUNDARY_TYPES.USER_INPUT_TO_EXECUTION,
    label: "Command Execution",
    regex: /\bexec\s*\(|\bexecSync\s*\(|\bspawn\s*\(|\bspawnSync\s*\(|\bchild_process\b/g,
    severityBase: 10
  },
  {
    id: "WALLET_SIGNING",
    boundaryType: BOUNDARY_TYPES.USER_INPUT_TO_SIGNING,
    label: "Wallet / Signing Flow",
    regex: /\.sign\s*\(|\bsignMessage\s*\(|\bsignTransaction\s*\(|\bwallet\.sign\b|\bprivateKey\b/gi,
    severityBase: 10
  },
  {
    id: "CONTRACT_CALL",
    boundaryType: BOUNDARY_TYPES.BACKEND_TO_BLOCKCHAIN,
    label: "Smart Contract Call",
    regex: /\.approve\s*\(|\.transferFrom\s*\(|\.send\s*\(|\.call\s*\(|contract\./g,
    severityBase: 8
  },
  {
    id: "HTML_RENDER",
    boundaryType: BOUNDARY_TYPES.FRONTEND_TO_BACKEND,
    label: "HTML Rendering Sink",
    regex: /\binnerHTML\b|\bdangerouslySetInnerHTML\b|\bdocument\.write\s*\(/g,
    severityBase: 7
  }
];

const SECRET_PATTERNS = [
  /\bprocess\.env\b/g,
  /\bAPI_KEY\b|\bSECRET\b|\bTOKEN\b|\bPRIVATE_KEY\b|\bMNEMONIC\b|\bSEED_PHRASE\b/gi,
  /sk-[a-zA-Z0-9_-]{12,}/g,
  /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g
];

const CICD_DEPLOY_PATTERNS = [
  /\bpermissions\s*:\s*write-all\b/i,
  /\bcontents\s*:\s*write\b/i,
  /\bid-token\s*:\s*write\b/i,
  /\bnpm publish\b/i,
  /\bdocker push\b/i,
  /\bdeploy\b/i,
  /\bvercel\b|\bnetlify\b|\bflyctl\b|\bkubectl\b/i
];

function getFilePath(file = {}) {
  return file.path || file.file || file.name || file.filename || "unknown";
}

function getFileContent(file = {}) {
  return file.content || file.text || file.source || "";
}

function getExtension(filePath = "") {
  const idx = filePath.lastIndexOf(".");
  return idx >= 0 ? filePath.slice(idx).toLowerCase() : "";
}

function getLineNumber(content, index) {
  return content.slice(0, index).split("\n").length;
}

function getLineText(content, lineNumber) {
  return content.split("\n")[lineNumber - 1] || "";
}

function cleanSnippet(value = "", max = 260) {
  return String(value).replace(/\s+/g, " ").trim().slice(0, max);
}

function resetRegex(regex) {
  regex.lastIndex = 0;
}

function collectMatches(content, patterns) {
  const matches = [];

  for (const pattern of patterns) {
    resetRegex(pattern.regex);

    let match;
    while ((match = pattern.regex.exec(content)) !== null) {
      const line = getLineNumber(content, match.index);

      matches.push({
        ...pattern,
        match: match[0],
        index: match.index,
        line,
        lineText: getLineText(content, line)
      });

      if (match.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++;
      }
    }
  }

  return matches.sort((a, b) => a.index - b.index);
}

function hasTrustControlNearby(content, leftIndex, rightIndex) {
  const start = Math.max(0, Math.min(leftIndex, rightIndex) - 1400);
  const end = Math.min(content.length, Math.max(leftIndex, rightIndex) + 1400);
  const window = content.slice(start, end);

  return TRUSTED_CONTROL_PATTERNS.some(regex => regex.test(window));
}

function scoreToSeverity(score) {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 2) return "low";
  return "info";
}

function confidenceFromDistance(sourceIndex, sinkIndex, hasTrustControl) {
  const distance = Math.abs(sinkIndex - sourceIndex);
  let confidence = 0.92;

  if (distance > 500) confidence -= 0.08;
  if (distance > 1500) confidence -= 0.12;
  if (distance > 3500) confidence -= 0.15;
  if (hasTrustControl) confidence -= 0.2;

  return Math.max(0.35, Math.min(0.98, confidence));
}

function buildBoundaryFinding({ filePath, content, source, sink }) {
  const hasTrustControl = hasTrustControlNearby(content, source.index, sink.index);
  const score = Math.max(1, sink.severityBase - (hasTrustControl ? 2 : 0));
  const severity = scoreToSeverity(score);
  const confidence = confidenceFromDistance(source.index, sink.index, hasTrustControl);

  const line = sink.line;
  const title = `${source.label} crosses into ${sink.label}`;
  const snippet = cleanSnippet(`${source.lineText} ... ${sink.lineText}`);

  return {
    id: `BOUNDARY-${sink.id}-${source.id}-${filePath}-${source.line}-${sink.line}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
    type: "trust_boundary",
    category: sink.boundaryType,
    severity,
    confidence,
    file: filePath,
    line,
    ruleId: `TRUST_BOUNDARY_${source.id}_TO_${sink.id}`,
    title,
    description: `${source.label} appears to cross a trust boundary into ${sink.label}.`,
    source: {
      id: source.id,
      label: source.label,
      line: source.line,
      snippet: cleanSnippet(source.lineText)
    },
    sink: {
      id: sink.id,
      label: sink.label,
      line: sink.line,
      snippet: cleanSnippet(sink.lineText)
    },
    trustControlDetected: hasTrustControl,
    evidence: {
      snippet,
      matchedText: `${source.match} -> ${sink.match}`,
      source: "trustBoundaryEngine"
    },
    attackSurface: inferAttackSurface(sink),
    assets: inferAssets(sink, filePath),
    recommendation: buildRecommendation(sink, hasTrustControl),
    remediation: [buildRecommendation(sink, hasTrustControl)],
    whyItMatters: buildWhyItMatters(source, sink, hasTrustControl),
    metadata: {
      sourceIndex: source.index,
      sinkIndex: sink.index,
      distance: Math.abs(source.index - sink.index),
      trustControlDetected: hasTrustControl
    }
  };
}

function inferAttackSurface(sink) {
  const surface = new Set();

  if (sink.boundaryType.includes("user_input")) surface.add("api");
  if (sink.boundaryType.includes("network")) surface.add("network");
  if (sink.boundaryType.includes("filesystem")) surface.add("filesystem");
  if (sink.boundaryType.includes("signing") || sink.boundaryType.includes("blockchain")) surface.add("web3");
  if (sink.boundaryType.includes("execution")) surface.add("runtime");

  return [...surface];
}

function inferAssets(sink, filePath) {
  const assets = new Set([filePath]);

  if (sink.id.includes("FILESYSTEM")) assets.add("filesystem");
  if (sink.id === "NETWORK_REQUEST") assets.add("network_endpoint");
  if (sink.id === "DATABASE_QUERY") assets.add("database");
  if (sink.id === "COMMAND_EXEC") assets.add("host_runtime");
  if (sink.id === "WALLET_SIGNING") assets.add("wallet_or_private_key");
  if (sink.id === "CONTRACT_CALL") assets.add("smart_contract");

  return [...assets];
}

function buildWhyItMatters(source, sink, hasTrustControl) {
  const controlText = hasTrustControl
    ? "A trust-control pattern was detected nearby, but this crossing still deserves review."
    : "No strong trust-control pattern was detected nearby.";

  return `${source.label} is potentially untrusted. If it reaches ${sink.label}, the application may expose ${sink.boundaryType.replace(/_/g, " ")} risk. ${controlText}`;
}

function buildRecommendation(sink, hasTrustControl) {
  const prefix = hasTrustControl
    ? "Verify the nearby authorization/validation control is complete and cannot be bypassed."
    : "Add explicit validation, authorization, and allowlisting before this boundary.";

  const advice = {
    FILESYSTEM_READ: "Enforce a safe base directory and block path traversal.",
    FILESYSTEM_WRITE: "Prevent user-controlled output paths and block overwrite of sensitive files.",
    NETWORK_REQUEST: "Use URL allowlists, block private IP ranges, validate protocol, and enforce timeouts.",
    DATABASE_QUERY: "Use parameterized queries and schema validation before database access.",
    COMMAND_EXEC: "Remove shell execution or isolate it behind strict allowlisted commands and arguments.",
    WALLET_SIGNING: "Require explicit user authorization, chain ID validation, transaction simulation, and signing limits.",
    CONTRACT_CALL: "Validate contract address, method, chain, token approvals, and transaction value.",
    HTML_RENDER: "Use safe rendering APIs or a vetted sanitizer before injecting HTML."
  };

  return `${prefix} ${advice[sink.id] || "Review this trust boundary and document its controls."}`;
}

function buildSecretToPublicFindings(filePath, content) {
  const findings = [];
  const hasSecret = SECRET_PATTERNS.some(regex => {
    regex.lastIndex = 0;
    return regex.test(content);
  });

  if (!hasSecret) return findings;

  const hasPublicSurface =
    /\bexport\b|\bapp\.(get|post|put|patch|delete)\b|\brouter\.(get|post|put|patch|delete)\b|\breturn\s+Response\b|\bres\.json\b|\bres\.send\b/i.test(content);

  if (!hasPublicSurface) return findings;

  const firstSecretIndex = SECRET_PATTERNS.reduce((best, regex) => {
    regex.lastIndex = 0;
    const match = regex.exec(content);
    if (!match) return best;
    return best === -1 ? match.index : Math.min(best, match.index);
  }, -1);

  const line = firstSecretIndex >= 0 ? getLineNumber(content, firstSecretIndex) : 1;

  findings.push({
    id: `BOUNDARY-SECRET-PUBLIC-${filePath}-${line}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
    type: "trust_boundary",
    category: BOUNDARY_TYPES.SECRET_TO_PUBLIC_SURFACE,
    severity: "high",
    confidence: 0.82,
    file: filePath,
    line,
    ruleId: "TRUST_BOUNDARY_SECRET_TO_PUBLIC_SURFACE",
    title: "Secret/config access appears near public output surface",
    description: "Secret or environment access appears in a file that also exposes public route/output behavior.",
    evidence: {
      snippet: cleanSnippet(getLineText(content, line)),
      matchedText: "secret/config + public output",
      source: "trustBoundaryEngine"
    },
    attackSurface: ["api", "web"],
    assets: [filePath, "secret_or_environment"],
    recommendation: "Ensure secrets are never returned, logged, serialized, or exposed through public route handlers.",
    remediation: ["Separate secret access from public response code and add tests that prevent secret leakage."],
    whyItMatters: "Secret material crossing toward public output can create credential disclosure or sensitive configuration exposure.",
    metadata: {
      hasSecret,
      hasPublicSurface
    }
  });

  return findings;
}

function buildCiFindings(filePath, content) {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();

  if (!normalized.includes(".github/workflows") && !normalized.endsWith(".yml") && !normalized.endsWith(".yaml")) {
    return [];
  }

  const findings = [];

  for (const pattern of CICD_DEPLOY_PATTERNS) {
    pattern.lastIndex = 0;
    const match = pattern.exec(content);

    if (!match) continue;

    const line = getLineNumber(content, match.index);

    findings.push({
      id: `BOUNDARY-CI-DEPLOY-${filePath}-${line}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
      type: "trust_boundary",
      category: BOUNDARY_TYPES.CI_TO_DEPLOYMENT,
      severity: /write-all|npm publish|docker push|kubectl/i.test(match[0]) ? "high" : "medium",
      confidence: 0.84,
      file: filePath,
      line,
      ruleId: "TRUST_BOUNDARY_CI_TO_DEPLOYMENT",
      title: "CI/CD workflow crosses into deployment or write-capable permission",
      description: "A CI/CD workflow appears to have deployment, publishing, or broad write capability.",
      evidence: {
        snippet: cleanSnippet(getLineText(content, line)),
        matchedText: match[0],
        source: "trustBoundaryEngine"
      },
      attackSurface: ["ci_cd", "supply_chain"],
      assets: [filePath, "deployment_pipeline"],
      recommendation: "Pin workflow permissions to least privilege, protect deployment secrets, and require review for deploy/publish jobs.",
      remediation: ["Use least-privilege GitHub Actions permissions and protected environments."],
      whyItMatters: "CI/CD is a high-value boundary. A compromise here can become a supply-chain or production deployment compromise.",
      metadata: {
        matchedPattern: match[0]
      }
    });
  }

  return findings;
}

function scanFileForBoundaries(file) {
  const filePath = getFilePath(file);
  const content = getFileContent(file);
  const ext = getExtension(filePath);

  if (!content || (!EXTENSIONS.has(ext) && !filePath.includes(".env"))) return [];

  const findings = [];

  const sources = collectMatches(content, PUBLIC_INPUT_PATTERNS);
  const sinks = collectMatches(content, SENSITIVE_SINK_PATTERNS);

  for (const source of sources) {
    for (const sink of sinks) {
      const distance = Math.abs(sink.index - source.index);
      if (distance > 7000) continue;

      findings.push(buildBoundaryFinding({
        filePath,
        content,
        source,
        sink
      }));
    }
  }

  findings.push(...buildSecretToPublicFindings(filePath, content));
  findings.push(...buildCiFindings(filePath, content));

  return findings;
}

function dedupeFindings(findings = []) {
  const seen = new Set();
  const output = [];

  for (const finding of findings) {
    const key = `${finding.file}:${finding.line}:${finding.ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(finding);
  }

  return output.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
}

function severityRank(severity) {
  switch (String(severity).toLowerCase()) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

function summarize(findings = []) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const finding of findings) {
    const severity = String(finding.severity || "info").toLowerCase();
    counts[severity] = (counts[severity] || 0) + 1;
  }

  const weighted =
    counts.critical * 30 +
    counts.high * 16 +
    counts.medium * 8 +
    counts.low * 3;

  const score = Math.max(0, Math.min(100, 100 - weighted));

  let riskLevel = "LOW";
  if (counts.critical > 0 || weighted >= 85) riskLevel = "CRITICAL";
  else if (counts.high > 1 || weighted >= 50) riskLevel = "HIGH";
  else if (counts.high > 0 || counts.medium > 2 || weighted >= 22) riskLevel = "MEDIUM";

  return {
    ...counts,
    weighted,
    score,
    riskLevel
  };
}

function importCodeFlowBoundaries(codeFlowReport = {}) {
  const findings = [];

  for (const item of codeFlowReport.findings || []) {
    const category = item.category || "code_flow_boundary";

    findings.push({
      id: `BOUNDARY-FROM-CODEFLOW-${item.id}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
      type: "trust_boundary",
      category,
      severity: item.severity || "medium",
      confidence: Math.min(0.95, item.confidence ?? 0.75),
      file: item.file,
      line: item.line,
      ruleId: `TRUST_BOUNDARY_FROM_${item.ruleId || "CODEFLOW"}`,
      title: `Code flow trust boundary: ${item.title}`,
      description: item.description,
      source: item.source,
      sink: item.sink,
      trustControlDetected: item.sanitized,
      evidence: item.evidence,
      attackSurface: item.attackSurface || [],
      assets: item.assets || [],
      recommendation: item.recommendation,
      remediation: item.remediation || [item.recommendation].filter(Boolean),
      whyItMatters: item.whyItMatters,
      metadata: {
        importedFrom: "codeFlowScannerEngine",
        originalFinding: item
      }
    });
  }

  return findings;
}

function importRouteBoundaries(routeExposureReport = {}) {
  const findings = [];

  for (const item of routeExposureReport.findings || []) {
    if (item.hasAuth && item.hasValidation && item.severity !== "critical") continue;

    findings.push({
      id: `BOUNDARY-FROM-ROUTE-${item.id}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
      type: "trust_boundary",
      category: BOUNDARY_TYPES.PUBLIC_TO_INTERNAL,
      severity: item.severity || "medium",
      confidence: Math.min(0.95, item.confidence ?? 0.75),
      file: item.file,
      line: item.line,
      ruleId: "TRUST_BOUNDARY_PUBLIC_ROUTE_TO_INTERNAL",
      title: `Public route trust boundary: ${item.method} ${item.path}`,
      description: item.description,
      evidence: item.evidence,
      attackSurface: item.attackSurface || ["api", "web"],
      assets: item.assets || [item.path, item.file].filter(Boolean),
      recommendation: item.recommendation,
      remediation: item.remediation || [item.recommendation].filter(Boolean),
      whyItMatters: item.whyItMatters,
      metadata: {
        importedFrom: "routeExposureEngine",
        originalFinding: item
      }
    });
  }

  return findings;
}

function buildRecommendations(findings = []) {
  const recommendations = [];

  const critical = findings.find(item => item.severity === "critical");
  if (critical) {
    recommendations.push({
      severity: "critical",
      recommendation: "Immediately review critical trust-boundary crossings and add explicit validation/authorization controls."
    });
  }

  const signing = findings.find(item => item.category === BOUNDARY_TYPES.USER_INPUT_TO_SIGNING);
  if (signing) {
    recommendations.push({
      severity: "critical",
      recommendation: "Protect wallet/private-key signing paths with strict authorization, chain validation, and transaction simulation."
    });
  }

  const execution = findings.find(item => item.category === BOUNDARY_TYPES.USER_INPUT_TO_EXECUTION);
  if (execution) {
    recommendations.push({
      severity: "critical",
      recommendation: "Remove or isolate command execution reachable from public or user-controlled input."
    });
  }

  const ci = findings.find(item => item.category === BOUNDARY_TYPES.CI_TO_DEPLOYMENT);
  if (ci) {
    recommendations.push({
      severity: "high",
      recommendation: "Lock down CI/CD permissions, deployment secrets, and production publishing workflows."
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      severity: "info",
      recommendation: "No major trust-boundary risks detected by the lightweight scanner."
    });
  }

  return recommendations.slice(0, 10);
}

export function trustBoundaryEngine(files = [], context = {}) {
  const findings = [];

  for (const file of files) {
    findings.push(...scanFileForBoundaries(file));
  }

  findings.push(...importCodeFlowBoundaries(context.codeFlowReport));
  findings.push(...importRouteBoundaries(context.routeExposureReport));

  const deduped = dedupeFindings(findings);
  const summary = summarize(deduped);

  return {
    engine: "trustBoundaryEngine",
    totalTrustBoundaryFindings: deduped.length,
    criticalTrustBoundaries: summary.critical,
    highTrustBoundaries: summary.high,
    mediumTrustBoundaries: summary.medium,
    lowTrustBoundaries: summary.low,
    trustBoundaryScore: summary.score,
    trustBoundaryRiskLevel: summary.riskLevel,
    findings: deduped,
    recommendations: buildRecommendations(deduped)
  };
}

export default trustBoundaryEngine;
