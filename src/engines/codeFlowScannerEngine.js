/**
 * Quantum Shield Trinity
 * Code Flow Scanner Engine
 *
 * Purpose:
 * Finds risky source -> sink flows in JavaScript/TypeScript-style repositories.
 *
 * This is a lightweight, dependency-free static analyzer.
 * It does not perform full AST analysis yet, but it gives Quantum Shield a real
 * data-flow intelligence layer for deep scans.
 *
 * Detects:
 * - user input sources
 * - dangerous sinks
 * - weak sanitization
 * - possible SSRF
 * - command injection risk
 * - path traversal risk
 * - HTML / XSS injection risk
 * - unsafe dynamic code execution
 * - weak crypto / signing flow exposure
 */

const DEFAULT_SOURCE_PATTERNS = [
  {
    id: "REQ_BODY",
    label: "Request Body",
    regex: /\b(req|request)\.body\b/g,
    risk: "User-controlled request body input"
  },
  {
    id: "REQ_QUERY",
    label: "Request Query",
    regex: /\b(req|request)\.query\b/g,
    risk: "User-controlled query string input"
  },
  {
    id: "REQ_PARAMS",
    label: "Request Params",
    regex: /\b(req|request)\.params\b/g,
    risk: "User-controlled route parameter input"
  },
  {
    id: "REQ_HEADERS",
    label: "Request Headers",
    regex: /\b(req|request)\.headers\b/g,
    risk: "User-controlled request header input"
  },
  {
    id: "URL_SEARCH_PARAMS",
    label: "URL Search Params",
    regex: /\bURLSearchParams\b|\bsearchParams\.get\s*\(/g,
    risk: "User-controlled URL parameter input"
  },
  {
    id: "LOCAL_STORAGE",
    label: "Local Storage",
    regex: /\blocalStorage\.getItem\s*\(/g,
    risk: "Browser-controlled local storage input"
  },
  {
    id: "PROCESS_ARGV",
    label: "Process Arguments",
    regex: /\bprocess\.argv\b/g,
    risk: "Command-line controlled input"
  },
  {
    id: "PROCESS_ENV",
    label: "Environment Variable",
    regex: /\bprocess\.env\b/g,
    risk: "Environment-controlled configuration input"
  },
  {
    id: "FILE_UPLOAD",
    label: "File Upload",
    regex: /\b(req|request)\.(file|files)\b|\bmulter\b|\bformidable\b/g,
    risk: "Uploaded file input"
  },
  {
    id: "WALLET_INPUT",
    label: "Wallet / Address Input",
    regex: /\b(wallet|address|privateKey|publicKey|signature|txHash|contractAddress)\b/gi,
    risk: "Blockchain or wallet-related user input"
  }
];

const DEFAULT_SINK_PATTERNS = [
  {
    id: "EVAL",
    label: "Dynamic Code Execution",
    regex: /\beval\s*\(|\bnew\s+Function\s*\(/g,
    severity: "critical",
    category: "code_execution",
    risk: "User input may reach dynamic code execution"
  },
  {
    id: "CHILD_PROCESS",
    label: "Child Process Execution",
    regex: /\bexec\s*\(|\bexecSync\s*\(|\bspawn\s*\(|\bspawnSync\s*\(|\bchild_process\b/g,
    severity: "critical",
    category: "command_injection",
    risk: "User input may reach OS command execution"
  },
  {
    id: "FETCH",
    label: "Outbound Network Request",
    regex: /\bfetch\s*\(|\baxios\.\w+\s*\(|\bhttp\.request\s*\(|\bhttps\.request\s*\(/g,
    severity: "high",
    category: "ssrf",
    risk: "User input may control outbound network request"
  },
  {
    id: "FS_READ",
    label: "Filesystem Read",
    regex: /\bfs\.readFileSync\s*\(|\bfs\.readFile\s*\(|\breadFileSync\s*\(|\breadFile\s*\(/g,
    severity: "high",
    category: "path_traversal",
    risk: "User input may control filesystem read path"
  },
  {
    id: "FS_WRITE",
    label: "Filesystem Write",
    regex: /\bfs\.writeFileSync\s*\(|\bfs\.writeFile\s*\(|\bwriteFileSync\s*\(|\bwriteFile\s*\(/g,
    severity: "high",
    category: "unsafe_file_write",
    risk: "User input may control filesystem write path"
  },
  {
    id: "HTML_INJECTION",
    label: "HTML Injection Sink",
    regex: /\binnerHTML\b|\bdangerouslySetInnerHTML\b|\bdocument\.write\s*\(|\.html\s*\(/g,
    severity: "high",
    category: "xss",
    risk: "User input may reach HTML rendering sink"
  },
  {
    id: "SQL_QUERY",
    label: "SQL Query Sink",
    regex: /\bquery\s*\(|\bexecute\s*\(|\braw\s*\(|\bknex\.raw\s*\(/g,
    severity: "high",
    category: "sql_injection",
    risk: "User input may reach database query execution"
  },
  {
    id: "REDIRECT",
    label: "Redirect Sink",
    regex: /\b(res|response)\.redirect\s*\(|\bwindow\.location\b|\blocation\.href\b/g,
    severity: "medium",
    category: "open_redirect",
    risk: "User input may control redirect destination"
  },
  {
    id: "CRYPTO_SIGN",
    label: "Signing / Private Key Sink",
    regex: /\.sign\s*\(|\bsignMessage\s*\(|\bsignTransaction\s*\(|\bprivateKey\b|\bwallet\.sign\b/gi,
    severity: "critical",
    category: "wallet_signing_flow",
    risk: "User input may influence signing or private-key flow"
  },
  {
    id: "CONTRACT_CALL",
    label: "Smart Contract Call Sink",
    regex: /\.send\s*\(|\.call\s*\(|\.estimateGas\s*\(|\.approve\s*\(|\.transferFrom\s*\(|\.safeTransferFrom\s*\(/g,
    severity: "high",
    category: "web3_contract_flow",
    risk: "User input may influence smart contract transaction flow"
  }
];

const SANITIZER_PATTERNS = [
  /\bvalidate\w*\s*\(/i,
  /\bsanitize\w*\s*\(/i,
  /\bescape\w*\s*\(/i,
  /\bencodeURIComponent\s*\(/i,
  /\bDOMPurify\b/i,
  /\bjoi\.|zod\.|yup\.|validator\./i,
  /\ballowlist\b|\bwhitelist\b|\bdenylist\b|\bblacklist\b/i,
  /\bNumber\s*\(|\bparseInt\s*\(|\bparseFloat\s*\(/i
];

const EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".vue",
  ".svelte"
]);

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

function cleanSnippet(snippet = "", max = 260) {
  return String(snippet).replace(/\s+/g, " ").trim().slice(0, max);
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

function hasNearbySanitizer(content, sourceIndex, sinkIndex) {
  const start = Math.max(0, Math.min(sourceIndex, sinkIndex) - 1200);
  const end = Math.min(content.length, Math.max(sourceIndex, sinkIndex) + 1200);
  const window = content.slice(start, end);

  return SANITIZER_PATTERNS.some(regex => regex.test(window));
}

function calculateDistanceScore(sourceIndex, sinkIndex, contentLength) {
  const distance = Math.abs(sinkIndex - sourceIndex);
  const normalized = Math.min(1, distance / Math.max(contentLength, 1));

  if (distance <= 500) return 1.0;
  if (distance <= 1500) return 0.85;
  if (distance <= 3500) return 0.7;
  return Math.max(0.35, 1 - normalized);
}

function severityToScore(severity) {
  switch (String(severity).toLowerCase()) {
    case "critical":
      return 10;
    case "high":
      return 7;
    case "medium":
      return 4;
    case "low":
      return 2;
    default:
      return 1;
  }
}

function scoreToSeverity(score) {
  if (score >= 8.5) return "critical";
  if (score >= 6.5) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 2.0) return "low";
  return "info";
}

function buildFinding({ filePath, content, source, sink, sanitized }) {
  const distanceScore = calculateDistanceScore(source.index, sink.index, content.length);
  const baseSeverityScore = severityToScore(sink.severity);
  const sanitizerPenalty = sanitized ? 2.0 : 0;
  const confidence = Math.max(0.35, Math.min(0.98, distanceScore - (sanitized ? 0.18 : 0)));
  const computedSeverity = scoreToSeverity(baseSeverityScore * distanceScore - sanitizerPenalty);

  const sourceLine = source.line;
  const sinkLine = sink.line;
  const line = sinkLine;
  const snippet = cleanSnippet(`${source.lineText} ... ${sink.lineText}`);

  return {
    id: `CODEFLOW-${sink.id}-${source.id}-${filePath}-${sourceLine}-${sinkLine}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
    type: "code_flow",
    category: sink.category,
    severity: computedSeverity,
    confidence,
    file: filePath,
    line,
    ruleId: `CODEFLOW_${source.id}_TO_${sink.id}`,
    title: `${source.label} may reach ${sink.label}`,
    description: `${source.risk}. ${sink.risk}.`,
    source: {
      id: source.id,
      label: source.label,
      line: sourceLine,
      match: source.match,
      snippet: cleanSnippet(source.lineText)
    },
    sink: {
      id: sink.id,
      label: sink.label,
      line: sinkLine,
      match: sink.match,
      snippet: cleanSnippet(sink.lineText)
    },
    sanitized,
    evidence: {
      snippet,
      matchedText: `${source.match} -> ${sink.match}`,
      source: "codeFlowScannerEngine"
    },
    attackSurface: inferAttackSurface(source, sink),
    assets: inferAssets(source, sink, filePath),
    recommendation: buildRecommendation(sink, sanitized),
    remediation: [buildRecommendation(sink, sanitized)],
    whyItMatters: buildWhyItMatters(source, sink),
    metadata: {
      sourceIndex: source.index,
      sinkIndex: sink.index,
      distance: Math.abs(source.index - sink.index),
      distanceScore,
      sanitizerDetected: sanitized
    }
  };
}

function inferAttackSurface(source, sink) {
  const surfaces = new Set();

  if (source.id.startsWith("REQ_")) surfaces.add("api");
  if (source.id === "LOCAL_STORAGE") surfaces.add("browser");
  if (source.id === "PROCESS_ARGV") surfaces.add("cli");
  if (sink.id === "FETCH") surfaces.add("network");
  if (sink.id === "CONTRACT_CALL" || sink.id === "CRYPTO_SIGN") surfaces.add("web3");
  if (sink.id.includes("FS_")) surfaces.add("filesystem");

  return [...surfaces];
}

function inferAssets(source, sink, filePath) {
  const assets = new Set([filePath]);

  if (sink.id === "CRYPTO_SIGN") assets.add("private_key_or_wallet");
  if (sink.id === "CONTRACT_CALL") assets.add("smart_contract");
  if (sink.id === "SQL_QUERY") assets.add("database");
  if (sink.id === "FETCH") assets.add("network_endpoint");
  if (sink.id.includes("FS_")) assets.add("filesystem");

  return [...assets];
}

function buildWhyItMatters(source, sink) {
  return `${source.label} is potentially attacker-controlled. If it reaches ${sink.label} without strong validation, it can create ${sink.category.replace(/_/g, " ")} risk.`;
}

function buildRecommendation(sink, sanitized) {
  const prefix = sanitized
    ? "A sanitizer-like pattern was detected, but manual verification is still recommended."
    : "Add strict validation, sanitization, and allowlisting before this sink.";

  const sinkAdvice = {
    EVAL: "Avoid eval/new Function entirely. Replace dynamic execution with explicit safe logic.",
    CHILD_PROCESS: "Avoid shell interpolation. Use argument arrays, allowlisted commands, and no user-controlled shell strings.",
    FETCH: "Add URL allowlists, block private IP ranges, enforce timeouts, and prevent user-controlled protocols.",
    FS_READ: "Normalize paths, enforce a safe base directory, and block ../ traversal.",
    FS_WRITE: "Normalize paths, enforce a safe output directory, and prevent overwriting sensitive files.",
    HTML_INJECTION: "Use textContent or a vetted sanitizer like DOMPurify before rendering HTML.",
    SQL_QUERY: "Use parameterized queries or ORM bindings. Never concatenate user input into SQL.",
    REDIRECT: "Use same-origin or allowlisted redirect destinations only.",
    CRYPTO_SIGN: "Never let untrusted input directly control private-key or signing operations.",
    CONTRACT_CALL: "Validate contract address, method, chain ID, and value before any transaction call."
  };

  return `${prefix} ${sinkAdvice[sink.id] || "Review this flow and enforce trust-boundary validation."}`;
}

export function codeFlowScannerEngine(files = [], options = {}) {
  const sourcePatterns = options.sourcePatterns || DEFAULT_SOURCE_PATTERNS;
  const sinkPatterns = options.sinkPatterns || DEFAULT_SINK_PATTERNS;
  const maxPairDistance = options.maxPairDistance || 6000;

  const findings = [];
  const scannedFiles = [];
  let totalSources = 0;
  let totalSinks = 0;

  for (const file of files) {
    const filePath = getFilePath(file);
    const content = getFileContent(file);
    const ext = getExtension(filePath);

    if (!content || !EXTENSIONS.has(ext)) continue;

    const sources = collectMatches(content, sourcePatterns);
    const sinks = collectMatches(content, sinkPatterns);

    totalSources += sources.length;
    totalSinks += sinks.length;

    if (sources.length || sinks.length) {
      scannedFiles.push({
        file: filePath,
        sources: sources.length,
        sinks: sinks.length
      });
    }

    for (const source of sources) {
      for (const sink of sinks) {
        const distance = Math.abs(sink.index - source.index);

        if (distance > maxPairDistance) continue;

        const sanitized = hasNearbySanitizer(content, source.index, sink.index);

        findings.push(buildFinding({
          filePath,
          content,
          source,
          sink,
          sanitized
        }));
      }
    }
  }

  const deduped = dedupeFindings(findings);
  const summary = summarizeFindings(deduped);

  return {
    engine: "codeFlowScannerEngine",
    scannedFiles: scannedFiles.length,
    scannedFileDetails: scannedFiles,
    totalSources,
    totalSinks,
    totalFlows: deduped.length,
    criticalFlows: summary.critical,
    highFlows: summary.high,
    mediumFlows: summary.medium,
    lowFlows: summary.low,
    riskLevel: summary.riskLevel,
    score: summary.score,
    findings: deduped,
    recommendations: buildTopRecommendations(deduped)
  };
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

  return output.sort((a, b) => severityToScore(b.severity) - severityToScore(a.severity));
}

function summarizeFindings(findings = []) {
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
    counts.critical * 25 +
    counts.high * 15 +
    counts.medium * 7 +
    counts.low * 3;

  const score = Math.max(0, Math.min(100, 100 - weighted));

  let riskLevel = "LOW";
  if (counts.critical > 0 || weighted >= 75) riskLevel = "CRITICAL";
  else if (counts.high > 2 || weighted >= 45) riskLevel = "HIGH";
  else if (counts.high > 0 || counts.medium > 3 || weighted >= 20) riskLevel = "MEDIUM";

  return {
    ...counts,
    weighted,
    score,
    riskLevel
  };
}

function buildTopRecommendations(findings = []) {
  const recs = [];

  const categories = new Map();

  for (const finding of findings) {
    if (!categories.has(finding.category)) {
      categories.set(finding.category, finding);
    }
  }

  for (const finding of categories.values()) {
    recs.push({
      category: finding.category,
      severity: finding.severity,
      recommendation: finding.recommendation
    });
  }

  if (recs.length === 0) {
    recs.push({
      category: "code_flow",
      severity: "info",
      recommendation: "No risky source-to-sink flows detected by the lightweight scanner."
    });
  }

  return recs.slice(0, 10);
}

export default codeFlowScannerEngine;
