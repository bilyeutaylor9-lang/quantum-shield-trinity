// src/engines/routeExposureEngine.js

/**
 * Quantum Shield Trinity
 * Route Exposure Engine
 *
 * Purpose:
 * Discovers exposed API / web routes and grades them by security posture.
 *
 * This engine is dependency-free and framework-aware.
 *
 * Detects route patterns from:
 * - Express
 * - Router instances
 * - Next.js style API handlers
 * - Fastify
 * - Hono-like route declarations
 * - Fetch/event handlers
 * - generic method/path strings
 *
 * Flags:
 * - public admin routes
 * - missing auth-like middleware
 * - risky HTTP methods
 * - wallet/signing routes
 * - upload routes
 * - webhook routes
 * - debug/internal routes
 * - route + secret / env / filesystem / network access combinations
 */

const ROUTE_PATTERNS = [
  {
    framework: "express",
    regex: /\b(?:app|router)\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/g
  },
  {
    framework: "fastify",
    regex: /\bfastify\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/g
  },
  {
    framework: "hono",
    regex: /\b(?:app|route)\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/g
  },
  {
    framework: "route_object",
    regex: /\bmethod\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE|ALL)['"`][\s\S]{0,180}?\bpath\s*:\s*['"`]([^'"`]+)['"`]/g
  },
  {
    framework: "generic_route",
    regex: /\b(GET|POST|PUT|PATCH|DELETE)\s+([\/][a-zA-Z0-9_/:.?=&-]+)/g
  }
];

const EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs"
]);

const AUTH_PATTERNS = [
  /\bauthenticate\b/i,
  /\bauthorize\b/i,
  /\brequireAuth\b/i,
  /\bisAuthenticated\b/i,
  /\bverifyToken\b/i,
  /\bcheckAuth\b/i,
  /\bpassport\.authenticate\b/i,
  /\bjwt\.verify\b/i,
  /\bsession\b/i,
  /\bclerkMiddleware\b/i,
  /\bwithAuth\b/i,
  /\bprotect\w*\b/i,
  /\badminOnly\b/i,
  /\brequireRole\b/i,
  /\brole\b/i
];

const VALIDATION_PATTERNS = [
  /\bvalidate\w*\s*\(/i,
  /\bsanitize\w*\s*\(/i,
  /\bzod\b/i,
  /\bjoi\b/i,
  /\byup\b/i,
  /\bvalidator\./i,
  /\bschema\.parse\b/i,
  /\bsafeParse\b/i
];

const RISKY_CONTEXT_PATTERNS = [
  {
    id: "ENV_ACCESS",
    label: "Environment / Secrets Access",
    regex: /\bprocess\.env\b|API_KEY|SECRET|TOKEN|PRIVATE_KEY|MNEMONIC/gi,
    severityBoost: 2
  },
  {
    id: "FILE_ACCESS",
    label: "Filesystem Access",
    regex: /\bfs\.|readFile|writeFile|createReadStream|createWriteStream/gi,
    severityBoost: 2
  },
  {
    id: "NETWORK_ACCESS",
    label: "Outbound Network Access",
    regex: /\bfetch\s*\(|axios\.|http\.request|https\.request/gi,
    severityBoost: 2
  },
  {
    id: "COMMAND_EXEC",
    label: "Command Execution",
    regex: /\bexec\s*\(|execSync|spawn\s*\(|child_process/gi,
    severityBoost: 4
  },
  {
    id: "DATABASE_ACCESS",
    label: "Database Access",
    regex: /\.query\s*\(|\.execute\s*\(|prisma\.|mongoose\.|sequelize\.|knex\./gi,
    severityBoost: 2
  },
  {
    id: "WALLET_SIGNING",
    label: "Wallet / Signing Access",
    regex: /privateKey|signMessage|signTransaction|wallet\.sign|\.sign\s*\(/gi,
    severityBoost: 4
  },
  {
    id: "CONTRACT_CALL",
    label: "Smart Contract Call",
    regex: /\.approve\s*\(|\.transferFrom\s*\(|\.send\s*\(|\.call\s*\(|contract\./gi,
    severityBoost: 3
  }
];

const SENSITIVE_PATH_HINTS = [
  { regex: /admin|root|superuser/i, label: "admin_route", boost: 4 },
  { regex: /wallet|sign|private|key|seed|mnemonic/i, label: "wallet_or_key_route", boost: 5 },
  { regex: /upload|file|import|export/i, label: "file_route", boost: 3 },
  { regex: /webhook|callback/i, label: "webhook_route", boost: 3 },
  { regex: /debug|internal|test|dev/i, label: "debug_or_internal_route", boost: 4 },
  { regex: /user|account|profile|email|phone|pii/i, label: "user_data_route", boost: 3 },
  { regex: /payment|billing|invoice|checkout/i, label: "payment_route", boost: 4 },
  { regex: /scan|repo|url|fetch|proxy/i, label: "scanner_or_fetch_route", boost: 4 }
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

function getWindow(content, index, before = 1200, after = 1800) {
  return content.slice(Math.max(0, index - before), Math.min(content.length, index + after));
}

function detectAuth(window) {
  return AUTH_PATTERNS.some(regex => regex.test(window));
}

function detectValidation(window) {
  return VALIDATION_PATTERNS.some(regex => regex.test(window));
}

function detectRiskyContext(window) {
  const context = [];

  for (const item of RISKY_CONTEXT_PATTERNS) {
    item.regex.lastIndex = 0;
    if (item.regex.test(window)) {
      context.push({
        id: item.id,
        label: item.label,
        severityBoost: item.severityBoost
      });
    }
  }

  return context;
}

function classifyPath(path) {
  const tags = [];
  let boost = 0;

  for (const hint of SENSITIVE_PATH_HINTS) {
    if (hint.regex.test(path)) {
      tags.push(hint.label);
      boost += hint.boost;
    }
  }

  return { tags, boost };
}

function methodRisk(method) {
  const m = String(method).toUpperCase();

  if (["POST", "PUT", "PATCH", "DELETE", "ALL"].includes(m)) return 3;
  return 1;
}

function scoreRoute({ method, path, hasAuth, hasValidation, riskyContext }) {
  const classified = classifyPath(path);

  let score = 0;
  score += methodRisk(method);
  score += classified.boost;
  score += riskyContext.reduce((sum, item) => sum + item.severityBoost, 0);

  if (!hasAuth) score += 5;
  if (!hasValidation && ["POST", "PUT", "PATCH", "DELETE", "ALL"].includes(String(method).toUpperCase())) {
    score += 3;
  }

  if (/\/$/i.test(path) || path === "/") score += 1;

  return {
    numericScore: score,
    severity: routeScoreToSeverity(score),
    tags: classified.tags
  };
}

function routeScoreToSeverity(score) {
  if (score >= 14) return "critical";
  if (score >= 10) return "high";
  if (score >= 6) return "medium";
  if (score >= 3) return "low";
  return "info";
}

function confidenceForRoute(framework, hasAuth, riskyContext) {
  let confidence = 0.72;

  if (framework === "express" || framework === "fastify" || framework === "hono") confidence += 0.12;
  if (riskyContext.length > 0) confidence += 0.08;
  if (!hasAuth) confidence += 0.05;

  return Math.min(0.98, confidence);
}

function buildFinding({ filePath, content, match, framework, method, path }) {
  const index = match.index;
  const line = getLineNumber(content, index);
  const snippet = cleanSnippet(getLineText(content, line));
  const window = getWindow(content, index);

  const hasAuth = detectAuth(window);
  const hasValidation = detectValidation(window);
  const riskyContext = detectRiskyContext(window);
  const scored = scoreRoute({ method, path, hasAuth, hasValidation, riskyContext });

  const title = `${String(method).toUpperCase()} ${path} exposure`;
  const authText = hasAuth ? "Auth-like control detected nearby." : "No auth-like control detected nearby.";
  const validationText = hasValidation ? "Validation-like control detected nearby." : "No validation-like control detected nearby.";

  return {
    id: `ROUTE-${String(method).toUpperCase()}-${path}-${filePath}-${line}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
    type: "route_exposure",
    category: "route_exposure",
    severity: scored.severity,
    confidence: confidenceForRoute(framework, hasAuth, riskyContext),
    file: filePath,
    line,
    ruleId: "ROUTE_EXPOSURE",
    title,
    description: `${title}. ${authText} ${validationText}`,
    method: String(method).toUpperCase(),
    path,
    framework,
    hasAuth,
    hasValidation,
    riskyContext,
    tags: scored.tags,
    evidence: {
      snippet,
      matchedText: match[0],
      source: "routeExposureEngine"
    },
    attackSurface: ["api", "web"],
    assets: [
      filePath,
      path,
      ...riskyContext.map(item => item.id)
    ],
    recommendation: buildRecommendation({ method, path, hasAuth, hasValidation, riskyContext }),
    remediation: [buildRecommendation({ method, path, hasAuth, hasValidation, riskyContext })],
    whyItMatters: buildWhyItMatters({ method, path, hasAuth, hasValidation, riskyContext }),
    metadata: {
      numericScore: scored.numericScore,
      pathTags: scored.tags,
      contextWindowSize: window.length
    }
  };
}

function buildWhyItMatters({ method, path, hasAuth, hasValidation, riskyContext }) {
  const risks = [];

  if (!hasAuth) risks.push("it may be publicly reachable without authentication");
  if (!hasValidation) risks.push("input validation was not detected nearby");
  if (riskyContext.length > 0) {
    risks.push(`it is near sensitive operations: ${riskyContext.map(item => item.label).join(", ")}`);
  }

  if (risks.length === 0) {
    risks.push("it expands the application attack surface");
  }

  return `${String(method).toUpperCase()} ${path} is a discovered route. ${risks.join("; ")}.`;
}

function buildRecommendation({ method, path, hasAuth, hasValidation, riskyContext }) {
  const recs = [];

  if (!hasAuth) {
    recs.push("Add authentication and authorization middleware before the handler.");
  }

  if (!hasValidation) {
    recs.push("Validate request body, query, params, and headers with a schema validator.");
  }

  if (riskyContext.some(item => item.id === "ENV_ACCESS")) {
    recs.push("Ensure secrets are never returned, logged, or exposed through this route.");
  }

  if (riskyContext.some(item => item.id === "COMMAND_EXEC")) {
    recs.push("Remove command execution or strictly allowlist commands and arguments.");
  }

  if (riskyContext.some(item => item.id === "WALLET_SIGNING")) {
    recs.push("Protect signing flows with explicit user authorization, chain validation, and transaction simulation.");
  }

  if (riskyContext.some(item => item.id === "FILE_ACCESS")) {
    recs.push("Normalize paths and enforce a safe base directory.");
  }

  if (/webhook|callback/i.test(path)) {
    recs.push("Verify webhook signatures and enforce replay protection.");
  }

  if (recs.length === 0) {
    recs.push("Review route exposure, logging, rate limiting, and authorization requirements.");
  }

  return recs.join(" ");
}

function discoverRoutes(filePath, content) {
  const findings = [];

  for (const pattern of ROUTE_PATTERNS) {
    resetRegex(pattern.regex);

    let match;
    while ((match = pattern.regex.exec(content)) !== null) {
      const method = match[1];
      const path = match[2];

      if (!method || !path) continue;

      findings.push(
        buildFinding({
          filePath,
          content,
          match,
          framework: pattern.framework,
          method,
          path
        })
      );

      if (match.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++;
      }
    }
  }

  return findings;
}

function detectNextApiRoute(filePath, content) {
  const lowerPath = filePath.toLowerCase();

  const isNextApi =
    lowerPath.includes("/pages/api/") ||
    lowerPath.includes("\\pages\\api\\") ||
    lowerPath.includes("/app/api/") ||
    lowerPath.includes("\\app\\api\\");

  if (!isNextApi) return [];

  const methodMatches = [...content.matchAll(/\b(req|request)\.method\b|\bexport\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\b/g)];
  const methods = new Set();

  for (const match of methodMatches) {
    if (match[2]) methods.add(match[2]);
  }

  if (methods.size === 0) methods.add("ALL");

  const path = "/" + filePath
    .replace(/\\/g, "/")
    .replace(/^.*\/pages\/api\//, "api/")
    .replace(/^.*\/app\/api\//, "api/")
    .replace(/\.(js|jsx|ts|tsx|mjs|cjs)$/i, "")
    .replace(/\/route$/, "")
    .replace(/\/index$/, "");

  const fakeFindings = [];

  for (const method of methods) {
    const match = {
      index: 0,
      0: `${method} ${path}`
    };

    fakeFindings.push(
      buildFinding({
        filePath,
        content,
        match,
        framework: "next_api",
        method,
        path
      })
    );
  }

  return fakeFindings;
}

export function routeExposureEngine(files = [], options = {}) {
  const findings = [];
  const routeInventory = [];
  const extensions = options.extensions || EXTENSIONS;

  for (const file of files) {
    const filePath = getFilePath(file);
    const content = getFileContent(file);
    const ext = getExtension(filePath);

    if (!content || !extensions.has(ext)) continue;

    const routeFindings = [
      ...discoverRoutes(filePath, content),
      ...detectNextApiRoute(filePath, content)
    ];

    for (const finding of routeFindings) {
      findings.push(finding);
      routeInventory.push({
        method: finding.method,
        path: finding.path,
        file: finding.file,
        line: finding.line,
        severity: finding.severity,
        hasAuth: finding.hasAuth,
        hasValidation: finding.hasValidation,
        framework: finding.framework
      });
    }
  }

  const deduped = dedupeFindings(findings);
  const summary = summarizeRoutes(deduped);

  return {
    engine: "routeExposureEngine",
    totalRoutes: deduped.length,
    routeInventory,
    publicRoutes: deduped.filter(item => !item.hasAuth).length,
    sensitiveRoutes: deduped.filter(item => item.tags?.length > 0 || item.riskyContext?.length > 0).length,
    criticalRoutes: summary.critical,
    highRoutes: summary.high,
    mediumRoutes: summary.medium,
    lowRoutes: summary.low,
    routeExposureScore: summary.score,
    routeExposureRiskLevel: summary.riskLevel,
    findings: deduped,
    recommendations: buildTopRecommendations(deduped)
  };
}

function dedupeFindings(findings = []) {
  const seen = new Set();
  const output = [];

  for (const finding of findings) {
    const key = `${finding.method}:${finding.path}:${finding.file}:${finding.line}`;

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

function summarizeRoutes(findings = []) {
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
    counts.medium * 8 +
    counts.low * 3;

  const score = Math.max(0, Math.min(100, 100 - weighted));

  let riskLevel = "LOW";
  if (counts.critical > 0 || weighted >= 75) riskLevel = "CRITICAL";
  else if (counts.high > 1 || weighted >= 45) riskLevel = "HIGH";
  else if (counts.high > 0 || counts.medium > 2 || weighted >= 20) riskLevel = "MEDIUM";

  return {
    ...counts,
    weighted,
    score,
    riskLevel
  };
}

function buildTopRecommendations(findings = []) {
  const recommendations = [];

  const unauthCritical = findings.find(item => item.severity === "critical" && !item.hasAuth);
  if (unauthCritical) {
    recommendations.push({
      severity: "critical",
      recommendation: "Prioritize authentication and authorization on critical exposed routes."
    });
  }

  const signingRoute = findings.find(item =>
    item.riskyContext?.some(ctx => ctx.id === "WALLET_SIGNING")
  );
  if (signingRoute) {
    recommendations.push({
      severity: "critical",
      recommendation: "Review wallet/signing routes for explicit user consent, transaction simulation, and chain validation."
    });
  }

  const commandRoute = findings.find(item =>
    item.riskyContext?.some(ctx => ctx.id === "COMMAND_EXEC")
  );
  if (commandRoute) {
    recommendations.push({
      severity: "critical",
      recommendation: "Remove or strictly isolate command execution reachable from routes."
    });
  }

  const webhook = findings.find(item => /webhook|callback/i.test(item.path));
  if (webhook) {
    recommendations.push({
      severity: "high",
      recommendation: "Verify webhook signatures, timestamps, and replay protection."
    });
  }

  const upload = findings.find(item => /upload|file/i.test(item.path));
  if (upload) {
    recommendations.push({
      severity: "high",
      recommendation: "Harden upload routes with content-type checks, size limits, extension allowlists, and malware scanning."
    });
  }

  if (recommendations.length === 0) {
    recommendations.push({
      severity: "info",
      recommendation: "No major route exposure risks detected by the lightweight route scanner."
    });
  }

  return recommendations.slice(0, 10);
}

export default routeExposureEngine;
