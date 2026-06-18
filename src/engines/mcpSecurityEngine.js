// src/engines/mcpSecurityEngine.js

/**
 * Quantum Shield Trinity
 * MCP Security Engine
 *
 * Detects Model Context Protocol risks:
 * - MCP servers
 * - server.tool() registrations
 * - stdio / HTTP / SSE transports
 * - filesystem tools
 * - shell execution tools
 * - database tools
 * - browser automation tools
 * - missing authentication
 * - missing approval gates
 * - unsafe tool schemas
 * - secrets exposed to tools
 */

const SUPPORTED_EXTENSIONS = [
  ".js",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".json",
  ".md",
  ".yaml",
  ".yml",
  ".txt"
];

const MCP_RULES = [
  {
    id: "MCP_SERVER_DETECTED",
    severity: "medium",
    pattern: /(McpServer|ModelContextProtocol|@modelcontextprotocol|mcp_server|FastMCP|server\s*=\s*Server\()/i,
    title: "MCP server detected",
    recommendation:
      "Review exposed MCP tools, authentication, transport security, approval gates, and secret handling."
  },
  {
    id: "MCP_TOOL_REGISTRATION",
    severity: "high",
    pattern: /(server\.tool\s*\(|server\.registerTool|tool\s*\(|@mcp\.tool|register_tool)/i,
    title: "MCP tool registration detected",
    recommendation:
      "Ensure registered tools use strict schemas, authorization checks, input validation, and approval gates."
  },
  {
    id: "MCP_STDIO_TRANSPORT",
    severity: "medium",
    pattern: /(StdioServerTransport|stdio|from\s+["']@modelcontextprotocol\/sdk\/server\/stdio)/i,
    title: "MCP stdio transport detected",
    recommendation:
      "Restrict which local clients can launch this server and avoid exposing powerful local tools."
  },
  {
    id: "MCP_HTTP_SSE_TRANSPORT",
    severity: "high",
    pattern: /(SSEServerTransport|StreamableHTTPServerTransport|httpServer|app\.listen|express\(|fastify\(|sse)/i,
    title: "MCP HTTP/SSE transport detected",
    recommendation:
      "Add authentication, origin checks, rate limiting, TLS, and network allowlists for remote MCP transport."
  },
  {
    id: "MCP_FILESYSTEM_TOOL",
    severity: "high",
    pattern: /(fs\.readFile|fs\.writeFile|fs\.rm|read_file|write_file|delete_file|open\(.*['"]w['"]|Path\(.*\)\.read_text)/i,
    title: "MCP filesystem tool capability detected",
    recommendation:
      "Restrict filesystem tools to sandboxed allowlisted paths and block access to secrets or credentials."
  },
  {
    id: "MCP_SHELL_TOOL",
    severity: "critical",
    pattern: /(child_process|exec\s*\(|execSync|spawn\s*\(|subprocess|os\.system|shell=True|runCommand|executeCommand)/i,
    title: "MCP shell execution capability detected",
    recommendation:
      "Avoid shell tools unless absolutely required. Use command allowlists, sandboxing, and human approval."
  },
  {
    id: "MCP_DATABASE_TOOL",
    severity: "high",
    pattern: /(db\.query|client\.query|prisma\.|mongoose\.|mongodb|postgres|mysql|sqlite|redis|supabase)/i,
    title: "MCP database tool capability detected",
    recommendation:
      "Use least-privilege database credentials, block destructive queries, and require approval for mutations."
  },
  {
    id: "MCP_BROWSER_TOOL",
    severity: "medium",
    pattern: /(puppeteer|playwright|selenium|browser\.newPage|page\.click|page\.goto|browserTool)/i,
    title: "MCP browser automation tool detected",
    recommendation:
      "Restrict browser tools to approved domains and require approval before submissions, purchases, or logins."
  },
  {
    id: "MCP_SECRET_EXPOSURE",
    severity: "critical",
    pattern: /(process\.env|OPENAI_API_KEY|ANTHROPIC_API_KEY|API_KEY|SECRET|TOKEN|PRIVATE_KEY|password|credentials)/i,
    title: "Secrets may be exposed to MCP server or tools",
    recommendation:
      "Do not expose secrets directly to MCP tools. Use scoped credentials, secret managers, and redaction."
  },
  {
    id: "MCP_UNSAFE_SCHEMA",
    severity: "medium",
    pattern: /(z\.any\(\)|z\.unknown\(\)|any\s*:|inputSchema\s*:\s*\{\s*\}|parameters\s*:\s*\{\s*\})/i,
    title: "Unsafe or overly broad MCP tool schema detected",
    recommendation:
      "Use strict schemas, enums, length limits, path validation, and type validation for every MCP tool input."
  }
];

const AUTH_PATTERNS = [
  /auth/i,
  /apiKey/i,
  /token/i,
  /bearer/i,
  /session/i,
  /isAuthorized/i,
  /requireAuth/i,
  /verify/i,
  /permission/i
];

const APPROVAL_PATTERNS = [
  /requireApproval/i,
  /requiresApproval/i,
  /approvalRequired/i,
  /humanApproval/i,
  /confirmBefore/i,
  /askUser/i,
  /userConfirmed/i,
  /confirm\s*\(/i
];

const ALLOWLIST_PATTERNS = [
  /allowlist/i,
  /allowedTools/i,
  /allowedPaths/i,
  /allowedCommands/i,
  /allowedDomains/i,
  /denylist/i,
  /blockedTools/i,
  /blockedPaths/i,
  /sandbox/i
];

function normalizePath(file = {}) {
  return String(file.path || file.file || file.name || file.filename || "unknown");
}

function normalizeContent(file = {}) {
  return String(file.content || file.text || file.source || file.code || "");
}

function isSupportedFile(filePath) {
  const lower = String(filePath).toLowerCase();
  return SUPPORTED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

function severityWeight(severity = "info") {
  const weights = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 2,
    info: 1
  };

  return weights[String(severity).toLowerCase()] ?? 1;
}

function hasAny(text, patterns = []) {
  return patterns.some((pattern) => pattern.test(text));
}

function riskLevelFromCounts(counts) {
  if (counts.critical > 0) return "CRITICAL";
  if (counts.high >= 3) return "HIGH";
  if (counts.high > 0 || counts.medium >= 3) return "MEDIUM";
  if (counts.medium > 0 || counts.low > 0) return "LOW";
  return "SAFE";
}

function buildFinding({
  rule,
  file,
  line,
  evidence,
  nearbyContext,
  hasAuth,
  hasApproval,
  hasAllowlist
}) {
  let severity = rule.severity;
  let confidence = 0.84;

  if (
    ["MCP_TOOL_REGISTRATION", "MCP_HTTP_SSE_TRANSPORT", "MCP_FILESYSTEM_TOOL", "MCP_SHELL_TOOL", "MCP_DATABASE_TOOL"].includes(rule.id)
  ) {
    if (!hasAuth && !hasApproval && !hasAllowlist) {
      confidence = 0.92;
      if (severity === "medium") severity = "high";
      else if (severity === "high") severity = "critical";
    }
  }

  const missingControls = [];
  if (!hasAuth) missingControls.push("authentication");
  if (!hasApproval) missingControls.push("approval gate");
  if (!hasAllowlist) missingControls.push("allowlist/sandbox policy");

  return {
    engine: "mcpSecurityEngine",
    category: "MCP Security",
    type: rule.id,
    severity,
    title: rule.title,
    description:
      missingControls.length > 0
        ? `${rule.title}. Missing nearby control(s): ${missingControls.join(", ")}.`
        : `${rule.title}. Nearby controls were detected.`,
    file,
    line,
    evidence,
    nearbyContext: nearbyContext.slice(0, 800),
    hasAuth,
    hasApproval,
    hasAllowlist,
    confidence,
    weightedRisk: Number((severityWeight(severity) * confidence).toFixed(2)),
    recommendation: rule.recommendation,
    tags: ["ai-security", "mcp", "tool-security"]
  };
}

function scanFile(file = {}) {
  const filePath = normalizePath(file);
  const content = normalizeContent(file);
  const findings = [];
  const capabilities = new Set();

  if (!isSupportedFile(filePath)) return { findings, capabilities };
  if (!content.trim()) return { findings, capabilities };

  const lines = content.split(/\r?\n/);

  lines.forEach((lineText, index) => {
    const trimmed = lineText.trim();
    if (!trimmed) return;

    for (const rule of MCP_RULES) {
      if (!rule.pattern.test(trimmed)) continue;

      const nearbyContext = lines
        .slice(Math.max(0, index - 8), Math.min(lines.length, index + 9))
        .join("\n");

      const hasAuth = hasAny(nearbyContext, AUTH_PATTERNS);
      const hasApproval = hasAny(nearbyContext, APPROVAL_PATTERNS);
      const hasAllowlist = hasAny(nearbyContext, ALLOWLIST_PATTERNS);

      capabilities.add(rule.id);

      findings.push(
        buildFinding({
          rule,
          file: filePath,
          line: index + 1,
          evidence: trimmed.slice(0, 300),
          nearbyContext,
          hasAuth,
          hasApproval,
          hasAllowlist
        })
      );
    }
  });

  return { findings, capabilities };
}

function summarize(findings = [], capabilities = []) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  findings.forEach((finding) => {
    const severity = String(finding.severity || "info").toLowerCase();
    if (counts[severity] !== undefined) counts[severity] += 1;
  });

  const missingAuth = findings.filter((finding) => !finding.hasAuth).length;
  const missingApproval = findings.filter((finding) => !finding.hasApproval).length;
  const missingAllowlist = findings.filter((finding) => !finding.hasAllowlist).length;

  const penalty =
    counts.critical * 20 +
    counts.high * 10 +
    counts.medium * 5 +
    counts.low * 2 +
    counts.info;

  const riskScore = Math.max(0, 100 - penalty);

  return {
    totalFindings: findings.length,
    detectedCapabilities: capabilities,
    totalCapabilities: capabilities.length,
    missingAuth,
    missingApproval,
    missingAllowlist,
    ...counts,
    riskScore,
    riskLevel: riskLevelFromCounts(counts),
    topFindings: [...findings]
      .sort((a, b) => b.weightedRisk - a.weightedRisk)
      .slice(0, 10)
  };
}

export function mcpSecurityEngine(files = []) {
  const findings = [];
  const capabilities = new Set();

  for (const file of files) {
    const result = scanFile(file);

    findings.push(...result.findings);
    result.capabilities.forEach((capability) => capabilities.add(capability));
  }

  const capabilityList = [...capabilities].sort();
  const summary = summarize(findings, capabilityList);

  return {
    engine: "mcpSecurityEngine",
    name: "MCP Security Engine",
    version: "1.0.0",
    category: "AI Security",
    description:
      "Detects MCP servers, tool registrations, transports, dangerous tools, missing controls, unsafe schemas, and secret exposure.",
    riskLevel: summary.riskLevel,
    riskScore: summary.riskScore,
    summary,
    findings,
    detectedCapabilities: capabilityList,
    recommendations: [
      "Require authentication for remote MCP transports.",
      "Use strict schemas for every MCP tool input.",
      "Require approval before tools modify files, run commands, send messages, access databases, browse, or move funds.",
      "Sandbox filesystem and shell tools.",
      "Use allowlists for paths, commands, tools, and domains.",
      "Never expose raw secrets or private keys to MCP tools.",
      "Log every MCP tool call with caller, arguments, result, and approval status."
    ]
  };
}

export default mcpSecurityEngine;
