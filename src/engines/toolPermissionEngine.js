// src/engines/toolPermissionEngine.js

/**
 * Quantum Shield Trinity
 * Tool Permission Engine
 *
 * Purpose:
 * Scores dangerous AI-agent tool permissions.
 *
 * Detects:
 * - shell execution
 * - filesystem reads/writes/deletes
 * - database access
 * - email/calendar actions
 * - browser automation
 * - payment/crypto operations
 * - admin APIs
 * - missing approval gates
 * - missing allowlists/denylists
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
  ".env",
  ".txt"
];

const APPROVAL_PATTERNS = [
  /requireApproval/i,
  /requiresApproval/i,
  /approvalRequired/i,
  /confirmBefore/i,
  /humanApproval/i,
  /human[-_ ]?in[-_ ]?the[-_ ]?loop/i,
  /askUser/i,
  /confirm\s*\(/i,
  /approved\s*===?\s*true/i,
  /userConfirmed/i,
  /permissionCheck/i,
  /authorize/i,
  /isAuthorized/i
];

const ALLOWLIST_PATTERNS = [
  /allowlist/i,
  /allowedTools/i,
  /allowedPaths/i,
  /allowedCommands/i,
  /allowedDomains/i,
  /safeTools/i,
  /toolPolicy/i,
  /permissionPolicy/i,
  /denylist/i,
  /blockedTools/i,
  /blockedCommands/i,
  /blockedPaths/i,
  /sandbox/i
];

const TOOL_RULES = [
  {
    id: "AI_TOOL_SHELL_EXECUTION",
    capability: "Shell Execution",
    severity: "critical",
    pattern:
      /(child_process|execSync|exec\s*\(|spawn\s*\(|spawnSync|subprocess|os\.system|shell=True|pty\.spawn|bash|powershell|terminal|runCommand|executeCommand)/i,
    description:
      "AI-adjacent code appears to expose shell or command execution capability.",
    recommendation:
      "Require explicit human approval, sandbox all commands, block dangerous commands, and use strict command allowlists."
  },
  {
    id: "AI_TOOL_FILESYSTEM_WRITE",
    capability: "Filesystem Write/Delete",
    severity: "high",
    pattern:
      /(fs\.writeFile|fs\.appendFile|fs\.rm|fs\.unlink|fs\.rmdir|write_file|delete_file|remove_file|unlink\s*\(|rm\s+-rf|shutil\.rmtree|Path\(.*\)\.write_text|open\(.*['"]w['"])/i,
    description:
      "AI-adjacent code appears to allow writing, deleting, or modifying local files.",
    recommendation:
      "Restrict writes to a sandbox directory, block destructive operations, and require user approval for file modification."
  },
  {
    id: "AI_TOOL_FILESYSTEM_READ",
    capability: "Filesystem Read",
    severity: "medium",
    pattern:
      /(fs\.readFile|read_file|open\(.*['"]r['"]|Path\(.*\)\.read_text|cat\s+|load_file|readLocalFile)/i,
    description:
      "AI-adjacent code appears to allow local file reads.",
    recommendation:
      "Use allowlisted read paths and block secrets such as .env, SSH keys, credentials, private keys, and config files."
  },
  {
    id: "AI_TOOL_DATABASE_ACCESS",
    capability: "Database Access",
    severity: "high",
    pattern:
      /(db\.query|client\.query|prisma\.|mongoose\.|mongodb|postgres|mysql|sqlite|redis|supabase|select\s+.*from|delete\s+from|drop\s+table|update\s+.*set)/i,
    description:
      "AI-adjacent code appears to access a database or execute queries.",
    recommendation:
      "Use read-only credentials where possible, block destructive queries, and require approval for mutations."
  },
  {
    id: "AI_TOOL_EMAIL_SEND",
    capability: "Email Sending",
    severity: "high",
    pattern:
      /(send_email|sendEmail|gmail\.users\.messages\.send|transporter\.sendMail|create_draft|send_draft|forward_emails|mailgun|sendgrid)/i,
    description:
      "AI-adjacent code appears capable of sending, drafting, or forwarding email.",
    recommendation:
      "Require user confirmation before sending messages and log recipient, subject, and body summaries."
  },
  {
    id: "AI_TOOL_CALENDAR_MODIFY",
    capability: "Calendar Modification",
    severity: "medium",
    pattern:
      /(create_event|update_event|delete_event|calendar\.events\.insert|calendar\.events\.delete|google calendar|gcal)/i,
    description:
      "AI-adjacent code appears capable of modifying calendar events.",
    recommendation:
      "Require approval before creating, updating, deleting, or responding to calendar events."
  },
  {
    id: "AI_TOOL_BROWSER_AUTOMATION",
    capability: "Browser Automation",
    severity: "medium",
    pattern:
      /(puppeteer|playwright|selenium|browser\.newPage|page\.click|page\.type|page\.goto|webbrowser|browse|browserTool)/i,
    description:
      "AI-adjacent code appears capable of browser automation.",
    recommendation:
      "Limit browser automation to approved domains, disable credential entry, and require confirmation before transactions."
  },
  {
    id: "AI_TOOL_PAYMENT_OR_CRYPTO",
    capability: "Payment/Crypto Action",
    severity: "critical",
    pattern:
      /(stripe\.charges|stripe\.paymentIntents|transfer\(|sendTransaction|wallet\.send|ethers\.Wallet|privateKey|signTransaction|approve\(|swapExact|bridge|withdraw|deposit)/i,
    description:
      "AI-adjacent code appears capable of payment, wallet, token, or transaction actions.",
    recommendation:
      "Never allow autonomous financial transactions. Require explicit confirmation, transaction previews, limits, and multisig where possible."
  },
  {
    id: "AI_TOOL_ADMIN_API",
    capability: "Admin API",
    severity: "high",
    pattern:
      /(admin\.|isAdmin|deleteUser|banUser|updateRole|setRole|grantRole|revokeRole|iam:|AdministratorAccess|root access|superuser)/i,
    description:
      "AI-adjacent code appears capable of using admin or privileged APIs.",
    recommendation:
      "Separate admin tools from autonomous agents and require strong authorization checks plus audit logging."
  },
  {
    id: "AI_TOOL_NETWORK_REQUEST",
    capability: "External Network Request",
    severity: "medium",
    pattern:
      /(fetch\s*\(|axios\.|requests\.|http\.request|https\.request|curl\s+|webhook|postToUrl|apiClient)/i,
    description:
      "AI-adjacent code appears capable of making external network requests.",
    recommendation:
      "Use domain allowlists, block internal metadata IPs, and prevent exfiltration to untrusted endpoints."
  }
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

function hasAnyPattern(text, patterns = []) {
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
  hasApprovalGate,
  hasPermissionPolicy,
  nearbyContext
}) {
  let severity = rule.severity;
  let confidence = 0.82;

  if (!hasApprovalGate && ["critical", "high"].includes(severity)) {
    confidence = 0.9;
  }

  if (hasApprovalGate && hasPermissionPolicy) {
    confidence = 0.62;
    if (severity === "critical") severity = "high";
    else if (severity === "high") severity = "medium";
  }

  const missingControls = [];
  if (!hasApprovalGate) missingControls.push("approval gate");
  if (!hasPermissionPolicy) missingControls.push("allowlist/denylist policy");

  return {
    engine: "toolPermissionEngine",
    category: "AI Tool Permission Security",
    type: rule.id,
    severity,
    title: `${rule.capability} permission detected`,
    description: `${rule.description}${
      missingControls.length
        ? ` Missing control(s): ${missingControls.join(", ")}.`
        : " Approval and permission controls appear nearby."
    }`,
    file,
    line,
    evidence,
    nearbyContext: nearbyContext.slice(0, 800),
    capability: rule.capability,
    hasApprovalGate,
    hasPermissionPolicy,
    confidence,
    weightedRisk: Number((severityWeight(severity) * confidence).toFixed(2)),
    recommendation: rule.recommendation,
    tags: [
      "ai-security",
      "tool-permissions",
      rule.capability.toLowerCase().replace(/[^a-z0-9]+/g, "-")
    ]
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

    for (const rule of TOOL_RULES) {
      if (!rule.pattern.test(trimmed)) continue;

      const nearbyContext = lines
        .slice(Math.max(0, index - 8), Math.min(lines.length, index + 9))
        .join("\n");

      const hasApprovalGate = hasAnyPattern(nearbyContext, APPROVAL_PATTERNS);
      const hasPermissionPolicy = hasAnyPattern(nearbyContext, ALLOWLIST_PATTERNS);

      capabilities.add(rule.capability);

      findings.push(
        buildFinding({
          rule,
          file: filePath,
          line: index + 1,
          evidence: trimmed.slice(0, 300),
          nearbyContext,
          hasApprovalGate,
          hasPermissionPolicy
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

  const missingApprovalGates = findings.filter((finding) => !finding.hasApprovalGate).length;
  const missingPermissionPolicies = findings.filter((finding) => !finding.hasPermissionPolicy).length;

  const penalty =
    counts.critical * 18 +
    counts.high * 10 +
    counts.medium * 5 +
    counts.low * 2 +
    counts.info;

  return {
    totalFindings: findings.length,
    detectedCapabilities: capabilities,
    totalCapabilities: capabilities.length,
    missingApprovalGates,
    missingPermissionPolicies,
    ...counts,
    riskScore: Math.max(0, 100 - penalty),
    riskLevel: riskLevelFromCounts(counts),
    topFindings: [...findings]
      .sort((a, b) => b.weightedRisk - a.weightedRisk)
      .slice(0, 10)
  };
}

export function toolPermissionEngine(files = []) {
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
    engine: "toolPermissionEngine",
    name: "Tool Permission Engine",
    version: "1.0.0",
    category: "AI Security",
    description:
      "Scores dangerous AI-agent tool permissions including shell, filesystem, database, email, browser, payment, crypto, admin, and network capabilities.",
    riskLevel: summary.riskLevel,
    riskScore: summary.riskScore,
    summary,
    findings,
    detectedCapabilities: capabilityList,
    recommendations: [
      "Require human approval before shell, filesystem write/delete, email, calendar, database mutation, payment, crypto, or admin actions.",
      "Use strict allowlists for commands, tools, domains, file paths, and database operations.",
      "Block autonomous access to secrets, private keys, credentials, production databases, and financial workflows.",
      "Sandbox agent tools and apply least-privilege permissions.",
      "Log every tool call with user, model, prompt, arguments, result, and approval status.",
      "Add emergency stop controls, budget limits, and rate limits for autonomous agents."
    ]
  };
}

export default toolPermissionEngine;
