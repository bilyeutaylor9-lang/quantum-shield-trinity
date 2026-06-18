


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

const AGENT_EXECUTION_RULES = [
  {
    id: "AI_AGENT_AUTONOMOUS_EXECUTION",
    severity: "high",
    pattern:
      /(agent\.run|agent\.execute|agent\.invoke|executor\.invoke|AgentExecutor|crew\.kickoff|autonomous|runAutonomous|autoRun|planner\.run|task\.execute)/i,
    title: "Autonomous agent execution detected",
    description:
      "The code appears to execute an AI agent or agent workflow that may perform actions without direct human approval.",
    recommendation:
      "Add approval gates, max-iteration limits, budget controls, and detailed audit logging for autonomous execution."
  },
  {
    id: "AI_AGENT_RECURSIVE_LOOP",
    severity: "critical",
    pattern:
      /(while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)|recursiveAgent|selfReflect|self_reflect|reflectAndRetry|run_until|loop_until|max_iterations\s*:\s*(0|null|undefined|-1))/i,
    title: "Recursive or unbounded agent loop detected",
    description:
      "The code may allow an AI agent to run recursively or without a safe iteration bound.",
    recommendation:
      "Set strict max iterations, execution timeouts, token budgets, cost budgets, and emergency stop controls."
  },
  {
    id: "AI_AGENT_SELF_MODIFICATION",
    severity: "high",
    pattern:
      /(updatePrompt|rewritePrompt|rewriteSystemPrompt|setSystemPrompt|modifyInstructions|selfModify|self_modify|agent\.memory\.save|save_context|systemPrompt\s*=|developerPrompt\s*=)/i,
    title: "Self-modifying prompt or agent behavior detected",
    description:
      "The code may allow an agent to alter prompts, instructions, memory, or behavior across executions.",
    recommendation:
      "Separate immutable system instructions from user-controlled memory and block agents from modifying their own authority."
  },
  {
    id: "AI_AGENT_TO_AGENT_COMMUNICATION",
    severity: "medium",
    pattern:
      /(agentA|agentB|multiAgent|groupChat|GroupChat|sendMessageToAgent|agent\.send|agent\.receive|handoff|delegateToAgent|swarm|crew|AutoGen)/i,
    title: "Agent-to-agent communication detected",
    description:
      "The code appears to coordinate multiple agents or delegate work between agents.",
    recommendation:
      "Define trust boundaries between agents, restrict delegation, and log agent-to-agent messages and tool handoffs."
  },
  {
    id: "AI_AGENT_TOOL_ESCALATION_SURFACE",
    severity: "high",
    pattern:
      /(tools\s*:|tool_choice|function_call|tool_calls|bindTools|availableTools|registerTool|server\.tool|ToolNode|StructuredTool)/i,
    title: "Agent tool escalation surface detected",
    description:
      "The code appears to expose tools or function calls to an AI agent, creating escalation risk if prompts are hijacked.",
    recommendation:
      "Use least-privilege tools, per-tool approval, input validation, output filtering, and strict allowlists."
  },
  {
    id: "AI_AGENT_EXTERNAL_ACTION_CHAIN",
    severity: "high",
    pattern:
      /(send_email|sendEmail|create_event|delete_event|db\.query|exec\s*\(|spawn\s*\(|fs\.writeFile|sendTransaction|stripe\.paymentIntents|browser\.newPage|page\.click)/i,
    title: "External action in agent-adjacent code detected",
    description:
      "The code appears to connect agent logic to external side effects such as email, calendar, database, shell, browser, or payments.",
    recommendation:
      "Require explicit user approval and action previews before any external side effect is performed."
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

function riskLevelFromCounts(counts) {
  if (counts.critical > 0) return "CRITICAL";
  if (counts.high >= 4) return "CRITICAL";
  if (counts.high >= 2) return "HIGH";
  if (counts.high > 0 || counts.medium >= 3) return "MEDIUM";
  if (counts.medium > 0 || counts.low > 0) return "LOW";
  return "SAFE";
}

function buildFinding({
  id,
  severity,
  title,
  description,
  file,
  line,
  evidence,
  recommendation,
  confidence = 0.84,
  tags = [],
  metadata = {}
}) {
  return {
    engine: "aiAgentRiskEngine",
    category: "AI Agent Risk",
    type: id,
    severity,
    title,
    description,
    file,
    line,
    evidence,
    confidence,
    weightedRisk: Number((severityWeight(severity) * confidence).toFixed(2)),
    recommendation,
    tags: ["ai-security", "agent-risk", ...tags],
    metadata
  };
}

function scanFile(file = {}) {
  const filePath = normalizePath(file);
  const content = normalizeContent(file);
  const findings = [];

  if (!isSupportedFile(filePath)) return findings;
  if (!content.trim()) return findings;

  const lines = content.split(/\r?\n/);

  lines.forEach((lineText, index) => {
    const trimmed = lineText.trim();
    if (!trimmed) return;

    for (const rule of AGENT_EXECUTION_RULES) {
      if (!rule.pattern.test(trimmed)) continue;

      findings.push(
        buildFinding({
          id: rule.id,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          file: filePath,
          line: index + 1,
          evidence: trimmed.slice(0, 300),
          recommendation: rule.recommendation,
          tags: ["static-detection"],
          metadata: {
            source: "static-rule",
            ruleId: rule.id
          }
        })
      );
    }
  });

  return findings;
}

function hasFindings(report = {}) {
  return Array.isArray(report.findings) && report.findings.length > 0;
}

function countBySeverity(findings = [], severity) {
  return findings.filter(
    (finding) => String(finding.severity || "").toLowerCase() === severity
  ).length;
}

function buildCorrelationFindings({
  agentDiscoveryReport = {},
  toolPermissionReport = {},
  promptInjectionReport = {}
}) {
  const findings = [];

  const agentFindings = agentDiscoveryReport.findings ?? [];
  const toolFindings = toolPermissionReport.findings ?? [];
  const promptFindings = promptInjectionReport.findings ?? [];

  const detectedFrameworks =
    agentDiscoveryReport.summary?.detectedFrameworks ??
    agentDiscoveryReport.detectedFrameworks ??
    [];

  const detectedCapabilities =
    toolPermissionReport.summary?.detectedCapabilities ??
    toolPermissionReport.detectedCapabilities ??
    [];

  const hasAgents = hasFindings(agentDiscoveryReport) || detectedFrameworks.length > 0;
  const hasTools = hasFindings(toolPermissionReport) || detectedCapabilities.length > 0;
  const hasPromptInjection = hasFindings(promptInjectionReport);

  const criticalTools = countBySeverity(toolFindings, "critical");
  const highTools = countBySeverity(toolFindings, "high");
  const criticalPrompts = countBySeverity(promptFindings, "critical");
  const highPrompts = countBySeverity(promptFindings, "high");

  if (hasAgents && hasTools && hasPromptInjection) {
    findings.push(
      buildFinding({
        id: "AI_AGENT_PROMPT_TO_TOOL_CHAIN",
        severity: criticalTools > 0 || criticalPrompts > 0 ? "critical" : "high",
        title: "Prompt injection to tool-abuse attack chain detected",
        description:
          "The repository contains AI-agent indicators, prompt-injection exposure, and tool permissions. A hijacked prompt could potentially drive agent tools.",
        file: "repository",
        line: null,
        evidence:
          `Frameworks: ${detectedFrameworks.join(", ") || "unknown"}; ` +
          `Tool capabilities: ${detectedCapabilities.join(", ") || "unknown"}`,
        recommendation:
          "Add prompt-injection filtering, strict tool allowlists, per-action approval, and audit logging across all agent tool calls.",
        confidence: 0.92,
        tags: ["correlation", "attack-chain", "tool-abuse"],
        metadata: {
          detectedFrameworks,
          detectedCapabilities,
          promptFindings: promptFindings.length,
          toolFindings: toolFindings.length
        }
      })
    );
  }

  if (hasAgents && (criticalTools > 0 || highTools >= 2)) {
    findings.push(
      buildFinding({
        id: "AI_AGENT_HIGH_PRIVILEGE_TOOLS",
        severity: criticalTools > 0 ? "critical" : "high",
        title: "AI agent has high-privilege tool exposure",
        description:
          "Agent indicators were found alongside high-risk or critical tool capabilities.",
        file: "repository",
        line: null,
        evidence:
          `Critical tools: ${criticalTools}; High tools: ${highTools}; ` +
          `Capabilities: ${detectedCapabilities.join(", ") || "unknown"}`,
        recommendation:
          "Separate high-privilege tools from autonomous agents. Require explicit approval and least-privilege policies.",
        confidence: 0.9,
        tags: ["correlation", "privilege-escalation"],
        metadata: {
          criticalTools,
          highTools,
          detectedCapabilities
        }
      })
    );
  }

  const missingApprovalGates =
    toolPermissionReport.summary?.missingApprovalGates ??
    toolFindings.filter((finding) => finding.hasApprovalGate === false).length;

  const missingPermissionPolicies =
    toolPermissionReport.summary?.missingPermissionPolicies ??
    toolFindings.filter((finding) => finding.hasPermissionPolicy === false).length;

  if (hasTools && (missingApprovalGates > 0 || missingPermissionPolicies > 0)) {
    findings.push(
      buildFinding({
        id: "AI_AGENT_MISSING_TOOL_GUARDRAILS",
        severity: missingApprovalGates >= 3 ? "high" : "medium",
        title: "AI tool permissions may lack guardrails",
        description:
          "Tool permissions were detected without enough nearby approval gates or allowlist/denylist policies.",
        file: "repository",
        line: null,
        evidence:
          `Missing approval gates: ${missingApprovalGates}; ` +
          `Missing permission policies: ${missingPermissionPolicies}`,
        recommendation:
          "Add human approval, allowlists, denylists, sandbox boundaries, and policy enforcement for agent tools.",
        confidence: 0.86,
        tags: ["correlation", "missing-controls"],
        metadata: {
          missingApprovalGates,
          missingPermissionPolicies
        }
      })
    );
  }

  if (hasAgents && detectedCapabilities.length >= 4) {
    findings.push(
      buildFinding({
        id: "AI_AGENT_BROAD_CAPABILITY_SURFACE",
        severity: detectedCapabilities.length >= 7 ? "high" : "medium",
        title: "Broad AI-agent capability surface detected",
        description:
          "The agent environment appears to expose multiple classes of capabilities, increasing blast radius if compromised.",
        file: "repository",
        line: null,
        evidence: detectedCapabilities.join(", "),
        recommendation:
          "Split tools into separate roles, restrict access by task, and isolate high-risk actions behind approval gates.",
        confidence: 0.84,
        tags: ["correlation", "blast-radius"],
        metadata: {
          detectedCapabilities
        }
      })
    );
  }

  return findings;
}

function summarize(findings = []) {
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

  const penalty =
    counts.critical * 20 +
    counts.high * 10 +
    counts.medium * 5 +
    counts.low * 2 +
    counts.info;

  const riskScore = Math.max(0, 100 - penalty);

  return {
    totalFindings: findings.length,
    ...counts,
    riskScore,
    riskLevel: riskLevelFromCounts(counts),
    topFindings: [...findings]
      .sort((a, b) => b.weightedRisk - a.weightedRisk)
      .slice(0, 10)
  };
}

export function aiAgentRiskEngine(input = {}) {
  const files = Array.isArray(input) ? input : input.files ?? [];

  const agentDiscoveryReport = Array.isArray(input)
    ? {}
    : input.agentDiscoveryReport ?? {};

  const toolPermissionReport = Array.isArray(input)
    ? {}
    : input.toolPermissionReport ?? {};

  const promptInjectionReport = Array.isArray(input)
    ? {}
    : input.promptInjectionReport ?? {};

  const staticFindings = [];

  for (const file of files) {
    staticFindings.push(...scanFile(file));
  }

  const correlationFindings = buildCorrelationFindings({
    agentDiscoveryReport,
    toolPermissionReport,
    promptInjectionReport
  });

  const findings = [...staticFindings, ...correlationFindings];
  const summary = summarize(findings);

  return {
    engine: "aiAgentRiskEngine",
    name: "AI Agent Risk Engine",
    version: "1.0.0",
    category: "AI Security",
    description:
      "Correlates AI-agent discovery, prompt-injection exposure, and tool permissions to identify weaponizable agent behavior.",
    riskLevel: summary.riskLevel,
    riskScore: summary.riskScore,
    summary,
    findings,
    recommendations: [
      "Require human approval for high-impact agent actions.",
      "Add max-iteration, cost, token, and runtime limits to autonomous workflows.",
      "Separate prompts, memory, retrieved documents, and executable instructions.",
      "Restrict tools by role and task using explicit allowlists.",
      "Block agents from modifying their own system prompts, policies, or authority.",
      "Log agent decisions, tool calls, prompt inputs, retrieved context, and approval status.",
      "Model prompt-injection-to-tool-abuse paths during security review."
    ]
  };
}

export default aiAgentRiskEngine;
