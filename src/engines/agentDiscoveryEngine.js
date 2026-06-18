// src/engines/agentDiscoveryEngine.js

/**
 * Quantum Shield Trinity
 * Agent Discovery Engine
 *
 * Detects AI agents, LLM frameworks, tool calling, RAG systems,
 * vector databases, memory, MCP servers, and autonomous workflows.
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

const FRAMEWORK_RULES = [
  {
    id: "OPENAI_SDK",
    framework: "OpenAI",
    pattern: /(from\s+["']openai["']|require\(["']openai["']\)|new\s+OpenAI|OpenAI\()/i,
    severity: "medium"
  },
  {
    id: "ANTHROPIC_SDK",
    framework: "Anthropic",
    pattern: /(from\s+["']@anthropic-ai\/sdk["']|require\(["']@anthropic-ai\/sdk["']\)|Anthropic\()/i,
    severity: "medium"
  },
  {
    id: "LANGCHAIN",
    framework: "LangChain",
    pattern: /(langchain|@langchain|ChatOpenAI|RunnableSequence|AgentExecutor|createReactAgent)/i,
    severity: "medium"
  },
  {
    id: "CREWAI",
    framework: "CrewAI",
    pattern: /(from\s+crewai|Crew\(|Agent\(|Task\()/i,
    severity: "medium"
  },
  {
    id: "AUTOGEN",
    framework: "AutoGen",
    pattern: /(autogen|AssistantAgent|UserProxyAgent|GroupChat)/i,
    severity: "medium"
  },
  {
    id: "MCP",
    framework: "MCP",
    pattern: /(ModelContextProtocol|@modelcontextprotocol|mcp_server|MCPServer|server\.tool\()/i,
    severity: "high"
  },
  {
    id: "GEMINI",
    framework: "Gemini",
    pattern: /(GoogleGenerativeAI|@google\/generative-ai|gemini-pro|gemini-)/i,
    severity: "medium"
  },
  {
    id: "OLLAMA",
    framework: "Ollama",
    pattern: /(ollama|localhost:11434)/i,
    severity: "low"
  }
];

const CAPABILITY_RULES = [
  {
    id: "TOOL_CALLING",
    capability: "Tool Calling",
    pattern: /(tools\s*:|function_call|tool_choice|functions\s*:|bindTools|tool_calls)/i,
    severity: "high",
    recommendation:
      "Review tool permissions and require approval for filesystem, shell, email, finance, or database actions."
  },
  {
    id: "FILE_SYSTEM_TOOL",
    capability: "Filesystem Access",
    pattern: /(fs\.readFile|fs\.writeFile|read_file|write_file|open\(|Path\(|os\.remove|unlink|rm\s+-rf)/i,
    severity: "high",
    recommendation:
      "Restrict file access to allowlisted paths and block secrets, credentials, and environment files."
  },
  {
    id: "SHELL_EXECUTION",
    capability: "Shell Execution",
    pattern: /(child_process|exec\(|spawn\(|subprocess|os\.system|shell=True|bash|powershell)/i,
    severity: "critical",
    recommendation:
      "Require explicit user approval before shell execution and sandbox all commands."
  },
  {
    id: "DATABASE_ACCESS",
    capability: "Database Access",
    pattern: /(postgres|mysql|mongodb|prisma|supabase|sqlite|redis|database|db\.query)/i,
    severity: "high",
    recommendation:
      "Use read-only credentials where possible and prevent agents from executing destructive queries."
  },
  {
    id: "EMAIL_CALENDAR_ACCESS",
    capability: "Email/Calendar Access",
    pattern: /(gmail|send_email|create_draft|calendar|create_event|delete_event)/i,
    severity: "high",
    recommendation:
      "Require user confirmation before sending emails, modifying calendars, or deleting messages."
  },
  {
    id: "VECTOR_DATABASE",
    capability: "Vector Database / RAG",
    pattern: /(pinecone|weaviate|chroma|qdrant|faiss|vectorStore|similaritySearch|retriever)/i,
    severity: "medium",
    recommendation:
      "Treat retrieved content as untrusted and protect against RAG poisoning."
  },
  {
    id: "MEMORY_SYSTEM",
    capability: "Agent Memory",
    pattern: /(memory|ConversationBufferMemory|VectorStoreRetrieverMemory|save_context|chat_history)/i,
    severity: "medium",
    recommendation:
      "Avoid storing secrets or sensitive data in long-term agent memory."
  },
  {
    id: "AUTONOMOUS_LOOP",
    capability: "Autonomous Loop",
    pattern: /(while\s*\(true\)|for\s*\(\s*;\s*;\s*\)|max_iterations|run_until|autonomous|planner|executor)/i,
    severity: "high",
    recommendation:
      "Add max-iteration limits, cost controls, approval gates, and emergency stop logic."
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
  if (counts.high >= 3) return "HIGH";
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
  tags = []
}) {
  return {
    engine: "agentDiscoveryEngine",
    category: "AI Agent Security",
    type: id,
    severity,
    title,
    description,
    file,
    line,
    evidence,
    confidence: 0.8,
    weightedRisk: Number((severityWeight(severity) * 0.8).toFixed(2)),
    recommendation,
    tags
  };
}

function scanFile(file = {}) {
  const filePath = normalizePath(file);
  const content = normalizeContent(file);
  const findings = [];
  const frameworks = new Set();
  const capabilities = new Set();

  if (!isSupportedFile(filePath)) {
    return { findings, frameworks, capabilities };
  }

  if (!content.trim()) {
    return { findings, frameworks, capabilities };
  }

  const lines = content.split(/\r?\n/);

  lines.forEach((lineText, index) => {
    const line = index + 1;
    const trimmed = lineText.trim();

    if (!trimmed) return;

    for (const rule of FRAMEWORK_RULES) {
      if (rule.pattern.test(trimmed)) {
        frameworks.add(rule.framework);

        findings.push(
          buildFinding({
            id: rule.id,
            severity: rule.severity,
            title: `${rule.framework} framework detected`,
            description:
              `The repository appears to use ${rule.framework}, indicating AI/LLM application behavior.`,
            file: filePath,
            line,
            evidence: trimmed.slice(0, 300),
            recommendation:
              "Review model usage, prompt handling, tool permissions, memory, logging, and data exposure controls.",
            tags: ["ai", "framework", rule.framework.toLowerCase()]
          })
        );
      }
    }

    for (const rule of CAPABILITY_RULES) {
      if (rule.pattern.test(trimmed)) {
        capabilities.add(rule.capability);

        findings.push(
          buildFinding({
            id: rule.id,
            severity: rule.severity,
            title: `${rule.capability} detected`,
            description:
              `AI-adjacent capability detected: ${rule.capability}. This may increase agent security risk if exposed to LLM decisions.`,
            file: filePath,
            line,
            evidence: trimmed.slice(0, 300),
            recommendation: rule.recommendation,
            tags: ["ai", "agent-capability", rule.capability.toLowerCase()]
          })
        );
      }
    }
  });

  return { findings, frameworks, capabilities };
}

function summarize(findings = [], frameworks = [], capabilities = []) {
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
    counts.critical * 18 +
    counts.high * 10 +
    counts.medium * 5 +
    counts.low * 2 +
    counts.info;

  const riskScore = Math.max(0, 100 - penalty);

  return {
    totalFindings: findings.length,
    detectedFrameworks: frameworks,
    detectedCapabilities: capabilities,
    totalFrameworks: frameworks.length,
    totalCapabilities: capabilities.length,
    ...counts,
    riskScore,
    riskLevel: riskLevelFromCounts(counts),
    topFindings: [...findings]
      .sort((a, b) => b.weightedRisk - a.weightedRisk)
      .slice(0, 10)
  };
}

export function agentDiscoveryEngine(files = []) {
  const findings = [];
  const frameworks = new Set();
  const capabilities = new Set();

  for (const file of files) {
    const result = scanFile(file);

    findings.push(...result.findings);

    result.frameworks.forEach((framework) => frameworks.add(framework));
    result.capabilities.forEach((capability) => capabilities.add(capability));
  }

  const frameworkList = [...frameworks].sort();
  const capabilityList = [...capabilities].sort();
  const summary = summarize(findings, frameworkList, capabilityList);

  return {
    engine: "agentDiscoveryEngine",
    name: "Agent Discovery Engine",
    version: "1.0.0",
    category: "AI Security",
    description:
      "Discovers AI frameworks, agents, tool usage, autonomous loops, memory, RAG systems, MCP servers, and high-risk agent capabilities.",
    riskLevel: summary.riskLevel,
    riskScore: summary.riskScore,
    summary,
    findings,
    detectedFrameworks: frameworkList,
    detectedCapabilities: capabilityList,
    recommendations: [
      "Inventory all AI frameworks, agents, tools, memory systems, and RAG pipelines.",
      "Apply least-privilege access to agent tools.",
      "Require approval before agents use shell, filesystem, email, calendar, financial, or database tools.",
      "Add maximum iteration limits and cost controls for autonomous workflows.",
      "Treat retrieved documents as untrusted input.",
      "Avoid storing secrets in agent memory or vector databases.",
      "Log all model calls, tool calls, and agent decisions for auditability."
    ]
  };
}

export default agentDiscoveryEngine;
