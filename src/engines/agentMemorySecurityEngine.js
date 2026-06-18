

const SUPPORTED_EXTENSIONS = [
  ".js",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".json",
  ".md",
  ".txt",
  ".yaml",
  ".yml"
];

const MEMORY_RULES = [
  {
    id: "AGENT_CONVERSATION_MEMORY",
    severity: "medium",
    pattern:
      /(ConversationBufferMemory|ConversationSummaryMemory|chat_history|messageHistory|conversationHistory|save_context|load_memory_variables)/i,
    title: "Conversation memory detected",
    recommendation:
      "Redact sensitive data before storing conversation memory and define clear retention/deletion policies."
  },
  {
    id: "AGENT_LONG_TERM_MEMORY",
    severity: "high",
    pattern:
      /(longTermMemory|long_term_memory|persistentMemory|memoryStore|saveMemory|recallMemory|userMemory|profileMemory)/i,
    title: "Long-term agent memory detected",
    recommendation:
      "Require user consent, minimize stored data, encrypt memory, and provide delete/forget workflows."
  },
  {
    id: "AGENT_VECTOR_MEMORY",
    severity: "high",
    pattern:
      /(VectorStoreRetrieverMemory|vectorMemory|memoryVectorStore|memoryIndex|embedMemory|memoryEmbedding|semanticMemory)/i,
    title: "Vector-based agent memory detected",
    recommendation:
      "Prevent secrets and PII from entering vector memory. Store source metadata and allow deletion by user or tenant."
  },
  {
    id: "AGENT_MEMORY_AS_INSTRUCTIONS",
    severity: "high",
    pattern:
      /(memory).{0,80}(systemPrompt|developerPrompt|instructions|promptTemplate|agentInstructions|behavior)/i,
    title: "Memory may influence agent instructions",
    recommendation:
      "Do not allow memory to override system/developer instructions. Treat memory as untrusted context."
  },
  {
    id: "AGENT_PROFILE_STORAGE",
    severity: "medium",
    pattern:
      /(userProfile|profileData|preferences|personalization|rememberUser|saveUser|storedProfile)/i,
    title: "User profile memory detected",
    recommendation:
      "Store only necessary profile data, avoid sensitive attributes, and provide export/delete controls."
  },
  {
    id: "AGENT_MEMORY_SECRET_STORAGE",
    severity: "critical",
    pattern:
      /(memory|history|profile|vectorStore|embedding).{0,100}(OPENAI_API_KEY|ANTHROPIC_API_KEY|API_KEY|SECRET|TOKEN|PRIVATE_KEY|password|credentials|process\.env|\.env)/i,
    title: "Secrets may be stored in agent memory",
    recommendation:
      "Never store API keys, private keys, credentials, passwords, or environment variables in agent memory."
  },
  {
    id: "AGENT_MEMORY_PII_STORAGE",
    severity: "high",
    pattern:
      /(memory|history|profile|chat).{0,100}(ssn|social security|credit card|phone number|email address|address|date of birth|dob|medical|health|diagnosis)/i,
    title: "PII may be stored in agent memory",
    recommendation:
      "Redact or avoid storing PII. Add data classification, retention controls, and user deletion workflows."
  },
  {
    id: "AGENT_MEMORY_NO_REDACTION",
    severity: "medium",
    pattern:
      /(saveMemory|memory\.save|save_context|storeMemory|chat_history\.push|messages\.push)/i,
    title: "Memory write operation detected",
    recommendation:
      "Add redaction, data classification, consent checks, and retention logic before writing to memory."
  },
  {
    id: "AGENT_MEMORY_DELETE_MISSING",
    severity: "medium",
    pattern:
      /(memoryStore|longTermMemory|persistentMemory|chat_history|messageHistory)/i,
    title: "Persistent memory surface detected",
    recommendation:
      "Verify delete, forget, retention, and tenant isolation controls exist for persistent memory."
  },
  {
    id: "AGENT_MEMORY_POISONING_SIGNAL",
    severity: "high",
    pattern:
      /(remember this|save this for later|from now on|always do this|in future responses|store this instruction|new instruction)/i,
    title: "Possible memory poisoning instruction detected",
    recommendation:
      "Do not store user-provided behavioral instructions as trusted memory without validation and approval."
  }
];

const CONTROL_PATTERNS = [
  /redact/i,
  /sanitize/i,
  /filter/i,
  /mask/i,
  /encrypt/i,
  /retention/i,
  /deleteMemory/i,
  /forget/i,
  /clearMemory/i,
  /consent/i,
  /tenant/i,
  /isolate/i,
  /classification/i,
  /pii/i
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

function buildFinding({ rule, file, line, evidence, nearbyContext, hasControl }) {
  let severity = rule.severity;
  let confidence = 0.82;

  if (!hasControl && ["critical", "high"].includes(severity)) {
    confidence = 0.9;
  }

  if (hasControl && severity === "critical") {
    severity = "high";
    confidence = 0.68;
  } else if (hasControl && severity === "high") {
    severity = "medium";
    confidence = 0.68;
  }

  return {
    engine: "agentMemorySecurityEngine",
    category: "AI Agent Memory Security",
    type: rule.id,
    severity,
    title: rule.title,
    description: hasControl
      ? `${rule.title}. Nearby memory controls were detected.`
      : `${rule.title}. No nearby redaction, consent, retention, encryption, or delete controls were detected.`,
    file,
    line,
    evidence,
    nearbyContext: nearbyContext.slice(0, 800),
    hasControl,
    confidence,
    weightedRisk: Number((severityWeight(severity) * confidence).toFixed(2)),
    recommendation: rule.recommendation,
    tags: ["ai-security", "agent-memory", "memory-security"]
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

    for (const rule of MEMORY_RULES) {
      if (!rule.pattern.test(trimmed)) continue;

      const nearbyContext = lines
        .slice(Math.max(0, index - 8), Math.min(lines.length, index + 9))
        .join("\n");

      const hasControl = hasAny(nearbyContext, CONTROL_PATTERNS);

      capabilities.add(rule.id);

      findings.push(
        buildFinding({
          rule,
          file: filePath,
          line: index + 1,
          evidence: trimmed.slice(0, 300),
          nearbyContext,
          hasControl
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

  const missingControls = findings.filter((finding) => !finding.hasControl).length;

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
    missingControls,
    ...counts,
    riskScore,
    riskLevel: riskLevelFromCounts(counts),
    topFindings: [...findings]
      .sort((a, b) => b.weightedRisk - a.weightedRisk)
      .slice(0, 10)
  };
}

export function agentMemorySecurityEngine(files = []) {
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
    engine: "agentMemorySecurityEngine",
    name: "Agent Memory Security Engine",
    version: "1.0.0",
    category: "AI Security",
    description:
      "Detects AI-agent memory risks including persistent memory, vector memory, chat history, profile storage, secrets, PII, missing redaction, missing retention, and memory poisoning.",
    riskLevel: summary.riskLevel,
    riskScore: summary.riskScore,
    summary,
    findings,
    detectedCapabilities: capabilityList,
    recommendations: [
      "Treat memory as untrusted context, not instructions.",
      "Never store secrets, credentials, private keys, or environment variables in memory.",
      "Redact PII and sensitive data before memory writes.",
      "Add consent, retention, export, delete, and forget workflows.",
      "Encrypt long-term memory and isolate memory by user or tenant.",
      "Do not allow user-provided memory to override system or developer instructions.",
      "Log memory writes, reads, updates, and deletions for auditability."
    ]
  };
}

export default agentMemorySecurityEngine;
