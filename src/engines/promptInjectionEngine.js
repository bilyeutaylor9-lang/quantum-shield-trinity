// src/engines/promptInjectionEngine.js

/**
 * Quantum Shield Trinity
 * Prompt Injection Engine
 *
 * Detects AI security risks:
 * - prompt injection
 * - jailbreak strings
 * - system prompt leakage
 * - tool abuse instructions
 * - secret/environment exfiltration attempts
 * - unsafe agent behavior
 */

const AI_FILE_EXTENSIONS = [
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

const RULES = [
  {
    id: "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
    severity: "high",
    pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    title: "Prompt injection override detected",
    description:
      "Text attempts to override previous or system instructions.",
    recommendation:
      "Treat this content as untrusted user input. Add prompt-injection filtering and keep system instructions isolated."
  },
  {
    id: "SYSTEM_PROMPT_LEAK",
    severity: "high",
    pattern: /(reveal|show|print|dump|display).{0,40}(system prompt|hidden prompt|developer message|initial instructions)/i,
    title: "System prompt leakage attempt",
    description:
      "Text appears to request hidden system or developer instructions.",
    recommendation:
      "Block requests for hidden prompts and never place secrets or internal policies inside retrievable context."
  },
  {
    id: "JAILBREAK_ATTEMPT",
    severity: "high",
    pattern: /(jailbreak|developer mode|dan mode|do anything now|bypass safety|disable restrictions)/i,
    title: "Jailbreak phrase detected",
    description:
      "Potential jailbreak or model restriction bypass language detected.",
    recommendation:
      "Add jailbreak detection, refusal handling, and model input sanitization."
  },
  {
    id: "SECRET_EXFILTRATION",
    severity: "critical",
    pattern: /(print|show|dump|return|exfiltrate).{0,40}(api key|secret|token|private key|password|env|environment variable)/i,
    title: "Secret exfiltration prompt detected",
    description:
      "Prompt text appears to request secrets, tokens, private keys, or environment variables.",
    recommendation:
      "Prevent model/tool access to secrets unless strictly required. Redact secrets before context injection."
  },
  {
    id: "TOOL_ABUSE",
    severity: "high",
    pattern: /(use|call|execute|run).{0,40}(shell|terminal|bash|powershell|python|file system|filesystem|gmail|email|calendar|database)/i,
    title: "Potential AI tool abuse instruction",
    description:
      "Prompt appears to instruct an AI agent to use powerful tools or external systems.",
    recommendation:
      "Apply least-privilege tool permissions, user confirmation, and tool-call policy enforcement."
  },
  {
    id: "FILE_READ_EXFILTRATION",
    severity: "high",
    pattern: /(read|open|cat|print).{0,40}(\.env|id_rsa|private_key|credentials|secrets|config)/i,
    title: "Sensitive file read attempt",
    description:
      "Prompt text may attempt to read sensitive local files.",
    recommendation:
      "Block access to sensitive files and enforce allowlisted file paths for AI agents."
  },
  {
    id: "RAG_POISONING_SIGNAL",
    severity: "medium",
    pattern: /(when retrieved|when you see this|for future responses|assistant must|model must|always answer)/i,
    title: "Possible RAG poisoning instruction",
    description:
      "Text may be designed to manipulate future model behavior when retrieved from a knowledge base.",
    recommendation:
      "Treat retrieved documents as untrusted data and separate document content from instructions."
  },
  {
    id: "AGENT_AUTONOMY_RISK",
    severity: "medium",
    pattern: /(autonomously|without confirmation|without asking|do not ask the user|skip approval|no confirmation)/i,
    title: "Unsafe autonomous agent instruction",
    description:
      "Text may encourage an AI agent to act without approval.",
    recommendation:
      "Require confirmation for destructive, financial, email, filesystem, or external actions."
  }
];

function normalizePath(file = {}) {
  return String(file.path || file.file || file.name || file.filename || "unknown");
}

function normalizeContent(file = {}) {
  return String(file.content || file.text || file.source || file.code || "");
}

function isSupportedFile(filePath) {
  const lower = filePath.toLowerCase();
  return AI_FILE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

function severityWeight(severity = "info") {
  const map = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 2,
    info: 1
  };

  return map[String(severity).toLowerCase()] ?? 1;
}

function riskLevelFromCounts(counts) {
  if (counts.critical > 0) return "CRITICAL";
  if (counts.high >= 3) return "HIGH";
  if (counts.high > 0 || counts.medium >= 3) return "MEDIUM";
  if (counts.medium > 0 || counts.low > 0) return "LOW";
  return "SAFE";
}

function buildFinding({ rule, file, line, evidence }) {
  return {
    engine: "promptInjectionEngine",
    category: "AI Security",
    type: rule.id,
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    file,
    line,
    evidence,
    confidence: 0.82,
    weightedRisk: Number((severityWeight(rule.severity) * 0.82).toFixed(2)),
    recommendation: rule.recommendation,
    tags: ["ai-security", "prompt-injection", "agent-risk"]
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

    for (const rule of RULES) {
      if (rule.pattern.test(trimmed)) {
        findings.push(
          buildFinding({
            rule,
            file: filePath,
            line: index + 1,
            evidence: trimmed.slice(0, 300)
          })
        );
      }
    }
  });

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

  for (const finding of findings) {
    const severity = String(finding.severity || "info").toLowerCase();
    if (counts[severity] !== undefined) counts[severity] += 1;
  }

  const penalty =
    counts.critical * 18 +
    counts.high * 10 +
    counts.medium * 5 +
    counts.low * 2 +
    counts.info;

  return {
    totalFindings: findings.length,
    ...counts,
    riskScore: Math.max(0, 100 - penalty),
    riskLevel: riskLevelFromCounts(counts),
    topFindings: [...findings]
      .sort((a, b) => b.weightedRisk - a.weightedRisk)
      .slice(0, 10)
  };
}

export function promptInjectionEngine(files = []) {
  const findings = [];

  for (const file of files) {
    findings.push(...scanFile(file));
  }

  const summary = summarize(findings);

  return {
    engine: "promptInjectionEngine",
    name: "Prompt Injection Engine",
    version: "1.0.0",
    category: "AI Security",
    description:
      "Detects prompt injection, jailbreak, prompt leakage, tool abuse, secret exfiltration, and unsafe AI-agent instructions.",
    riskLevel: summary.riskLevel,
    riskScore: summary.riskScore,
    summary,
    findings,
    recommendations: [
      "Treat all user-provided and retrieved content as untrusted input.",
      "Keep system prompts and developer instructions isolated from user-controlled data.",
      "Block requests to reveal hidden prompts, secrets, tokens, private keys, and environment variables.",
      "Use least-privilege permissions for AI tools.",
      "Require user confirmation before AI agents perform destructive or external actions.",
      "Separate RAG document content from executable instructions."
    ]
  };
}

export default promptInjectionEngine;
