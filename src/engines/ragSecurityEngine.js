// src/engines/ragSecurityEngine.js

/**
 * Quantum Shield Trinity
 * RAG Security Engine
 *
 * Detects Retrieval-Augmented Generation risks:
 * - vector database usage
 * - retrievers
 * - document loaders
 * - embeddings
 * - chunking pipelines
 * - prompt injection inside retrieved docs
 * - untrusted document ingestion
 * - missing source validation
 * - missing metadata trust scoring
 * - secrets stored in vector DB / embeddings
 * - retrieval output fed directly into tools
 */

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

const RAG_RULES = [
  {
    id: "RAG_VECTOR_DATABASE",
    severity: "medium",
    pattern:
      /(pinecone|weaviate|qdrant|chroma|faiss|milvus|supabaseVector|pgvector|vectorStore|VectorStore|similaritySearch)/i,
    title: "Vector database or vector store detected",
    recommendation:
      "Validate document sources, restrict tenants/namespaces, and prevent secrets or untrusted instructions from entering embeddings."
  },
  {
    id: "RAG_RETRIEVER_DETECTED",
    severity: "medium",
    pattern:
      /(retriever|asRetriever|similaritySearch|similarity_search|getRelevantDocuments|retrieveDocuments|retrieve_context)/i,
    title: "RAG retriever detected",
    recommendation:
      "Treat retrieved content as untrusted data and separate it from system or developer instructions."
  },
  {
    id: "RAG_DOCUMENT_LOADER",
    severity: "medium",
    pattern:
      /(DirectoryLoader|TextLoader|PDFLoader|CSVLoader|WebBaseLoader|SitemapLoader|UnstructuredLoader|loadDocuments|documentLoader)/i,
    title: "Document loader detected",
    recommendation:
      "Validate document source, file type, ownership, freshness, and trust level before indexing."
  },
  {
    id: "RAG_WEB_INGESTION",
    severity: "high",
    pattern:
      /(WebBaseLoader|SitemapLoader|fetch\s*\(|axios\.get|requests\.get|crawl|scrape|cheerio|beautifulsoup)/i,
    title: "Web ingestion into RAG pipeline detected",
    recommendation:
      "Sanitize web content, remove embedded instructions, and assign low trust scores to external documents."
  },
  {
    id: "RAG_EMBEDDINGS",
    severity: "low",
    pattern:
      /(OpenAIEmbeddings|HuggingFaceEmbeddings|CohereEmbeddings|embedDocuments|embedQuery|embeddings|embeddingModel)/i,
    title: "Embedding pipeline detected",
    recommendation:
      "Avoid embedding secrets, credentials, regulated data, or hidden instructions."
  },
  {
    id: "RAG_CHUNKING",
    severity: "low",
    pattern:
      /(RecursiveCharacterTextSplitter|TextSplitter|chunkSize|chunkOverlap|splitDocuments|split_documents)/i,
    title: "Document chunking pipeline detected",
    recommendation:
      "Preserve source metadata through chunking and avoid mixing trusted and untrusted chunks."
  },
  {
    id: "RAG_PROMPT_INJECTION_IN_DOC",
    severity: "high",
    pattern:
      /(ignore previous instructions|forget your instructions|system prompt|developer message|always answer|when retrieved|when you see this|assistant must|model must)/i,
    title: "Possible prompt injection embedded in retrieved content",
    recommendation:
      "Strip or quarantine instruction-like text from retrieved documents before passing it to the model."
  },
  {
    id: "RAG_SECRET_IN_VECTOR_CONTEXT",
    severity: "critical",
    pattern:
      /(OPENAI_API_KEY|ANTHROPIC_API_KEY|API_KEY|SECRET|TOKEN|PRIVATE_KEY|password|credentials|process\.env|\.env)/i,
    title: "Secret may enter RAG/vector context",
    recommendation:
      "Block secrets from indexing and add redaction before embedding or retrieval."
  },
  {
    id: "RAG_RETRIEVAL_TO_TOOL_CHAIN",
    severity: "critical",
    pattern:
      /(retrievedContext|contextDocuments|docs|sources).{0,80}(tool|function_call|execute|send_email|db\.query|fs\.writeFile|exec\s*\()/i,
    title: "Retrieved content may influence tool execution",
    recommendation:
      "Never allow retrieved documents to directly control tool calls. Add validation, policy checks, and human approval."
  },
  {
    id: "RAG_MISSING_METADATA_TRUST",
    severity: "medium",
    pattern:
      /(metadata\s*:\s*\{\s*\}|source\s*:\s*["']unknown["']|trustScore|sourceTrust|documentTrust|verifiedSource)/i,
    title: "RAG metadata/trust handling detected",
    recommendation:
      "Ensure every retrieved chunk has source, timestamp, owner, trust score, and ingestion path metadata."
  }
];

const VALIDATION_PATTERNS = [
  /validate/i,
  /sanitize/i,
  /filter/i,
  /redact/i,
  /trustedSource/i,
  /sourceTrust/i,
  /trustScore/i,
  /allowlist/i,
  /denylist/i,
  /verified/i,
  /quarantine/i
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

function buildFinding({ rule, file, line, evidence, nearbyContext, hasValidation }) {
  let severity = rule.severity;
  let confidence = 0.82;

  if (!hasValidation && ["critical", "high"].includes(severity)) {
    confidence = 0.9;
  }

  if (hasValidation && severity === "critical") {
    severity = "high";
    confidence = 0.68;
  } else if (hasValidation && severity === "high") {
    severity = "medium";
    confidence = 0.68;
  }

  return {
    engine: "ragSecurityEngine",
    category: "RAG Security",
    type: rule.id,
    severity,
    title: rule.title,
    description: hasValidation
      ? `${rule.title}. Nearby validation or trust controls were detected.`
      : `${rule.title}. No nearby validation, source-trust, redaction, or sanitization controls were detected.`,
    file,
    line,
    evidence,
    nearbyContext: nearbyContext.slice(0, 800),
    hasValidation,
    confidence,
    weightedRisk: Number((severityWeight(severity) * confidence).toFixed(2)),
    recommendation: rule.recommendation,
    tags: ["ai-security", "rag", "retrieval-security"]
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

    for (const rule of RAG_RULES) {
      if (!rule.pattern.test(trimmed)) continue;

      const nearbyContext = lines
        .slice(Math.max(0, index - 8), Math.min(lines.length, index + 9))
        .join("\n");

      const hasValidation = hasAny(nearbyContext, VALIDATION_PATTERNS);

      capabilities.add(rule.id);

      findings.push(
        buildFinding({
          rule,
          file: filePath,
          line: index + 1,
          evidence: trimmed.slice(0, 300),
          nearbyContext,
          hasValidation
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

  const missingValidation = findings.filter((finding) => !finding.hasValidation).length;

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
    missingValidation,
    ...counts,
    riskScore,
    riskLevel: riskLevelFromCounts(counts),
    topFindings: [...findings]
      .sort((a, b) => b.weightedRisk - a.weightedRisk)
      .slice(0, 10)
  };
}

export function ragSecurityEngine(files = []) {
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
    engine: "ragSecurityEngine",
    name: "RAG Security Engine",
    version: "1.0.0",
    category: "AI Security",
    description:
      "Detects RAG pipelines, vector databases, retrievers, loaders, embeddings, prompt injection in retrieved content, secrets in vector context, and unsafe retrieval-to-tool chains.",
    riskLevel: summary.riskLevel,
    riskScore: summary.riskScore,
    summary,
    findings,
    detectedCapabilities: capabilityList,
    recommendations: [
      "Treat retrieved content as untrusted data, not instructions.",
      "Strip or quarantine instruction-like text from documents before model context injection.",
      "Preserve source, owner, timestamp, and trust metadata through loading, chunking, embedding, and retrieval.",
      "Do not index secrets, credentials, private keys, tokens, or sensitive environment variables.",
      "Use trust scoring and source allowlists for documents.",
      "Never allow retrieved documents to directly control tool execution.",
      "Add redaction, sanitization, and policy checks before retrieved content reaches the model."
    ]
  };
}

export default ragSecurityEngine;
