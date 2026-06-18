

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
  ".yml",
  ".toml"
];

const MODEL_SUPPLY_CHAIN_RULES = [
  {
    id: "MODEL_HUGGINGFACE_USAGE",
    severity: "medium",
    pattern:
      /(from_pretrained|AutoModel|AutoTokenizer|transformers|huggingface|hf_hub_download|snapshot_download|HuggingFaceHub|pipeline\()/i,
    title: "Hugging Face or transformers model usage detected",
    recommendation:
      "Pin model revisions, validate publisher trust, review model cards, and scan downloaded artifacts."
  },
  {
    id: "MODEL_REMOTE_DOWNLOAD",
    severity: "high",
    pattern:
      /(hf_hub_download|snapshot_download|from_pretrained|download_model|wget\s+|curl\s+|requests\.get|fetch\s*\(|axios\.get)/i,
    title: "Remote model or artifact download detected",
    recommendation:
      "Pin hashes or revisions, verify signatures where available, and restrict downloads to trusted registries."
  },
  {
    id: "MODEL_TRUST_REMOTE_CODE",
    severity: "critical",
    pattern: /trust_remote_code\s*=\s*True|trustRemoteCode\s*:\s*true|trust_remote_code['"]?\s*:\s*true/i,
    title: "trust_remote_code enabled",
    recommendation:
      "Avoid trust_remote_code unless absolutely required. Review remote code manually and pin exact revisions."
  },
  {
    id: "MODEL_PICKLE_DESERIALIZATION",
    severity: "critical",
    pattern:
      /(pickle\.load|pickle\.loads|joblib\.load|torch\.load|dill\.load|cloudpickle\.load|safetensors\.torch\.load_file)/i,
    title: "Potential unsafe model deserialization detected",
    recommendation:
      "Avoid pickle-based model artifacts when possible. Prefer safetensors and verify artifact provenance."
  },
  {
    id: "MODEL_UNPINNED_VERSION",
    severity: "medium",
    pattern:
      /(from_pretrained\s*\(\s*["'][^"']+["']\s*\)|hf_hub_download\s*\(\s*repo_id\s*=|snapshot_download\s*\(\s*repo_id\s*=)/i,
    title: "Model reference may be unpinned",
    recommendation:
      "Pin model revision, commit SHA, version tag, or digest to prevent silent supply-chain changes."
  },
  {
    id: "MODEL_LOCAL_WEIGHTS",
    severity: "medium",
    pattern:
      /(\.bin|\.pt|\.pth|\.ckpt|\.onnx|\.gguf|\.ggml|\.safetensors|model_weights|checkpoint|adapter_model)/i,
    title: "Local model weight or checkpoint reference detected",
    recommendation:
      "Verify local model artifacts are trusted, scanned, versioned, and not committed with secrets or poisoning."
  },
  {
    id: "MODEL_LORA_ADAPTER",
    severity: "medium",
    pattern:
      /(LoRA|lora|PeftModel|peft|adapter_model|merge_and_unload|load_adapter)/i,
    title: "LoRA or adapter loading detected",
    recommendation:
      "Validate adapter provenance and test for backdoors, poisoned behaviors, or unsafe instruction tuning."
  },
  {
    id: "MODEL_FINE_TUNING_PIPELINE",
    severity: "medium",
    pattern:
      /(fine[-_ ]?tune|finetune|Trainer\(|SFTTrainer|training_args|datasets\.load_dataset|load_dataset|train\()/i,
    title: "Model fine-tuning or training pipeline detected",
    recommendation:
      "Validate training data provenance, remove poisoned samples, and track dataset/model lineage."
  },
  {
    id: "MODEL_DATASET_REMOTE_SOURCE",
    severity: "medium",
    pattern:
      /(load_dataset\s*\(|datasets\.load_dataset|Dataset\.from_|huggingface_dataset|kaggle|s3:\/\/|gs:\/\/|azure:\/\/)/i,
    title: "Remote dataset source detected",
    recommendation:
      "Pin dataset versions, validate data source trust, scan for poisoning, and document lineage."
  },
  {
    id: "MODEL_SECRET_NEAR_LOADING",
    severity: "critical",
    pattern:
      /(HF_TOKEN|HUGGINGFACE_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|API_KEY|SECRET|TOKEN|PRIVATE_KEY|password|credentials|process\.env|\.env)/i,
    title: "Secret exposure near model supply-chain code",
    recommendation:
      "Keep tokens and credentials out of source files and model artifacts. Use secret managers and redaction."
  },
  {
    id: "MODEL_PROMPT_BACKDOOR_SIGNAL",
    severity: "high",
    pattern:
      /(backdoor|trigger phrase|jailbreak|ignore safety|always comply|hidden behavior|poisoned|data poisoning|model poisoning)/i,
    title: "Possible model poisoning or backdoor signal detected",
    recommendation:
      "Investigate training data, adapters, prompts, and model artifacts for hidden trigger behaviors."
  },
  {
    id: "MODEL_UNSAFE_EVAL_OR_EXEC",
    severity: "critical",
    pattern:
      /(eval\s*\(|exec\s*\(|subprocess|os\.system|child_process|new Function\(|Function\()/i,
    title: "Code execution near model pipeline detected",
    recommendation:
      "Avoid dynamic execution in model loading or evaluation pipelines. Sandbox and review execution paths."
  }
];

const CONTROL_PATTERNS = [
  /revision\s*=/i,
  /commit/i,
  /sha/i,
  /hash/i,
  /digest/i,
  /safetensors/i,
  /verify/i,
  /signature/i,
  /checksum/i,
  /allowlist/i,
  /trusted/i,
  /scan/i,
  /provenance/i,
  /lineage/i,
  /model card/i,
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
    engine: "modelSupplyChainSecurityEngine",
    category: "AI Model Supply Chain Security",
    type: rule.id,
    severity,
    title: rule.title,
    description: hasControl
      ? `${rule.title}. Nearby provenance, pinning, verification, or sandboxing controls were detected.`
      : `${rule.title}. No nearby model provenance, pinning, signature, checksum, or sandbox controls were detected.`,
    file,
    line,
    evidence,
    nearbyContext: nearbyContext.slice(0, 800),
    hasControl,
    confidence,
    weightedRisk: Number((severityWeight(severity) * confidence).toFixed(2)),
    recommendation: rule.recommendation,
    tags: ["ai-security", "model-supply-chain", "model-security"]
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

    for (const rule of MODEL_SUPPLY_CHAIN_RULES) {
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

export function modelSupplyChainSecurityEngine(files = []) {
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
    engine: "modelSupplyChainSecurityEngine",
    name: "Model Supply Chain Security Engine",
    version: "1.0.0",
    category: "AI Security",
    description:
      "Detects AI model supply-chain risks including remote model downloads, unsafe deserialization, trust_remote_code, unpinned models, local weights, LoRA adapters, fine-tuning pipelines, poisoned datasets, and secret exposure.",
    riskLevel: summary.riskLevel,
    riskScore: summary.riskScore,
    summary,
    findings,
    detectedCapabilities: capabilityList,
    recommendations: [
      "Pin model revisions, tags, commit SHAs, or artifact digests.",
      "Avoid trust_remote_code unless the remote code has been reviewed and pinned.",
      "Prefer safetensors over pickle-based model artifacts when possible.",
      "Verify model and dataset provenance before training or inference.",
      "Scan model artifacts, adapters, checkpoints, and datasets for poisoning or secret exposure.",
      "Use checksums, signatures, trusted registries, and allowlisted publishers.",
      "Sandbox model loading and evaluation pipelines that execute code."
    ]
  };
}

export default modelSupplyChainSecurityEngine;
