// src/engines/reactiveSecurityEngine.js

/**
 * Quantum Shield Trinity
 * Reactive Security Engine
 *
 * Purpose:
 * Detects Reactive Network specific risks in Solidity contracts:
 * - Reactive callbacks
 * - event subscription exposure
 * - callback authorization gaps
 * - hardcoded callback/service addresses
 * - cross-chain execution assumptions
 * - gas griefing risk
 * - automation failure risk
 * - owner/admin control over reactive execution
 */

const DEFAULT_CONFIDENCE = {
  low: 0.35,
  medium: 0.6,
  high: 0.82,
  certain: 0.95
};

function normalizeContent(file = {}) {
  return String(file.content || file.source || file.code || "");
}

function normalizePath(file = {}) {
  return String(file.path || file.file || file.name || "unknown.sol");
}

function getLines(content) {
  return String(content || "").split(/\r?\n/);
}

function hasAny(text, patterns = []) {
  return patterns.some((pattern) => pattern.test(text));
}

function severityWeight(severity) {
  const map = {
    info: 1,
    low: 2,
    medium: 4,
    high: 7,
    critical: 10
  };

  return map[String(severity || "info").toLowerCase()] || 1;
}

function buildFinding({
  severity = "medium",
  type,
  title,
  description,
  file,
  line,
  evidence,
  recommendation,
  confidence = DEFAULT_CONFIDENCE.medium,
  tags = []
}) {
  return {
    engine: "reactiveSecurityEngine",
    category: "Reactive Security",
    severity,
    type,
    title,
    description,
    file,
    line,
    evidence,
    recommendation,
    confidence,
    weightedRisk: Number((severityWeight(severity) * confidence).toFixed(2)),
    tags
  };
}

function detectReactiveContext(content) {
  return hasAny(content, [
    /\bIReactive\b/,
    /\bReactiveSubscriber\b/,
    /\bReactiveCallback\b/,
    /\breactiveCallback\b/,
    /\bcallback\b/i,
    /\bsubscribe\b/i,
    /\bunsubscribe\b/i,
    /\bemit\s+\w+/,
    /\bchainId\b/,
    /\boriginChainId\b/,
    /\bdestinationChainId\b/,
    /\bvm\.callback\b/,
    /\bCallbackProxy\b/i
  ]);
}

function scanFile(file) {
  const content = normalizeContent(file);
  const filePath = normalizePath(file);
  const lines = getLines(content);
  const findings = [];

  if (!content.trim()) return findings;

  const isReactiveContract = detectReactiveContext(content);

  lines.forEach((lineText, index) => {
    const line = index + 1;
    const text = lineText.trim();

    if (!text || text.startsWith("//")) return;

    // 1. Reactive callback without obvious access control
    if (
      /\breactiveCallback\s*\(/.test(text) ||
      /\bcallback\s*\(/i.test(text)
    ) {
      const nearby = lines.slice(Math.max(0, index - 5), index + 8).join("\n");

      const hasAccessControl = hasAny(nearby, [
        /\bonlyOwner\b/,
        /\bonlyRole\b/,
        /\brequire\s*\(\s*msg\.sender\s*==/,
        /\brequire\s*\(\s*authorized/,
        /\brequire\s*\(\s*isAuthorized/,
        /\bAccessControl\b/,
        /\bOwnable\b/,
        /\bmsg\.sender\s*==\s*callback/i,
        /\bmsg\.sender\s*==\s*CALLBACK/i
      ]);

      if (!hasAccessControl) {
        findings.push(
          buildFinding({
            severity: "high",
            type: "REACTIVE_CALLBACK_ACCESS_CONTROL",
            title: "Reactive callback may lack access control",
            description:
              "A reactive callback-like function was detected without nearby owner, role, sender, or authorization checks.",
            file: filePath,
            line,
            evidence: text,
            recommendation:
              "Restrict callback execution to the trusted Reactive callback proxy, authorized executor, or role-based access control.",
            confidence: DEFAULT_CONFIDENCE.high,
            tags: ["reactive", "callback", "access-control"]
          })
        );
      }
    }

    // 2. Public/external reactive execution function
    if (
      /\bfunction\b/.test(text) &&
      /\b(public|external)\b/.test(text) &&
      hasAny(text, [
        /\breactive/i,
        /\bcallback/i,
        /\bexecute/i,
        /\bhandle/i,
        /\bonMessage/i,
        /\bonEvent/i
      ])
    ) {
      findings.push(
        buildFinding({
          severity: "medium",
          type: "PUBLIC_REACTIVE_EXECUTION_SURFACE",
          title: "Public reactive execution surface detected",
          description:
            "A public or external function appears related to reactive execution and should be reviewed for authorization, replay protection, and input validation.",
          file: filePath,
          line,
          evidence: text,
          recommendation:
            "Validate msg.sender, source chain, event origin, payload integrity, and replay protection before executing state changes.",
          confidence: DEFAULT_CONFIDENCE.medium,
          tags: ["reactive", "public-function", "execution"]
        })
      );
    }

    // 3. Hardcoded callback/service address
    if (
      /\baddress\b/.test(text) &&
      /(0x[a-fA-F0-9]{40})/.test(text) &&
      hasAny(text, [
        /callback/i,
        /proxy/i,
        /service/i,
        /system/i,
        /reactive/i,
        /origin/i,
        /destination/i
      ])
    ) {
      findings.push(
        buildFinding({
          severity: "medium",
          type: "HARDCODED_REACTIVE_ADDRESS",
          title: "Hardcoded Reactive-related address",
          description:
            "A hardcoded address appears to control callback, proxy, service, or reactive execution behavior.",
          file: filePath,
          line,
          evidence: text,
          recommendation:
            "Confirm this address is network-specific, documented, upgrade-safe, and cannot cause misrouting across deployments.",
          confidence: DEFAULT_CONFIDENCE.medium,
          tags: ["reactive", "hardcoded-address", "deployment-risk"]
        })
      );
    }

    // 4. Chain ID assumptions
    if (
      hasAny(text, [
        /\bchainId\b/,
        /\bblock\.chainid\b/,
        /\boriginChainId\b/,
        /\bdestinationChainId\b/,
        /\bsourceChain\b/,
        /\btargetChain\b/
      ])
    ) {
      const nearby = lines.slice(Math.max(0, index - 4), index + 6).join("\n");

      const validatesChain = hasAny(nearby, [
        /\brequire\s*\(/,
        /\brevert\b/,
        /\bif\s*\(/,
        /\ballowedChain\b/i,
        /\bsupportedChain\b/i,
        /\btrustedChain\b/i
      ]);

      if (!validatesChain) {
        findings.push(
          buildFinding({
            severity: "medium",
            type: "CHAIN_TRUST_ASSUMPTION",
            title: "Cross-chain trust assumption detected",
            description:
              "The contract references chain identity without nearby validation logic.",
            file: filePath,
            line,
            evidence: text,
            recommendation:
              "Add explicit validation for supported source chains, destination chains, and trusted reactive origins.",
            confidence: DEFAULT_CONFIDENCE.medium,
            tags: ["cross-chain", "reactive", "trust-boundary"]
          })
        );
      }
    }

    // 5. Event-driven execution risk
    if (/\bemit\s+\w+/.test(text) && isReactiveContract) {
      findings.push(
        buildFinding({
          severity: "low",
          type: "EVENT_DRIVEN_EXECUTION_POINT",
          title: "Event may trigger reactive execution",
          description:
            "This event may be part of a reactive execution flow. Event parameters should be resistant to spoofing and unsafe automation.",
          file: filePath,
          line,
          evidence: text,
          recommendation:
            "Ensure subscribers validate event origin, indexed parameters, chain context, and replay conditions.",
          confidence: DEFAULT_CONFIDENCE.low,
          tags: ["event", "reactive", "automation"]
        })
      );
    }

    // 6. Gas griefing risk
    if (
      isReactiveContract &&
      hasAny(text, [
        /\bfor\s*\(/,
        /\bwhile\s*\(/,
        /\.length\b/,
        /\bpush\s*\(/,
        /\bdelete\b/
      ])
    ) {
      findings.push(
        buildFinding({
          severity: "medium",
          type: "REACTIVE_GAS_GRIEFING_RISK",
          title: "Potential gas griefing in reactive flow",
          description:
            "Loops or dynamic storage operations inside reactive contracts may create gas griefing or callback failure risk.",
          file: filePath,
          line,
          evidence: text,
          recommendation:
            "Bound loops, cap array sizes, avoid untrusted iteration, and design callbacks to fail safely.",
          confidence: DEFAULT_CONFIDENCE.medium,
          tags: ["reactive", "gas", "dos"]
        })
      );
    }

    // 7. Owner/admin control over execution
    if (
      isReactiveContract &&
      hasAny(text, [
        /\bonlyOwner\b/,
        /\bowner\s*\(/,
        /\btransferOwnership\b/,
        /\bDEFAULT_ADMIN_ROLE\b/,
        /\bonlyRole\b/
      ])
    ) {
      findings.push(
        buildFinding({
          severity: "medium",
          type: "REACTIVE_ADMIN_CONTROL",
          title: "Admin control in Reactive contract",
          description:
            "Owner or admin privileges appear to affect a reactive contract. This may be acceptable, but should be reviewed as a trust boundary.",
          file: filePath,
          line,
          evidence: text,
          recommendation:
            "Document admin capabilities, consider multisig/timelock control, and include emergency pause procedures.",
          confidence: DEFAULT_CONFIDENCE.low,
          tags: ["reactive", "admin", "trust-boundary"]
        })
      );
    }

    // 8. Missing pause/emergency controls
    if (
      isReactiveContract &&
      hasAny(text, [
        /\bexecute\b/i,
        /\bcallback\b/i,
        /\breactive\b/i
      ])
    ) {
      const contractHasPause = hasAny(content, [
        /\bPausable\b/,
        /\bwhenNotPaused\b/,
        /\bemergencyPause\b/,
        /\bpause\s*\(/,
        /\bunpause\s*\(/
      ]);

      if (!contractHasPause) {
        findings.push(
          buildFinding({
            severity: "low",
            type: "MISSING_REACTIVE_PAUSE_CONTROL",
            title: "Reactive contract may lack pause control",
            description:
              "A reactive execution surface was detected, but no obvious pause or emergency stop control was found.",
            file: filePath,
            line,
            evidence: text,
            recommendation:
              "Consider adding Pausable, emergency stop, or circuit breaker logic for automated execution failures.",
            confidence: DEFAULT_CONFIDENCE.low,
            tags: ["reactive", "pause", "resilience"]
          })
        );
      }
    }

    // 9. External calls in reactive context
    if (
      isReactiveContract &&
      hasAny(text, [
        /\.call\s*\{/,
        /\.call\s*\(/,
        /\.delegatecall\s*\(/,
        /\.staticcall\s*\(/,
        /\btransfer\s*\(/,
        /\bsend\s*\(/
      ])
    ) {
      findings.push(
        buildFinding({
          severity: "high",
          type: "EXTERNAL_CALL_IN_REACTIVE_FLOW",
          title: "External call inside Reactive flow",
          description:
            "External calls inside reactive execution can create reentrancy, callback failure, or chained exploit risk.",
          file: filePath,
          line,
          evidence: text,
          recommendation:
            "Use checks-effects-interactions, reentrancy protection, strict target allowlists, and failure isolation.",
          confidence: DEFAULT_CONFIDENCE.high,
          tags: ["reactive", "external-call", "reentrancy"]
        })
      );
    }

    // 10. Unvalidated payload decoding
    if (
      isReactiveContract &&
      hasAny(text, [
        /\babi\.decode\b/,
        /\bbytes\b/,
        /\bcalldata\b/,
        /\bpayload\b/i,
        /\bdata\b/i
      ])
    ) {
      const nearby = lines.slice(Math.max(0, index - 5), index + 8).join("\n");

      const hasValidation = hasAny(nearby, [
        /\brequire\s*\(/,
        /\brevert\b/,
        /\.length\b/,
        /\bhash\b/i,
        /\bsignature\b/i,
        /\bverify\b/i,
        /\btrusted\b/i
      ]);

      if (!hasValidation) {
        findings.push(
          buildFinding({
            severity: "medium",
            type: "UNVALIDATED_REACTIVE_PAYLOAD",
            title: "Reactive payload may be insufficiently validated",
            description:
              "Payload or calldata handling was detected without obvious nearby validation.",
            file: filePath,
            line,
            evidence: text,
            recommendation:
              "Validate payload length, source, schema, replay status, and expected message hash before decoding or execution.",
            confidence: DEFAULT_CONFIDENCE.medium,
            tags: ["reactive", "payload", "input-validation"]
          })
        );
      }
    }
  });

  return findings;
}

function summarize(findings = []) {
  const summary = {
    totalFindings: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    riskScore: 100,
    riskLevel: "LOW",
    topRisks: []
  };

  for (const finding of findings) {
    const sev = String(finding.severity || "info").toLowerCase();
    if (summary[sev] !== undefined) summary[sev] += 1;
  }

  const penalty =
    summary.critical * 18 +
    summary.high * 10 +
    summary.medium * 5 +
    summary.low * 2 +
    summary.info;

  summary.riskScore = Math.max(0, 100 - penalty);

  if (summary.critical > 0 || summary.riskScore < 40) {
    summary.riskLevel = "CRITICAL";
  } else if (summary.high >= 3 || summary.riskScore < 60) {
    summary.riskLevel = "HIGH";
  } else if (summary.high > 0 || summary.medium >= 3 || summary.riskScore < 80) {
    summary.riskLevel = "MEDIUM";
  } else {
    summary.riskLevel = "LOW";
  }

  summary.topRisks = [...findings]
    .sort((a, b) => b.weightedRisk - a.weightedRisk)
    .slice(0, 10);

  return summary;
}

export function reactiveSecurityEngine(input = {}) {
  const files =
    input.files ||
    input.scannedFiles ||
    input.contracts ||
    input.items ||
    [];

  const findings = [];

  for (const file of files) {
    const filePath = normalizePath(file);

    if (!filePath.endsWith(".sol")) continue;

    const fileFindings = scanFile(file);
    findings.push(...fileFindings);
  }

  const summary = summarize(findings);

  return {
    engine: "reactiveSecurityEngine",
    name: "Reactive Security Engine",
    version: "1.0.0",
    description:
      "Detects Reactive Network callback, automation, cross-chain, and event-driven smart contract risks.",
    summary,
    findings,
    recommendations: [
      "Restrict reactive callbacks to trusted Reactive callback proxies or authorized executors.",
      "Validate source chain, destination chain, event origin, and message payloads.",
      "Avoid unbounded loops and unsafe external calls inside reactive execution paths.",
      "Add pause, emergency stop, and failure-isolation controls for automated execution.",
      "Document hardcoded Reactive service addresses and ensure they match the deployment network.",
      "Use multisig or timelock protection for privileged reactive administration."
    ]
  };
}

export default reactiveSecurityEngine;
