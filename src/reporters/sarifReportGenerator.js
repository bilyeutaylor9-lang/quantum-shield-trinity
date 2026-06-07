export function sarifReportGenerator(report = {}) {
  const findings = collectFindings(report);

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Quantum Shield Trinity",
            version: report.version ?? "1.3.0",
            informationUri:
              "https://github.com/bilyeutaylor9-lang/quantum-shield-trinity",
            rules: buildRules(findings)
          }
        },
        results: findings.map(toSarifResult)
      }
    ]
  };
}

function collectFindings(report = {}) {
  const findings = [];

  addFindings(findings, report.findings, "repository");
  addFindings(findings, report.dependencyReport?.dependencyFindings, "dependency");
  addFindings(findings, report.attackSurfaceReport?.attackFindings, "attack-surface");
  addFindings(findings, report.smartContractAuditReport?.auditFindings, "smart-contract-audit");
  addFindings(findings, report.exploitSimulationReport?.simulations, "exploit-simulation");
  addFindings(findings, report.securityScoreReport?.findings, "security-score");

  return findings;
}

function addFindings(target = [], findings = [], source = "unknown") {
  if (!Array.isArray(findings)) return;

  for (const finding of findings) {
    target.push({
      ...finding,
      source
    });
  }
}

function buildRules(findings = []) {
  const rules = new Map();

  for (const finding of findings) {
    const ruleId = getRuleId(finding);

    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        name: finding.type ?? finding.simulationName ?? finding.category ?? ruleId,
        shortDescription: {
          text:
            finding.description ??
            finding.reason ??
            finding.recommendation ??
            finding.simulationName ??
            "Quantum Shield Trinity finding"
        },
        fullDescription: {
          text:
            finding.recommendation ??
            finding.description ??
            finding.reason ??
            "Review this security finding."
        },
        help: {
          text:
            finding.recommendation ??
            "Review this finding and apply the recommended remediation."
        },
        properties: {
          category: finding.category ?? finding.affectedArea ?? finding.source ?? "security",
          severity: finding.severity ?? finding.estimatedImpact ?? "LOW"
        }
      });
    }
  }

  return Array.from(rules.values());
}

function toSarifResult(finding = {}) {
  return {
    ruleId: getRuleId(finding),
    level: mapSeverityToSarifLevel(
      finding.severity ?? finding.estimatedImpact
    ),
    message: {
      text:
        finding.description ??
        finding.reason ??
        finding.recommendation ??
        finding.simulationName ??
        finding.type ??
        "Quantum Shield Trinity finding"
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: normalizePath(finding.file ?? "unknown")
          },
          region: {
            startLine: Number(finding.line ?? 1)
          }
        }
      }
    ],
    properties: {
      source: finding.source ?? "unknown",
      severity: finding.severity ?? finding.estimatedImpact ?? "LOW",
      category: finding.category ?? finding.affectedArea ?? "security",
      confidence: finding.confidence ?? "unknown",
      recommendation:
        finding.recommendation ??
        finding.firstAttackStep ??
        finding.attackPath?.[0] ??
        "Review this finding manually."
    }
  };
}

function getRuleId(finding = {}) {
  return String(
    finding.ruleId ??
      finding.id ??
      finding.type ??
      finding.simulationName ??
      finding.category ??
      finding.source ??
      "QST_FINDING"
  )
    .toUpperCase()
    .replaceAll(" ", "_")
    .replace(/[^A-Z0-9_]/g, "");
}

function mapSeverityToSarifLevel(severity = "LOW") {
  const normalized = String(severity).toUpperCase();

  if (normalized === "CRITICAL") return "error";
  if (normalized === "HIGH") return "error";
  if (normalized === "MEDIUM") return "warning";
  if (normalized === "LOW") return "note";

  return "warning";
}

function normalizePath(filePath = "") {
  return String(filePath)
    .replaceAll("\\", "/")
    .replace(/^\.?\//, "");
}
