export function sarifReportGenerator(report = {}) {
  const findings = collectFindings(report);

  return {
    version: "2.1.0",
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Quantum Shield Trinity",
            informationUri:
              "https://github.com/bilyeutaylor9-lang/quantum-shield-trinity",
            version: report.version ?? "1.2.0",
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

  addFindings(findings, report.dependencyRiskReport?.findings, "dependency-risk");
  addFindings(findings, report.assessmentReport?.findings, "security-assessment");
  addFindings(findings, report.walletReport?.findings, "wallet-risk");
  addFindings(findings, report.inventoryReport?.findings, "crypto-inventory");
  addFindings(findings, report.migrationReport?.findings, "migration-risk");
  addFindings(findings, report.forecastReport?.findings, "quantum-forecast");
  addFindings(findings, report.simulationReport?.findings, "attack-simulation");
  addFindings(findings, report.auditReport?.findings, "audit-loop");

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
  const uniqueRules = new Map();

  for (const finding of findings) {
    const ruleId = getRuleId(finding);

    if (!uniqueRules.has(ruleId)) {
      uniqueRules.set(ruleId, {
        id: ruleId,
        name: finding.type ?? finding.category ?? ruleId,
        shortDescription: {
          text:
            finding.reason ??
            finding.description ??
            finding.recommendation ??
            "Quantum Shield Trinity finding"
        },
        fullDescription: {
          text:
            finding.recommendation ??
            finding.reason ??
            finding.description ??
            "Review this finding."
        },
        help: {
          text:
            finding.recommendation ??
            "Review this finding and apply the recommended remediation."
        },
        properties: {
          category: finding.category ?? finding.source ?? "security",
          severity: finding.severity ?? "LOW"
        }
      });
    }
  }

  return Array.from(uniqueRules.values());
}

function toSarifResult(finding = {}) {
  return {
    ruleId: getRuleId(finding),
    level: mapSeverityToSarifLevel(finding.severity),
    message: {
      text:
        finding.reason ??
        finding.description ??
        finding.recommendation ??
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
      severity: finding.severity ?? "LOW",
      category: finding.category ?? "security",
      confidence: finding.confidence ?? "unknown",
      recommendation:
        finding.recommendation ??
        "Review this finding manually."
    }
  };
}

function getRuleId(finding = {}) {
  return String(
    finding.ruleId ??
      finding.id ??
      finding.type ??
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
  if (normalized === "INFO") return "note";

  return "warning";
}

function normalizePath(filePath = "") {
  return String(filePath)
    .replaceAll("\\", "/")
    .replace(/^\.?\//, "");
}
