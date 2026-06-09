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
            version: report.version ?? "2.3.0",
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
  addFindings(findings, report.dependencyReport?.dependencyFindings, "dependency-intelligence");
  addFindings(findings, report.dependencyRiskReport?.findings, "dependency-risk");
  addFindings(findings, report.attackSurfaceReport?.attackFindings, "attack-surface");
  addFindings(findings, report.smartContractAuditReport?.auditFindings, "smart-contract-audit");
  addFindings(findings, report.smartContractContextReport?.contexts, "smart-contract-context");
  addFindings(findings, report.cryptoInventoryReport?.assets, "crypto-inventory");
  addFindings(findings, report.quantumReadinessReport?.findings, "quantum-readiness");
  addFindings(findings, report.codeFlowReport?.findings, "code-flow");
  addFindings(findings, report.routeExposureReport?.findings, "route-exposure");
  addFindings(findings, report.trustBoundaryReport?.findings, "trust-boundary");
  addFindings(findings, report.rootCauseReport?.rootCauses, "root-cause");
  addFindings(findings, report.securityCopilotReport?.guidance, "security-copilot");
  addFindings(findings, report.attackChainBuilderReport?.attackChains, "attack-chain-builder");
  addFindings(findings, report.attackPathReport?.attackPaths, "attack-path");
  addFindings(findings, report.exploitSimulationReport?.simulations, "exploit-simulation");
  addFindings(findings, report.complianceMappingReport?.mappedFindings, "compliance-mapping");
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
        name:
          finding.type ??
          finding.findingType ??
          finding.simulationName ??
          finding.category ??
          ruleId,
        shortDescription: {
          text: safeText(
            finding.description ??
              finding.reason ??
              finding.recommendation ??
              finding.summary ??
              finding.simulationName ??
              "Quantum Shield Trinity finding"
          )
        },
        fullDescription: {
          text: safeText(
            finding.recommendation ??
              finding.description ??
              finding.reason ??
              finding.summary ??
              "Review this security finding."
          )
        },
        help: {
          text: safeText(
            finding.recommendation ??
              finding.recommendedDefense ??
              "Review this finding and apply the recommended remediation."
          )
        },
        properties: {
          category: finding.category ?? finding.affectedArea ?? finding.source ?? "security",
          severity: finding.severity ?? finding.estimatedImpact ?? finding.exploitability ?? "LOW"
        }
      });
    }
  }

  if (rules.size === 0) {
    rules.set("QST_NO_FINDINGS", {
      id: "QST_NO_FINDINGS",
      name: "No Findings",
      shortDescription: {
        text: "No SARIF findings were generated."
      },
      fullDescription: {
        text: "Quantum Shield Trinity completed but produced no SARIF findings."
      },
      help: {
        text: "No action required."
      }
    });
  }

  return Array.from(rules.values());
}

function toSarifResult(finding = {}) {
  return {
    ruleId: getRuleId(finding),
    level: mapSeverityToSarifLevel(
      finding.severity ?? finding.estimatedImpact ?? finding.exploitability
    ),
    message: {
      text: safeText(
        finding.description ??
          finding.reason ??
          finding.recommendation ??
          finding.summary ??
          finding.simulationName ??
          finding.type ??
          finding.findingType ??
          "Quantum Shield Trinity finding"
      )
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: normalizePath(finding.file ?? finding.path ?? "unknown")
          },
          region: {
            startLine: safeLine(finding.line)
          }
        }
      }
    ],
    properties: {
      source: finding.source ?? "unknown",
      severity: finding.severity ?? finding.estimatedImpact ?? finding.exploitability ?? "LOW",
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
      finding.findingType ??
      finding.simulationName ??
      finding.category ??
      finding.source ??
      "QST_FINDING"
  )
    .toUpperCase()
    .replaceAll(" ", "_")
    .replace(/[^A-Z0-9_]/g, "")
    .slice(0, 120);
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

function safeLine(line) {
  const value = Number(line ?? 1);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : 1;
}

function safeText(value = "") {
  return String(value)
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 2000);
}

export default sarifReportGenerator;
