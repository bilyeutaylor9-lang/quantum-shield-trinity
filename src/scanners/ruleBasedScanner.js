import { QUANTUM_RULES } from "../data/quantumRules.js";

export function ruleBasedScanner(files = []) {
  const findings = [];

  for (const file of files) {
    const content = file.content.toUpperCase();

    for (const rule of QUANTUM_RULES) {
      if (content.includes(rule.id)) {
        findings.push({
          file: file.name,
          ruleId: rule.id,
          severity: rule.severity,
          description: rule.description
        });
      }
    }
  }

  return {
    engine: "Rule Based Scanner",
    findings,
    totalFindings: findings.length
  };
}
