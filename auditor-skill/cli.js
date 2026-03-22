#!/usr/bin/env node

/**
 * ClawGuard Auditor CLI
 * Command-line interface for auditing skills
 */

const ClawGuardAuditor = require('./src/auditor');
const path = require('path');

// Parse command line arguments
const args = process.argv.slice(2);

if (args.length === 0) {
  console.log('Usage: node cli.js <skill-path>');
  console.log('Example: node cli.js /workspace/skills/my-skill');
  process.exit(1);
}

const skillPath = args[0];

async function main() {
  console.log('Auditing skill: ' + skillPath);

  const auditor = new ClawGuardAuditor({
    autoApproveTier: 'TIER_1',
    mlDetection: true,
    sandboxExecution: true
  });

  const result = await auditor.audit(skillPath);

  console.log('\n=== Audit Result ===');
  console.log('Verdict: ' + result.verdict);
  console.log('Risk Tier: ' + result.risk_tier);
  console.log('Risk Score: ' + result.risk_score);
  console.log('Recommendation: ' + result.recommendation);

  if (result.analysis && result.analysis.sast && result.analysis.sast.findings) {
    console.log('\n=== Findings ===');
    const findings = result.analysis.sast.findings;
    console.log('Critical: ' + findings.filter(f => f.severity === 'CRITICAL').length);
    console.log('High: ' + findings.filter(f => f.severity === 'HIGH').length);
    console.log('Medium: ' + findings.filter(f => f.severity === 'MEDIUM').length);
    console.log('Low: ' + findings.filter(f => f.severity === 'LOW').length);
  }
}

main().catch(console.error);
