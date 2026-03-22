#!/usr/bin/env node

/**
 * ClawGuard Checker CLI
 * Command-line interface for security checks
 */

const SecurityChecker = require('./src/checker');

// Parse command line arguments
const args = process.argv.slice(2);

async function main() {
  console.log('Running ClawGuard Security Check...');

  const checker = new SecurityChecker({
    openclawDir: process.env.HOME + '/.openclaw',
    workspaceDir: '/workspace'
  });

  const result = await checker.runFullCheck();

  console.log('\n=== Security Check Result ===');
  console.log(`Security Score: ${result.security_score}/100`);
  console.log(`Grade: ${result.grade}`);

  const totalIssues = Object.values(result.checks).reduce((sum, check) => {
    return sum + (check.issues && check.issues.length) || 0;
  }, 0);

  console.log(`Total Issues: ${totalIssues}`);

  if (result.recommendations.length > 0) {
    console.log('\n=== Top Recommendations ===');
    result.recommendations.slice(0, 5).forEach((rec, i) => {
      console.log(`${i + 1}. [${rec.priority}] ${rec.message}`);
    });
  }
}

main().catch(console.error);
