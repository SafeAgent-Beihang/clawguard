/**
 * ClawGuard Supply Chain Analyzer
 *
 * Analyzes Skill dependencies for security risks
 * Includes CVE scanning, typosquatting detection, and registry verification
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class SupplyChainAnalyzer {
  constructor() {
    // Known typosquatting targets
    this.typosquattingTargets = [
      'react', 'vue', 'angular', 'express', 'lodash', 'axios', 'moment', 'jquery',
      'underscore', 'async', 'request', 'chalk', 'debug', 'bluebird', 'joi',
      'mongoose', 'express', 'koa', 'hapi', 'fastify', 'socket.io', 'ws',
      'npm', 'yarn', 'pnpm', 'node', 'python', 'pip', 'pipenv', 'poetry'
    ];

    // Suspicious patterns in package names
    this.suspiciousPatterns = [
      /^npm-/,
      /^node-/,
      /^lib-/,
      /^utils-/,
      /-secure$/,
      /-safe$/,
      /^-/,
      /-$/
    ];

    // Critical CVEs cache
    this.cveCache = new Map();
  }

  /**
   * Find all dependencies in skill directory
   */
  findDependencies(skillPath) {
    const dependencies = [];

    // Check package.json
    const packageJsonPath = path.join(skillPath, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [name, version] of Object.entries(deps)) {
          dependencies.push({
            name,
            version,
            type: 'npm',
            source: 'package.json'
          });
        }
      } catch (e) {
        console.error('Error parsing package.json:', e.message);
      }
    }

    // Check requirements.txt
    const requirementsPath = path.join(skillPath, 'requirements.txt');
    if (fs.existsSync(requirementsPath)) {
      try {
        const content = fs.readFileSync(requirementsPath, 'utf-8');
        const lines = content.split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#')) {
            const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*(?:([><=!~]+)\s*(\d+\.\d+.*))?/);
            if (match) {
              dependencies.push({
                name: match[1],
                version: match[3] || 'latest',
                type: 'python',
                source: 'requirements.txt'
              });
            }
          }
        }
      } catch (e) {
        console.error('Error parsing requirements.txt:', e.message);
      }
    }

    // Check go.mod
    const goModPath = path.join(skillPath, 'go.mod');
    if (fs.existsSync(goModPath)) {
      try {
        const content = fs.readFileSync(goModPath, 'utf-8');
        const lines = content.split('\n');
        let inRequire = false;
        for (const line of lines) {
          if (line.startsWith('require (')) {
            inRequire = true;
            continue;
          }
          if (inRequire && line.trim() === ')') {
            inRequire = false;
            continue;
          }
          if (inRequire) {
            const match = line.trim().match(/^([^\s]+)\s+(.+)$/);
            if (match) {
              dependencies.push({
                name: match[1],
                version: match[2],
                type: 'go',
                source: 'go.mod'
              });
            }
          }
        }
      } catch (e) {
        console.error('Error parsing go.mod:', e.message);
      }
    }

    return dependencies;
  }

  /**
   * Check for vulnerabilities in dependencies
   */
  async checkVulnerabilities(dependencies) {
    const results = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      details: []
    };

    // Simulated CVE database (in production, would query real CVE databases)
    const knownVulnerabilities = {
      'lodash': { versions: ['<4.17.21'], cve: 'CVE-2021-23337', severity: 'high' },
      'axios': { versions: ['<0.21.1'], cve: 'CVE-2020-28168', severity: 'medium' },
      'moment': { versions: ['<2.29.2'], cve: 'CVE-2022-24785', severity: 'medium' },
      'json5': { versions: ['<1.0.2'], cve: 'CVE-2022-46175', severity: 'critical' },
      'ua-parser-js': { versions: ['<0.7.31'], cve: 'CVE-2022-25927', severity: 'critical' },
    };

    for (const dep of dependencies) {
      const vuln = knownVulnerabilities[dep.name];
      if (vuln) {
        // Check if version is vulnerable
        if (this.isVersionVulnerable(dep.version, vuln.versions)) {
          results[vuln.severity]++;
          results.details.push({
            package: dep.name,
            version: dep.version,
            cve: vuln.cve,
            severity: vuln.severity
          });
        }
      }
    }

    return results;
  }

  /**
   * Check if version is vulnerable
   */
  isVersionVulnerable(currentVersion, vulnerableRanges) {
    // Simplified version checking
    // In production, would use semver library
    for (const range of vulnerableRanges) {
      if (range.includes('<') && currentVersion !== 'latest') {
        const [, minVersion] = range.split('<');
        if (this.compareVersions(currentVersion, minVersion.trim()) < 0) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Simple version comparison
   */
  compareVersions(v1, v2) {
    const p1 = v1.split('.').map(n => parseInt(n) || 0);
    const p2 = v2.split('.').map(n => parseInt(n) || 0);

    for (let i = 0; i < Math.max(p1.length, p2.length); i++) {
      const n1 = p1[i] || 0;
      const n2 = p2[i] || 0;
      if (n1 > n2) return 1;
      if (n1 < n2) return -1;
    }
    return 0;
  }

  /**
   * Detect typosquatting attempts
   */
  detectTyposquatting(dependencies) {
    const risks = [];

    for (const dep of dependencies) {
      const name = dep.name.toLowerCase();

      // Check for exact match to known packages
      if (this.typosquattingTargets.includes(name)) {
        risks.push({
          package: dep.name,
          type: 'typosquatting',
          target: name,
          severity: 'HIGH',
          message: `Package name '${dep.name}' matches popular package '${name}'`
        });
        continue;
      }

      // Check for close match (1-2 character difference)
      for (const target of this.typosquattingTargets) {
        const distance = this.levenshteinDistance(name, target);
        if (distance > 0 && distance <= 2) {
          risks.push({
            package: dep.name,
            type: 'typosquatting',
            target: target,
            severity: 'MEDIUM',
            message: `Package name '${dep.name}' is similar to '${target}' (distance: ${distance})`
          });
        }
      }

      // Check for suspicious patterns
      for (const pattern of this.suspiciousPatterns) {
        if (pattern.test(name)) {
          risks.push({
            package: dep.name,
            type: 'suspicious_pattern',
            pattern: pattern.toString(),
            severity: 'MEDIUM',
            message: `Package name '${dep.name}' matches suspicious pattern`
          });
        }
      }
    }

    return risks;
  }

  /**
   * Calculate Levenshtein distance
   */
  levenshteinDistance(s1, s2) {
    const m = s1.length;
    const n = s2.length;
    const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (s1[i - 1] === s2[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = Math.min(
            dp[i - 1][j] + 1,
            dp[i][j - 1] + 1,
            dp[i - 1][j - 1] + 1
          );
        }
      }
    }

    return dp[m][n];
  }

  /**
   * Analyze registry trust
   */
  analyzeRegistryTrust(dependencies) {
    const scores = {
      npm: 80,
      pypi: 80,
      go: 75,
      cargo: 70,
      maven: 70,
      unknown: 30
    };

    const types = [...new Set(dependencies.map(d => d.type))];
    const avgScore = types.reduce((sum, t) => sum + (scores[t] || scores.unknown), 0) / types.length;

    return {
      score: avgScore,
      types: types,
      recommendation: avgScore >= 70 ? 'Trust acceptable' : 'Review dependencies'
    };
  }
}

module.exports = SupplyChainAnalyzer;
