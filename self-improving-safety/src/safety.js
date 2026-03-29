/**
 * ClawGuard Self-Improving Safety Core Logic
 */

const fs = require('fs-extra');
const path = require('path');
const chalk = require('chalk');

class SelfImprovingSafety {
  constructor(options = {}) {
    this.workspaceDir = options.workspaceDir || path.join(process.env.HOME || '.', '.openclaw/workspace/skills/self-improving-safety');
    this.safetyDir = path.join(this.workspaceDir, '.safety');
    this.blocklistPath = path.join(this.safetyDir, 'BLOCKLIST.json');
    this.attemptsPath = path.join(this.safetyDir, 'ATTEMPTS.md');
    
    this.ensureWorkspace();
    this.rules = this.loadRules();
  }

  ensureWorkspace() {
    fs.ensureDirSync(this.safetyDir);
    if (!fs.existsSync(this.blocklistPath)) {
      fs.writeJsonSync(this.blocklistPath, [], { spaces: 2 });
    }
    if (!fs.existsSync(this.attemptsPath)) {
      fs.writeFileSync(this.attemptsPath, '# Safety Incident Log\n\n');
    }
  }

  loadRules() {
    try {
      return fs.readJsonSync(this.blocklistPath);
    } catch (error) {
      console.error(chalk.red('Failed to load rules:'), error.message);
      return [];
    }
  }

  saveRules() {
    try {
      fs.writeJsonSync(this.blocklistPath, this.rules, { spaces: 2 });
    } catch (error) {
      console.error(chalk.red('Failed to save rules:'), error.message);
    }
  }
  
  getRules() {
    return this.rules;
  }

  addRule(type, pattern) {
    // Check for duplicates
    const exists = this.rules.find(r => r.type === type && r.pattern === pattern);
    if (exists) return;

    this.rules.push({
      type,
      pattern,
      created: new Date().toISOString(),
      hits: 0
    });
    this.saveRules();
  }

  /**
   * Process a threat alert and potentially learn a new rule
   * @param {Object} threat - The threat object or raw data
   */
  processThreat(threat) {
    // Simplistic Logic for Demo:
    // If we receive a threat, log it.
    // In a real system, this would use an LLM or heuristic to generalize the threat into a regex.
    
    const logEntry = `\n## Incident [${new Date().toISOString()}]\n- Data: ${JSON.stringify(threat)}\n`;
    fs.appendFileSync(this.attemptsPath, logEntry);
    
    console.log(chalk.yellow(`[LEARNING] Recorded incident in ${this.attemptsPath}`));
    
    // Auto-learning simulation (if structured)
    if (threat.raw && threat.raw.includes('command')) {
         // Logic to parse raw would go here
    }
  }

  /**
   * Check if an input string violates any rules
   * @param {string} input 
   */
  checkInput(input) {
    for (const rule of this.rules) {
      // Robust check: try simple includes first
      if (input.includes(rule.pattern)) {
        rule.hits = (rule.hits || 0) + 1;
        this.saveRules();
        return { blocked: true, rule };
      }
      
      // If it looks like a regex, try regex (basic support)
      try {
        if (rule.pattern.startsWith('/') || rule.pattern.startsWith('^')) {
           const regex = new RegExp(rule.pattern);
           if (regex.test(input)) {
             rule.hits = (rule.hits || 0) + 1;
             this.saveRules();
             return { blocked: true, rule };
           }
        }
      } catch (e) {
        // ignore regex errors
      }
    }
    return { blocked: false };
  }
}

module.exports = SelfImprovingSafety;
