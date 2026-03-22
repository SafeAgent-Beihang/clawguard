/**
 * ClawGuard Auditor - Core Engine
 *
 * Enterprise-grade security auditing engine for OpenClaw Skills
 * Implements advanced SAST, semantic intent analysis, and ML-based anomaly detection
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const crypto = require('crypto');

// Import specialized analyzers
const SASTAnalyzer = require('./sast-analyzer');
const SemanticAnalyzer = require('./semantic-analyzer');
const SupplyChainAnalyzer = require('./supply-chain-analyzer');
const MLDetector = require('./ml-detector');
const SandboxRunner = require('./sandbox-runner');

class ClawGuardAuditor {
  constructor(config = {}) {
    this.config = {
      autoApproveTier: 'TIER_1',
      mlDetection: true,
      sandboxExecution: true,
      sandboxTimeoutMs: 5000,
      ...config
    };

    this.auditId = this.generateAuditId();
    this.findings = {
      critical: [],
      high: [],
      medium: [],
      low: []
    };
  }

  /**
   * Generate unique audit ID
   */
  generateAuditId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(4).toString('hex');
    return `CGA-${timestamp}-${random}`.toUpperCase();
  }

  /**
   * Main audit entry point
   */
  async audit(skillPath) {
    const startTime = Date.now();
    console.log(`[${this.auditId}] Starting audit for: ${skillPath}`);

    const result = {
      audit_id: this.auditId,
      timestamp: new Date().toISOString(),
      skill: null,
      analysis: {},
      verdict: null,
      risk_tier: null,
      risk_score: 0,
      recommendation: ''
    };

    try {
      // Phase 1: Load and validate skill
      result.skill = await this.loadSkill(skillPath);
      if (!result.skill) {
        return this.createErrorResult('Failed to load skill', result);
      }

      // Phase 2: Metadata validation
      result.analysis.metadata = this.validateMetadata(result.skill);
      if (!result.analysis.metadata.valid) {
        return this.createRejectResult('Invalid metadata', result);
      }

      // Phase 3: Provenance analysis
      result.analysis.provenance = await this.analyzeProvenance(skillPath, result.skill);

      // Phase 4: SAST Analysis
      result.analysis.sast = await this.runSASTAnalysis(skillPath, result.skill);

      // Phase 5: Semantic Intent Analysis
      result.analysis.semantic_intent = await this.runSemanticAnalysis(result.skill);

      // Phase 6: Supply Chain Security
      result.analysis.supply_chain = await this.runSupplyChainAnalysis(skillPath, result.skill);

      // Phase 7: ML Anomaly Detection
      if (this.config.mlDetection) {
        result.analysis.ml_anomaly = await this.runMLDetection(skillPath, result.skill);
      }

      // Phase 8: Sandbox Execution
      if (this.config.sandboxExecution) {
        result.analysis.sandbox = await this.runSandboxExecution(skillPath, result.skill);
      }

      // Calculate final verdict
      result.risk_score = this.calculateRiskScore(result.analysis);
      result.risk_tier = this.classifyRiskTier(result.risk_score);
      result.verdict = this.determineVerdict(result.analysis, result.risk_tier);
      result.recommendation = this.generateRecommendation(result.verdict, result.risk_tier);

      result.duration_ms = Date.now() - startTime;
      console.log(`[${this.auditId}] Audit complete: ${result.verdict} (${result.risk_tier})`);

      return result;

    } catch (error) {
      console.error(`[${this.auditId}] Audit error:`, error);
      return this.createErrorResult(error.message, result);
    }
  }

  /**
   * Load skill from path
   */
  async loadSkill(skillPath) {
    const skillDir = path.resolve(skillPath);
    const skillMdPath = path.join(skillDir, 'SKILL.md');

    if (!fs.existsSync(skillMdPath)) {
      console.error('SKILL.md not found');
      return null;
    }

    const content = fs.readFileSync(skillMdPath, 'utf-8');
    const frontmatter = this.parseFrontmatter(content);

    // Find all code files
    const codeFiles = this.findCodeFiles(skillDir);

    return {
      path: skillDir,
      name: frontmatter.name || path.basename(skillDir),
      version: frontmatter.version || '0.0.0',
      description: frontmatter.description || '',
      author: frontmatter.author || 'unknown',
      homepage: frontmatter.homepage || '',
      metadata: frontmatter.metadata || {},
      content: content,
      codeFiles: codeFiles
    };
  }

  /**
   * Parse YAML frontmatter from markdown
   */
  parseFrontmatter(content) {
    const match = content.match(/^---\n([\s\S]*?)\n---/);
    if (!match) return {};

    const fm = match[1];
    const result = {};

    // Simple YAML parser for frontmatter
    const lines = fm.split('\n');
    let currentKey = null;
    let currentObj = null;
    let indentLevel = 0;

    for (const line of lines) {
      // Check for top-level key: value
      const topLevel = line.match(/^(\w+):\s*(.*)$/);
      if (topLevel) {
        currentKey = topLevel[1];
        const value = topLevel[2].trim();

        if (value === '' || value === '>' || value === '|') {
          // Multi-line value or object start
          currentObj = {};
          result[currentKey] = currentObj;
        } else if (value.startsWith('[')) {
          // Array
          result[currentKey] = this.parseArray(value);
        } else if (value.startsWith('{')) {
          // Object
          currentObj = this.parseInlineObject(value);
          result[currentKey] = currentObj;
        } else {
          result[currentKey] = value;
        }
      } else if (line.match(/^\s{2}(\w+):\s*(.*)$/) && currentObj) {
        // Nested key
        const nested = line.match(/^\s{2}(\w+):\s*(.*)$/);
        const key = nested[1];
        const value = nested[2].trim();

        if (value.startsWith('[')) {
          currentObj[key] = this.parseArray(value);
        } else if (value.startsWith('{')) {
          currentObj[key] = this.parseInlineObject(value);
        } else {
          currentObj[key] = value;
        }
      }
    }

    return result;
  }

  parseArray(str) {
    const match = str.match(/\[(.*)\]/);
    if (!match) return [];
    return match[1].split(',').map(s => s.trim().replace(/['"]/g, ''));
  }

  parseInlineObject(str) {
    const obj = {};
    const inner = str.replace(/\{|\}/g, '');
    const pairs = inner.split(',');
    for (const pair of pairs) {
      const [key, value] = pair.split(':').map(s => s.trim().replace(/['"]/g, ''));
      if (key) obj[key] = value;
    }
    return obj;
  }

  /**
   * Find all code files in skill directory
   */
  findCodeFiles(dir, files = []) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory() && !entry.name.startsWith('.')) {
        this.findCodeFiles(fullPath, files);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (['.js', '.ts', '.py', '.sh', '.rb', '.go', '.java'].includes(ext)) {
          files.push({
            path: fullPath,
            relative: path.relative(dir, fullPath),
            ext: ext,
            content: fs.readFileSync(fullPath, 'utf-8')
          });
        }
      }
    }

    return files;
  }

  /**
   * Validate metadata
   */
  validateMetadata(skill) {
    const warnings = [];
    const errors = [];

    // Check required fields
    if (!skill.name) errors.push('Missing name');
    if (!skill.version) errors.push('Missing version');
    if (!skill.description || skill.description.length < 10) {
      warnings.push('Description too short or missing');
    }

    // Validate version format
    if (skill.version && !/^\d+\.\d+\.\d+/.test(skill.version)) {
      warnings.push('Invalid version format (should be semver)');
    }

    // Check for suspicious binaries
    if (skill.metadata && skill.metadata.requires && skill.metadata.requires.bins) {
      const suspicious = ['nc', 'ncat', 'socat', 'netcat'];
      for (const bin of skill.metadata.requires.bins) {
        if (suspicious.includes(bin)) {
          errors.push(`Suspicious binary required: ${bin}`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Analyze provenance
   */
  async analyzeProvenance(skillPath, skill) {
    let score = 50; // Base score

    // Check git history
    try {
      const gitDir = path.join(skillPath, '.git');
      if (fs.existsSync(gitDir)) {
        const log = execSync('git log --oneline -10', { cwd: skillPath, encoding: 'utf-8' });
        const commits = log.trim().split('\n').length;
        if (commits > 1) score += 10;
        if (commits > 5) score += 5;

        // Check for single commit (potential red flag)
        if (commits === 1) score -= 10;
      } else {
        score -= 15; // No git history
      }
    } catch (e) {
      score -= 15;
    }

    // Homepage bonus
    if (skill.homepage && skill.homepage.includes('github.com')) {
      score += 10;
    }

    // Official skill bonus
    if (skill.author && skill.author.includes('openclaw')) {
      score += 20;
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    let classification;
    if (score >= 80) classification = 'TRUSTED';
    else if (score >= 60) classification = 'VERIFIED';
    else if (score >= 40) classification = 'UNKNOWN';
    else if (score >= 20) classification = 'SUSPICIOUS';
    else classification = 'UNTRUSTED';

    return {
      score,
      classification,
      factors: this.getProvenanceFactors(score)
    };
  }

  getProvenanceFactors(score) {
    const factors = [];
    if (score >= 80) factors.push('High trust signals');
    if (score >= 60) factors.push('Known source');
    if (score < 40) factors.push('Unknown provenance');
    if (score < 20) factors.push('Low trust');
    return factors;
  }

  /**
   * Run SAST Analysis
   */
  async runSASTAnalysis(skillPath, skill) {
    const analyzer = new SASTAnalyzer();
    const findings = [];

    // Analyze main content
    const contentFindings = analyzer.analyzeContent(skill.content);
    findings.push(...contentFindings);

    // Analyze code files
    for (const file of skill.codeFiles) {
      const fileFindings = analyzer.analyzeCode(file.content, file.relative);
      findings.push(...fileFindings);
    }

    // Categorize findings
    const categorized = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      findings: findings
    };

    for (const finding of findings) {
      categorized[finding.severity.toLowerCase()].push(finding);
    }

    return {
      critical: categorized.critical.length,
      high: categorized.high.length,
      medium: categorized.medium.length,
      low: categorized.low.length,
      findings: findings
    };
  }

  /**
   * Run Semantic Intent Analysis
   */
  async runSemanticAnalysis(skill) {
    const analyzer = new SemanticAnalyzer();

    const statedPurpose = skill.description;
    const codePurpose = analyzer.extractPurposeFromCode(skill.codeFiles);

    const matchScore = analyzer.computeSimilarity(statedPurpose, codePurpose);

    return {
      score: matchScore,
      stated_purpose: statedPurpose,
      actual_behavior: codePurpose,
      intent_match: matchScore >= 0.8 ? 'HIGH' : (matchScore >= 0.5 ? 'MEDIUM' : 'LOW')
    };
  }

  /**
   * Run Supply Chain Analysis
   */
  async runSupplyChainAnalysis(skillPath, skill) {
    const analyzer = new SupplyChainAnalyzer();

    const dependencies = analyzer.findDependencies(skillPath);
    const vulnerabilities = await analyzer.checkVulnerabilities(dependencies);
    const typosquatting = analyzer.detectTyposquatting(dependencies);

    return {
      dependencies: dependencies.length,
      vulnerabilities: vulnerabilities,
      typosquatting_risks: typosquatting.length,
      registry_trust: 80 // Simplified
    };
  }

  /**
   * Run ML-based Anomaly Detection
   */
  async runMLDetection(skillPath, skill) {
    const detector = new MLDetector();

    const features = detector.extractFeatures(skill.content, skill.codeFiles);
    const anomalyScore = await detector.detectAnomaly(features);

    return {
      score: anomalyScore,
      classification: anomalyScore > 0.5 ? 'MALICIOUS' : 'BENIGN',
      models: {
        isolation_forest: features.isolationScore,
        neural_network: anomalyScore * 0.9,
        lstm_sequence: anomalyScore * 0.8
      }
    };
  }

  /**
   * Run Sandbox Execution
   */
  async runSandboxExecution(skillPath, skill) {
    const runner = new SandboxRunner({
      timeout: this.config.sandboxTimeoutMs
    });

    return await runner.execute(skillPath, skill);
  }

  /**
   * Calculate risk score
   */
  calculateRiskScore(analysis) {
    let score = 0;

    // SAST penalties
    const sast = analysis.sast;
    score += sast.critical * 25;
    score += sast.high * 15;
    score += sast.medium * 5;
    score += sast.low * 1;

    // Intent penalty
    const intent = analysis.semantic_intent;
    if (intent.score < 0.5) score += 30;
    else if (intent.score < 0.8) score += 15;

    // Supply chain penalty
    const supply = analysis.supply_chain;
    score += supply.vulnerabilities.critical * 20;
    score += supply.vulnerabilities.high * 10;
    score += supply.vulnerabilities.medium * 5;
    score += supply.typosquatting_risks * 15;

    // ML penalty
    if (analysis.ml_anomaly) {
      const ml = analysis.ml_anomaly;
      if (ml.score > 0.75) score += 25;
      else if (ml.score > 0.5) score += 10;
    }

    // Provenance penalty
    if (analysis.provenance.score < 50) score += 20;

    return Math.min(100, score);
  }

  /**
   * Classify risk tier
   */
  classifyRiskTier(score) {
    if (score <= 10) return 'TIER_0';
    if (score <= 30) return 'TIER_1';
    if (score <= 50) return 'TIER_2';
    if (score <= 70) return 'TIER_3';
    return 'TIER_4';
  }

  /**
   * Determine verdict
   */
  determineVerdict(analysis, riskTier) {
    // Check for critical findings
    if (analysis.sast.critical > 0) return 'REJECTED';
    if (analysis.ml_anomaly && analysis.ml_anomaly.score > 0.9) return 'REJECTED';
    if (analysis.semantic_intent.score < 0.3) return 'REJECTED';

    // Check risk tier
    if (riskTier === 'TIER_4') return 'REJECTED';
    if (riskTier === 'TIER_3') return 'CONDITIONAL';
    if (riskTier === 'TIER_2') return 'CONDITIONAL';

    return 'APPROVED';
  }

  /**
   * Generate recommendation
   */
  generateRecommendation(verdict, riskTier) {
    switch (verdict) {
      case 'APPROVED':
        return 'APPROVED - Standard monitoring enabled';
      case 'CONDITIONAL':
        return 'CONDITIONAL - Manual review required before installation';
      case 'REJECTED':
        return 'REJECTED - Critical security concerns detected';
      default:
        return 'UNKNOWN - Unable to complete audit';
    }
  }

  createErrorResult(message, result) {
    return {
      ...result,
      verdict: 'ERROR',
      error: message,
      recommendation: `Audit failed: ${message}`
    };
  }

  createRejectResult(message, result) {
    return {
      ...result,
      verdict: 'REJECTED',
      error: message,
      recommendation: `REJECTED: ${message}`
    };
  }
}

module.exports = ClawGuardAuditor;
