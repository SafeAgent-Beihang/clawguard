/**
 * ClawGuard Semantic Intent Analyzer
 *
 * Analyzes if a Skill's actual behavior matches its stated purpose
 * Uses NLP techniques and capability mapping to detect intent mismatches
 */

class SemanticAnalyzer {
  constructor() {
    // Keywords that indicate different capability categories
    this.capabilityKeywords = {
      'fs_read': ['read', 'load', 'get', 'fetch', 'open', 'parse', 'readFile', 'readdir'],
      'fs_write': ['write', 'save', 'create', 'update', 'edit', 'writeFile', 'mkdir', 'copy', 'move', 'delete', 'remove'],
      'net_egress': ['fetch', 'request', 'http', 'https', 'curl', 'wget', 'axios', 'send', 'post', 'get', 'put', 'delete', 'api'],
      'sys_exec': ['exec', 'spawn', 'run', 'execute', 'command', 'shell', 'bash', 'sh', 'process', 'child_process'],
      'env_access': ['env', 'process.env', 'os.environ', 'getenv', 'config', 'secret', 'key', 'token'],
      'crypto': ['encrypt', 'decrypt', 'hash', 'sign', 'verify', 'cipher', 'crypto', 'random'],
      'persistence': ['cron', 'schedule', 'timer', 'interval', 'setTimeout', 'setInterval', 'daemon'],
      'network_socket': ['socket', 'connect', 'listen', 'accept', 'bind', 'net', 'tcp', 'udp', 'websocket'],
    };

    // Suspicious capability combinations for different stated purposes
    this.suspiciousCombinations = {
      'formatter': ['sys_exec', 'net_egress', 'persistence', 'network_socket'],
      'parser': ['sys_exec', 'net_egress', 'persistence'],
      'helper': ['sys_exec', 'net_egress', 'persistence', 'network_socket'],
      'utility': ['sys_exec', 'net_egress', 'persistence'],
      'tool': ['sys_exec', 'net_egress', 'persistence'],
      'simple': ['sys_exec', 'net_egress', 'persistence', 'network_socket'],
    };
  }

  /**
   * Extract purpose from code
   */
  extractPurposeFromCode(codeFiles) {
    const allCode = codeFiles.map(f => f.content).join('\n');
    const capabilities = this.detectCapabilities(allCode);
    return {
      capabilities,
      summary: this.summarizeCapabilities(capabilities)
    };
  }

  /**
   * Detect capabilities from code
   */
  detectCapabilities(code) {
    const capabilities = {};

    for (const [cap, keywords] of Object.entries(this.capabilityKeywords)) {
      const matches = keywords.filter(keyword => {
        const pattern = new RegExp(`\\b${keyword}\\b`, 'gi');
        return pattern.test(code);
      });

      if (matches.length > 0) {
        capabilities[cap] = matches;
      }
    }

    return capabilities;
  }

  /**
   * Summarize capabilities into a readable description
   */
  summarizeCapabilities(capabilities) {
    const parts = [];

    if (capabilities.fs_read) parts.push('reads files');
    if (capabilities.fs_write) parts.push('writes/modifies files');
    if (capabilities.net_egress) parts.push('makes network requests');
    if (capabilities.sys_exec) parts.push('executes system commands');
    if (capabilities.env_access) parts.push('accesses environment variables');
    if (capabilities.crypto) parts.push('performs cryptographic operations');
    if (capabilities.persistence) parts.push('schedules persistent tasks');
    if (capabilities.network_socket) parts.push('creates network sockets');

    return parts.length > 0 ? parts.join(', ') : 'minimal functionality';
  }

  /**
   * Compute similarity between stated purpose and actual behavior
   */
  computeSimilarity(statedPurpose, actualBehavior) {
    if (!statedPurpose || statedPurpose.length < 5) {
      return 0.5; // Neutral if no stated purpose
    }

    const statedLower = statedPurpose.toLowerCase();

    // Extract key terms from stated purpose
    const statedWords = this.extractKeywords(statedLower);
    const statedCategories = this.categorizePurpose(statedLower);

    // Get actual behavior
    const actualCapabilities = actualBehavior.capabilities || {};
    const actualSummary = (actualBehavior.summary || '').toLowerCase();

    let score = 0.5; // Base score

    // Check for capability category match
    const categoryMatch = this.checkCategoryMatch(statedCategories, actualCapabilities);
    score += categoryMatch * 0.3;

    // Check for suspicious combinations
    const suspiciousPenalty = this.checkSuspiciousCombinations(statedCategories, actualCapabilities);
    score -= suspiciousPenalty * 0.4;

    // Check keyword alignment
    const keywordAlignment = this.checkKeywordAlignment(statedWords, actualSummary);
    score += keywordAlignment * 0.2;

    // Cap score between 0 and 1
    return Math.max(0, Math.min(1, score));
  }

  /**
   * Extract keywords from text
   */
  extractKeywords(text) {
    // Remove common words
    const stopWords = ['the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been',
      'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
      'should', 'may', 'might', 'must', 'shall', 'can', 'need', 'to', 'of', 'in',
      'for', 'on', 'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
      'before', 'after', 'above', 'below', 'between', 'under', 'again', 'further',
      'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'each',
      'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not', 'only',
      'own', 'same', 'so', 'than', 'too', 'very', 'just', 'and', 'but', 'if', 'or',
      'because', 'until', 'while', 'this', 'that', 'these', 'those', 'it', 'its'];

    const words = text.replace(/[^a-zA-Z\s]/g, ' ').split(/\s+/);
    return words.filter(w => w.length > 2 && !stopWords.includes(w));
  }

  /**
   * Categorize stated purpose
   */
  categorizePurpose(text) {
    const categories = [];

    if (/\b(format|convert|transform|parse|render|display|show|print)\b/.test(text)) {
      categories.push('formatter');
    }
    if (/\b(fetch|get|retrieve|download|upload|send|receive|request)\b/.test(text)) {
      categories.push('fetcher');
    }
    if (/\b(analyze|scan|check|detect|audit|verify|validate)\b/.test(text)) {
      categories.push('analyzer');
    }
    if (/\b(manage|organize|sort|filter|search|find)\b/.test(text)) {
      categories.push('manager');
    }
    if (/\b(encrypt|decrypt|hash|sign|verify)\b/.test(text)) {
      categories.push('crypto');
    }
    if (/\b(test|run|execute|build|deploy)\b/.test(text)) {
      categories.push('executor');
    }
    if (/\b(helper|tool|utility|assistant)\b/.test(text)) {
      categories.push('helper');
    }

    return categories.length > 0 ? categories : ['unknown'];
  }

  /**
   * Check if stated categories align with actual capabilities
   */
  checkCategoryMatch(categories, capabilities) {
    let matchScore = 0;

    for (const category of categories) {
      const suspicious = this.suspiciousCombinations[category] || [];
      const actualCaps = Object.keys(capabilities);

      // Check for suspicious capabilities
      const suspiciousCount = actualCaps.filter(cap => suspicious.includes(cap)).length;

      if (suspiciousCount === 0) {
        matchScore += 1;
      } else if (suspiciousCount === 1) {
        matchScore += 0.5;
      } else {
        matchScore -= suspiciousCount * 0.3;
      }
    }

    return matchScore / Math.max(categories.length, 1);
  }

  /**
   * Check for suspicious capability combinations
   */
  checkSuspiciousCombinations(categories, capabilities) {
    let penalty = 0;

    const actualCaps = Object.keys(capabilities);

    for (const category of categories) {
      const suspicious = this.suspiciousCombinations[category] || [];
      const found = actualCaps.filter(cap => suspicious.includes(cap));

      if (found.length > 0) {
        penalty += found.length;
      }
    }

    return penalty;
  }

  /**
   * Check keyword alignment
   */
  checkKeywordAlignment(statedWords, actualSummary) {
    if (statedWords.length === 0) return 0;

    let matches = 0;
    for (const word of statedWords) {
      if (actualSummary.includes(word)) {
        matches++;
      }
    }

    return matches / statedWords.length;
  }

  /**
   * Generate intent analysis report
   */
  generateReport(statedPurpose, actualBehavior) {
    const score = this.computeSimilarity(statedPurpose, actualBehavior);

    return {
      score,
      stated_purpose: statedPurpose,
      actual_behavior: actualBehavior.summary,
      capabilities: Object.keys(actualBehavior.capabilities),
      intent_match: score >= 0.8 ? 'HIGH' : (score >= 0.5 ? 'MEDIUM' : 'LOW'),
      warnings: this.generateWarnings(score, statedPurpose, actualBehavior)
    };
  }

  /**
   * Generate warnings based on analysis
   */
  generateWarnings(score, statedPurpose, actualBehavior) {
    const warnings = [];

    if (score < 0.3) {
      warnings.push('CRITICAL: Significant intent mismatch detected');
    } else if (score < 0.5) {
      warnings.push('WARNING: Possible intent mismatch - review required');
    }

    const caps = Object.keys(actualBehavior.capabilities || {});
    if (caps.includes('sys_exec') && !statedPurpose.toLowerCase().includes('command')) {
      warnings.push('Skill executes system commands but does not explicitly state this');
    }
    if (caps.includes('net_egress') && !statedPurpose.toLowerCase().includes('network')) {
      warnings.push('Skill makes network requests but does not explicitly state this');
    }
    if (caps.includes('persistence') && !statedPurpose.toLowerCase().includes('schedule')) {
      warnings.push('Skill creates persistent tasks but does not explicitly state this');
    }

    return warnings;
  }
}

module.exports = SemanticAnalyzer;
