/**
 * ClawGuard ML-based Anomaly Detector
 *
 * Machine learning based detection for novel attack patterns
 * Uses feature extraction and ensemble methods for anomaly detection
 */

class MLDetector {
  constructor() {
    // Pre-trained thresholds (in production, would load actual models)
    this.thresholds = {
      isolationForest: 0.7,
      neuralNetwork: 0.8,
      lstmSequence: 0.75
    };

    // Known benign patterns for comparison
    this.benignPatterns = this.initializeBenignPatterns();
  }

  /**
   * Initialize known benign patterns
   */
  initializeBenignPatterns() {
    return {
      // Common benign operations
      benignKeywords: [
        'console.log', 'return', 'const', 'let', 'var', 'function', 'async',
        'await', 'try', 'catch', 'if', 'else', 'for', 'while', 'switch',
        'class', 'import', 'export', 'default', 'require'
      ],
      // Benign file operations
      benignFileOps: [
        'readFile', 'writeFile', 'appendFile', 'readdir', 'stat', 'exists'
      ],
      // Benign network patterns
      benignNetwork: [
        'fetch(https://api', 'axios.get(https://', 'https://api.'
      ]
    };
  }

  /**
   * Extract features from code
   */
  extractFeatures(content, codeFiles) {
    const features = {
      // Structural features
      astDepth: 0,
      functionCount: 0,
      loopNesting: 0,
      dynamicCodeRatio: 0,

      // Behavioral features
      networkCalls: 0,
      fileOperations: 0,
      processSpawns: 0,

      // Obfuscation features
      encodedStrings: 0,
      obfuscationScore: 0,
      entropy: 0,

      // Anomaly indicators
      suspiciousPatterns: [],
      riskSignals: []
    };

    // Combine all code
    const allCode = codeFiles.map(f => f.content).join('\n') + '\n' + content;

    // Count network calls
    const networkPatterns = [
      /\bfetch\s*\(/g, /\baxios\.\w+\(/g, /\bhttp\.\w+\(/g,
      /\brequest\s*\(/g, /\bwget\s+/g, /\bcurl\s+/g
    ];
    for (const pattern of networkPatterns) {
      features.networkCalls += (allCode.match(pattern) || []).length;
    }

    // Count file operations
    const filePatterns = [
      /\breadFile\s*\(/g, /\bwriteFile\s*\(/g, /\bappendFile\s*\(/g,
      /\bopen\s*\(/g, /\bcreateReadStream/g
    ];
    for (const pattern of filePatterns) {
      features.fileOperations += (allCode.match(pattern) || []).length;
    }

    // Count process spawns
    const processPatterns = [
      /\bexec\s*\(/g, /\bexecSync\s*\(/g, /\bspawn\s*\(/g,
      /\bsystem\s*\(/g, /\bpopen\s*\(/g
    ];
    for (const pattern of processPatterns) {
      features.processSpawns += (allCode.match(pattern) || []).length;
    }

    // Count encoded strings
    const encodedPatterns = [
      /atob\s*\(/g, /btoa\s*\(/g, /fromCharCode\s*\(/g,
      /\\x[0-9a-fA-F]{2}/g, /\\u[0-9a-fA-F]{4}/g
    ];
    for (const pattern of encodedPatterns) {
      features.encodedStrings += (allCode.match(pattern) || []).length;
    }

    // Calculate string entropy
    features.entropy = this.calculateEntropy(allCode);

    // Count functions
    const functionPatterns = [
      /\bfunction\s+\w+\s*\(/g, /\bconst\s+\w+\s*=\s*(async\s+)?\(/g,
      /\b\w+\s*:\s*function\s*\(/g, /\bdef\s+\w+\s*\(/g
    ];
    for (const pattern of functionPatterns) {
      features.functionCount += (allCode.match(pattern) || []).length;
    }

    // Detect obfuscation score
    features.obfuscationScore = this.calculateObfuscationScore(allCode);

    // Detect suspicious patterns
    features.suspiciousPatterns = this.detectSuspiciousPatterns(allCode);
    features.riskSignals = this.generateRiskSignals(features);

    // Calculate isolation forest score (simplified)
    features.isolationScore = this.calculateIsolationScore(features);

    return features;
  }

  /**
   * Calculate string entropy
   */
  calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};

    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    for (const char in frequencies) {
      const freq = frequencies[char] / len;
      entropy -= freq * Math.log2(freq);
    }

    return entropy;
  }

  /**
   * Calculate obfuscation score
   */
  calculateObfuscationScore(code) {
    let score = 0;

    // Check for various obfuscation techniques
    if (/[\u200B\u200C\u200D\uFEFF]/.test(code)) score += 0.3;
    if (/[\u202A-\u202E]/.test(code)) score += 0.3;
    if (/atob\s*\(/.test(code)) score += 0.2;
    if (/fromCharCode\s*\(/.test(code)) score += 0.2;
    if (/eval\s*\(/.test(code)) score += 0.3;
    if (/new\s+Function\s*\(/.test(code)) score += 0.3;
    if (/\.split\s*\(\s*['"`]\s*['"`]\s*\)\.join/.test(code)) score += 0.2;

    return Math.min(1, score);
  }

  /**
   * Detect suspicious patterns
   */
  detectSuspiciousPatterns(code) {
    const patterns = [];

    // Check for known malicious patterns
    const maliciousSignatures = [
      { pattern: /bash\s+-i\s+.*\/?dev\/tcp\//, name: 'reverse_shell' },
      { pattern: /nc\s+.*-e\s+/, name: 'netcat_reverse' },
      { pattern: /eval\s*\(\s*process\.env/, name: 'env_injection' },
      { pattern: /child_process.*\.exec\s*\(\s*`/, name: 'shell_injection' },
      { pattern: /setTimeout\s*\(\s*['"`].*rm\s+-rf/, name: 'destructive_command' },
      { pattern: /wget.*\|\s*bash/i, name: 'remote_execution' },
      { pattern: /curl.*\|\s*bash/i, name: 'remote_execution' },
      { pattern: /socket\s*\(\s*['"`]TCP/, name: 'raw_socket' },
    ];

    for (const sig of maliciousSignatures) {
      if (sig.pattern.test(code)) {
        patterns.push(sig.name);
      }
    }

    return patterns;
  }

  /**
   * Generate risk signals
   */
  generateRiskSignals(features) {
    const signals = [];

    if (features.networkCalls > 5) signals.push('excessive_network_activity');
    if (features.processSpawns > 2) signals.push('multiple_process_spawns');
    if (features.encodedStrings > 3) signals.push('heavy_encoding_usage');
    if (features.obfuscationScore > 0.5) signals.push('high_obfuscation');
    if (features.entropy > 5.5) signals.push('high_code_entropy');
    if (features.suspiciousPatterns.length > 0) signals.push('suspicious_signatures_detected');
    if (features.fileOperations > 10) signals.push('excessive_file_operations');

    return signals;
  }

  /**
   * Calculate isolation forest score (simplified)
   */
  calculateIsolationScore(features) {
    let score = 0;

    // Anomaly indicators
    if (features.suspiciousPatterns.length > 0) score += 0.3;
    if (features.riskSignals.length > 3) score += 0.2;
    if (features.obfuscationScore > 0.5) score += 0.2;
    if (features.processSpawns > 2) score += 0.15;
    if (features.encodedStrings > 3) score += 0.15;

    return Math.min(1, score);
  }

  /**
   * Detect anomaly using ensemble methods
   */
  async detectAnomaly(features) {
    // Simplified ML detection (in production, would use actual ML models)

    // 1. Isolation Forest based detection
    const isolationScore = features.isolationScore;

    // 2. Neural network based detection (simplified as rule-based)
    let neuralScore = 0;

    // Check for malicious signatures
    if (features.suspiciousPatterns.length > 0) {
      neuralScore += 0.4;
    }

    // Check for risk signals
    if (features.riskSignals.length > 0) {
      neuralScore += Math.min(0.3, features.riskSignals.length * 0.05);
    }

    // Check for obfuscation
    if (features.obfuscationScore > 0.3) {
      neuralScore += features.obfuscationScore * 0.3;
    }

    // 3. LSTM sequence detection (simplified)
    const lstmScore = features.entropy > 5 ? 0.3 : 0.1;

    // Ensemble: weighted average
    const finalScore = 0.3 * isolationScore + 0.4 * neuralScore + 0.3 * lstmScore;

    return Math.min(1, finalScore);
  }

  /**
   * Generate detection report
   */
  generateReport(features, anomalyScore) {
    return {
      score: anomalyScore,
      classification: anomalyScore > 0.5 ? 'MALICIOUS' : 'BENIGN',
      features: {
        network_calls: features.networkCalls,
        file_operations: features.fileOperations,
        process_spawns: features.processSpawns,
        encoded_strings: features.encodedStrings,
        obfuscation_score: features.obfuscationScore,
        entropy: features.entropy
      },
      suspicious_patterns: features.suspiciousPatterns,
      risk_signals: features.riskSignals,
      isolation_score: features.isolationScore,
      recommendation: this.getRecommendation(anomalyScore)
    };
  }

  getRecommendation(score) {
    if (score > 0.8) return 'BLOCK - High confidence malicious';
    if (score > 0.5) return 'REVIEW - Suspicious patterns detected';
    if (score > 0.3) return 'WARN - Some risk factors identified';
    return 'ALLOW - No significant risk detected';
  }
}

module.exports = MLDetector;
