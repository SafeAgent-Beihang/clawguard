/**
 * ClawGuard SAST Analyzer
 *
 * Advanced Static Application Security Testing for Skills
 * Comprehensive detection of execution risks, network anomalies, obfuscation, and more
 */

class SASTAnalyzer {
  constructor() {
    this.findings = [];

    // Initialize detection patterns
    this.initPatterns();
  }

  initPatterns() {
    // Critical execution risks
    this.executionRisks = [
      { pattern: /\beval\s*\(/gi, type: 'dynamic_execution', severity: 'CRITICAL' },
      { pattern: /\bexec\s*\(/gi, type: 'dynamic_execution', severity: 'CRITICAL' },
      { pattern: /__import__\s*\(/gi, type: 'dynamic_import', severity: 'CRITICAL' },
      { pattern: /\bcompile\s*\(/gi, type: 'dynamic_compilation', severity: 'HIGH' },
      { pattern: /new\s+Function\s*\(/gi, type: 'dynamic_function', severity: 'CRITICAL' },
      { pattern: /child_process\.execSync/gi, type: 'command_execution', severity: 'HIGH' },
      { pattern: /child_process\.exec\s*\(/gi, type: 'command_execution', severity: 'HIGH' },
      { pattern: /child_process\.spawn\s*\(/gi, type: 'process_spawning', severity: 'HIGH' },
      { pattern: /subprocess\.(Popen|call|run|check_output)/gi, type: 'command_execution', severity: 'HIGH' },
      { pattern: /os\.system\s*\(/gi, type: 'shell_execution', severity: 'HIGH' },
      { pattern: /os\.popen\s*\(/gi, type: 'shell_execution', severity: 'HIGH' },
      { pattern: /\bpopen\s*\(/gi, type: 'shell_execution', severity: 'HIGH' },
      { pattern: /Runtime\.exec\s*\(/gi, type: 'command_execution', severity: 'HIGH' },
      { pattern: /ProcessBuilder/gi, type: 'process_building', severity: 'HIGH' },
    ];

    // Network anomaly patterns
    this.networkPatterns = [
      { pattern: /curl\s+.*[?&](token|key|password|secret)=/gi, type: 'credential_exfiltration', severity: 'CRITICAL' },
      { pattern: /wget\s+.*[?&](token|key|password|secret)=/gi, type: 'credential_exfiltration', severity: 'CRITICAL' },
      { pattern: /curl\s+.*-d\s+.*[A-Za-z0-9+/]{20,}/gi, type: 'data_exfiltration', severity: 'CRITICAL' },
      { pattern: /bash\s+-i\s+.*\/?dev\/tcp\//gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /nc\s+.*-e\s+/gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /ncat\s+.*-e\s+/gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /socat\s+.*TCP:.*EXEC:/gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /python.*socket.*connect.*exec/gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /perl.*socket.*connect/gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /php.*fsockopen/gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /node.*child_process.*net\.Socket/gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /powershell.*-NoP.*-NonI/gi, type: 'reverse_shell', severity: 'CRITICAL' },
      { pattern: /\b(exec|system|spawn)\s*\(.*\$_(GET|POST|REQUEST|ENV)/gi, type: 'command_injection', severity: 'CRITICAL' },
      { pattern: /exec\s*\(\s*`/gi, type: 'shell_injection', severity: 'CRITICAL' },
    ];

    // File system threats
    this.fileSystemPatterns = [
      { pattern: /readFile\s*\(\s*['"`]\/etc\/passwd/gi, type: 'sensitive_file_read', severity: 'HIGH' },
      { pattern: /readFile\s*\(\s*['"`]\/etc\/shadow/gi, type: 'sensitive_file_read', severity: 'CRITICAL' },
      { pattern: /readFile\s*\(\s*['"`]\/\.ssh\//gi, type: 'credential_access', severity: 'CRITICAL' },
      { pattern: /readFile\s*\(\s*['"`]\/\.aws\//gi, type: 'credential_access', severity: 'CRITICAL' },
      { pattern: /readFile\s*\(\s*['"`]\/\.kube\//gi, type: 'credential_access', severity: 'CRITICAL' },
      { pattern: /readFile\s*\(\s*['"`]\.env/gi, type: 'credential_access', severity: 'HIGH' },
      { pattern: /writeFile\s*\(\s*['"`]\/\.ssh\/authorized_keys/gi, type: 'persistence', severity: 'CRITICAL' },
      { pattern: /writeFile\s*\(\s*['"`]\/etc\/cron/gi, type: 'persistence', severity: 'CRITICAL' },
      { pattern: /writeFile\s*\(\s*['"`]\.bashrc/gi, type: 'persistence', severity: 'HIGH' },
      { pattern: /appendFile\s*\(\s*['"`]\/etc\/cron/gi, type: 'persistence', severity: 'CRITICAL' },
      { pattern: /echo.*>>\s*\/etc\/crontab/gi, type: 'persistence', severity: 'CRITICAL' },
      { pattern: /crontab\s+-e/gi, type: 'persistence', severity: 'HIGH' },
      { pattern: /chmod\s+777/gi, type: 'privilege_escalation', severity: 'HIGH' },
      { pattern: /chown\s+/gi, type: 'privilege_escalation', severity: 'HIGH' },
      { pattern: /sudo\s+/gi, type: 'privilege_escalation', severity: 'HIGH' },
    ];

    // Obfuscation patterns
    this.obfuscationPatterns = [
      { pattern: /fromCharCode\s*\(/gi, type: 'code_obfuscation', severity: 'MEDIUM' },
      { pattern: /\beval\s*\(atob\s*\(/gi, type: 'obfuscated_execution', severity: 'CRITICAL' },
      { pattern: /String\.fromCharCode\s*\(/gi, type: 'obfuscation', severity: 'MEDIUM' },
      { pattern: /\[!\+\[\]\]/gi, type: 'jsfuck_obfuscation', severity: 'CRITICAL' },
      { pattern: /\\x[0-9a-fA-F]{2}/gi, type: 'hex_obfuscation', severity: 'MEDIUM' },
      { pattern: /\\u[0-9a-fA-F]{4}/gi, type: 'unicode_obfuscation', severity: 'MEDIUM' },
      { pattern: /\u200B|\u200C|\u200D|\uFEFF/gi, type: 'zero_width_characters', severity: 'CRITICAL' },
      { pattern: /\u202A|\u202B|\u202C|\u202D|\u202E/gi, type: 'bidi_override', severity: 'CRITICAL' },
      { pattern: /atob\s*\(/gi, type: 'base64_decode', severity: 'MEDIUM' },
      { pattern: /btoa\s*\(/gi, type: 'base64_encode', severity: 'MEDIUM' },
      { pattern: /concat\s*\(\s*['"`][a-zA-Z]+['"`]\)/gi, type: 'string_splitting', severity: 'MEDIUM' },
      { pattern: /\.split\s*\(\s*['"`]\s*['"`]\s*\)\.join/gi, type: 'string_splitting', severity: 'MEDIUM' },
    ];

    // Environment access patterns
    this.envAccessPatterns = [
      { pattern: /process\.env\.[A-Z_]+/gi, type: 'env_access', severity: 'MEDIUM' },
      { pattern: /os\.environ\[/gi, type: 'env_access', severity: 'MEDIUM' },
      { pattern: /getenv\s*\(/gi, type: 'env_access', severity: 'MEDIUM' },
      { pattern: /process\.env\.(API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE)/gi, type: 'credential_access', severity: 'HIGH' },
    ];
  }

  /**
   * Analyze content (markdown + code blocks)
   */
  analyzeContent(content) {
    const findings = [];

    // Extract code blocks from markdown
    const codeBlockPattern = /```(\w+)?\n([\s\S]*?)```/g;
    let match;

    while ((match = codeBlockPattern.exec(content)) !== null) {
      const language = match[1] || 'text';
      const code = match[2];

      if (['bash', 'shell', 'sh', 'zsh', 'javascript', 'js', 'python', 'py', 'ruby', 'go', 'java', 'php'].includes(language)) {
        const codeFindings = this.analyzeCode(code, `inline:${language}`);
        findings.push(...codeFindings);
      }
    }

    // Check for hidden code in comments
    const hiddenCodeFindings = this.detectHiddenCode(content);
    findings.push(...hiddenCodeFindings);

    return findings;
  }

  /**
   * Analyze code
   */
  analyzeCode(code, location) {
    const findings = [];

    // Check execution risks
    for (const pattern of this.executionRisks) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        findings.push({
          severity: pattern.severity,
          category: pattern.type,
          title: this.getTitle(pattern.type),
          location: location,
          evidence: match,
          recommendation: this.getRecommendation(pattern.type)
        });
      }
    }

    // Check network patterns
    for (const pattern of this.networkPatterns) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        findings.push({
          severity: pattern.severity,
          category: pattern.type,
          title: this.getTitle(pattern.type),
          location: location,
          evidence: match,
          recommendation: this.getRecommendation(pattern.type)
        });
      }
    }

    // Check file system patterns
    for (const pattern of this.fileSystemPatterns) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        findings.push({
          severity: pattern.severity,
          category: pattern.type,
          title: this.getTitle(pattern.type),
          location: location,
          evidence: match,
          recommendation: this.getRecommendation(pattern.type)
        });
      }
    }

    // Check obfuscation
    for (const pattern of this.obfuscationPatterns) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        findings.push({
          severity: pattern.severity,
          category: pattern.type,
          title: this.getTitle(pattern.type),
          location: location,
          evidence: this.truncate(match, 50),
          recommendation: this.getRecommendation(pattern.type)
        });
      }
    }

    // Check environment access
    for (const pattern of this.envAccessPatterns) {
      const matches = this.findMatches(code, pattern.pattern);
      for (const match of matches) {
        findings.push({
          severity: pattern.severity,
          category: pattern.type,
          title: this.getTitle(pattern.type),
          location: location,
          evidence: match,
          recommendation: this.getRecommendation(pattern.type)
        });
      }
    }

    return findings;
  }

  /**
   * Find all matches of a pattern in code
   */
  findMatches(code, pattern) {
    const matches = [];
    let match;

    // Reset lastIndex for global patterns
    const re = new RegExp(pattern.source, pattern.flags);

    while ((match = re.exec(code)) !== null) {
      matches.push(match[0]);
      // Prevent infinite loop for zero-length matches
      if (match.index === re.lastIndex) {
        re.lastIndex++;
      }
    }

    return matches;
  }

  /**
   * Detect hidden code in HTML comments, etc.
   */
  detectHiddenCode(content) {
    const findings = [];

    // HTML comments containing code
    const htmlCommentPattern = /<!--[\s\S]*?(eval|exec|execSync|spawn|curl|wget|import|require|child_process)/gi;
    const htmlMatches = content.match(htmlCommentPattern);
    if (htmlMatches) {
      for (const match of htmlMatches) {
        findings.push({
          severity: 'HIGH',
          category: 'hidden_code',
          title: 'Hidden code in HTML comments',
          location: 'inline:html',
          evidence: this.truncate(match, 50),
          recommendation: 'Remove code from HTML comments'
        });
      }
    }

    // Zero-width characters
    if (/[\u200B\u200C\u200D\uFEFF]/.test(content)) {
      findings.push({
        severity: 'CRITICAL',
        category: 'zero_width_characters',
        title: 'Zero-width characters detected',
        location: 'SKILL.md',
        evidence: 'Zero-width unicode characters found in content',
        recommendation: 'Remove all zero-width characters from content'
      });
    }

    // Bidi override
    if (/[\u202A-\u202E]/.test(content)) {
      findings.push({
        severity: 'CRITICAL',
        category: 'bidi_override',
        title: 'Bidi override characters detected',
        location: 'SKILL.md',
        evidence: 'RTL/LTR override characters found',
        recommendation: 'Remove all Bidi override characters'
      });
    }

    return findings;
  }

  getTitle(type) {
    const titles = {
      'dynamic_execution': 'Dynamic code execution detected',
      'dynamic_import': 'Dynamic module import detected',
      'dynamic_compilation': 'Dynamic code compilation detected',
      'dynamic_function': 'Dynamic function creation detected',
      'command_execution': 'Command execution capability detected',
      'process_spawning': 'Process spawning detected',
      'shell_execution': 'Shell execution detected',
      'credential_exfiltration': 'Credential exfiltration pattern detected',
      'data_exfiltration': 'Data exfiltration pattern detected',
      'reverse_shell': 'Reverse shell pattern detected',
      'command_injection': 'Command injection vulnerability',
      'shell_injection': 'Shell injection vulnerability',
      'sensitive_file_read': 'Sensitive file read attempt',
      'credential_access': 'Credential access detected',
      'persistence': 'Persistence mechanism detected',
      'privilege_escalation': 'Privilege escalation attempt',
      'code_obfuscation': 'Code obfuscation detected',
      'obfuscated_execution': 'Obfuscated execution detected',
      'jsfuck_obfuscation': 'JSFuck obfuscation detected',
      'hex_obfuscation': 'Hex-encoded string detected',
      'unicode_obfuscation': 'Unicode escape sequence detected',
      'zero_width_characters': 'Zero-width characters detected',
      'bidi_override': 'Bidi override characters detected',
      'base64_decode': 'Base64 decoding detected',
      'base64_encode': 'Base64 encoding detected',
      'string_splitting': 'String splitting detected',
      'env_access': 'Environment variable access detected',
    };
    return titles[type] || type;
  }

  getRecommendation(type) {
    const recommendations = {
      'dynamic_execution': 'Avoid using eval/exec with user input',
      'dynamic_import': 'Use static imports instead of dynamic imports',
      'reverse_shell': 'This pattern indicates potential malicious code',
      'credential_exfiltration': 'Review for accidental credential leakage',
      'persistence': 'Document why persistence is required',
      'privilege_escalation': 'Avoid privilege escalation attempts',
      'zero_width_characters': 'Remove zero-width characters from content',
      'bidi_override': 'Remove Bidi override characters',
    };
    return recommendations[type] || 'Review and verify this code is necessary';
  }

  truncate(str, len) {
    if (str.length <= len) return str;
    return str.substring(0, len) + '...';
  }
}

module.exports = SASTAnalyzer;
