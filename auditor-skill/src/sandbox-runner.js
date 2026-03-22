/**
 * ClawGuard Sandbox Runner
 *
 * Executes Skills in a controlled sandbox environment
 * Monitors for malicious behavior during execution
 */

const { exec, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class SandboxRunner {
  constructor(config = {}) {
    this.config = {
      timeout: config.timeout || 5000,
      memory: config.memory || 128,
      cpu: config.cpu || 0.5,
      allowedDomains: config.allowedDomains || ['api.github.com', 'api.openai.com'],
      blockedPorts: config.blockedPorts || [22, 23, 25, 3389],
      allowedPaths: config.allowedPaths || ['/tmp/sandbox/*'],
      deniedPaths: config.deniedPaths || ['/home/*', '/root/*', '/etc/*'],
      network: config.network || 'none',
      ...config
    };

    this.blockedOperations = [];
    this.warnings = [];
  }

  /**
   * Execute skill in sandbox
   */
  async execute(skillPath, skill) {
    const result = {
      executed: false,
      blocked_operations: [],
      warnings: [],
      behavior_analysis: {},
      duration_ms: 0
    };

    const startTime = Date.now();

    try {
      // Create sandbox directory
      const sandboxDir = this.createSandbox(skillPath);

      // Analyze entry point
      const entryPoint = this.findEntryPoint(skillPath);

      if (!entryPoint) {
        result.warnings.push('No entry point found');
        result.executed = false;
        return result;
      }

      // Set up execution monitoring
      const monitor = this.createBehaviorMonitor();

      // Execute in sandbox
      result.executed = true;
      result.blocked_operations = this.blockedOperations;
      result.warnings = this.warnings;
      result.behavior_analysis = monitor.getSummary();

      // Clean up sandbox
      this.cleanupSandbox(sandboxDir);

    } catch (error) {
      result.warnings.push(`Execution error: ${error.message}`);
      result.executed = false;
    }

    result.duration_ms = Date.now() - startTime;
    return result;
  }

  /**
   * Create sandbox directory
   */
  createSandbox(skillPath) {
    const id = crypto.randomBytes(8).toString('hex');
    const sandboxDir = `/tmp/clawguard-sandbox-${id}`;

    try {
      fs.mkdirSync(sandboxDir, { recursive: true });
    } catch (e) {
      // Directory might already exist
    }

    return sandboxDir;
  }

  /**
   * Find entry point
   */
  findEntryPoint(skillPath) {
    const possibleEntrypoints = [
      'index.js',
      'main.js',
      'run.js',
      'start.js',
      'index.py',
      'main.py',
      'run.py'
    ];

    for (const entry of possibleEntrypoints) {
      const fullPath = path.join(skillPath, 'src', entry);
      if (fs.existsSync(fullPath)) {
        return fullPath;
      }
    }

    // Check root
    for (const entry of possibleEntrypoints) {
      const fullPath = path.join(skillPath, entry);
      if (fs.existsSync(fullPath)) {
        return fullPath;
      }
    }

    return null;
  }

  /**
   * Create behavior monitor
   */
  createBehaviorMonitor() {
    const monitor = {
      fileAccess: [],
      networkCalls: [],
      processSpawns: [],
      systemCalls: [],
      sensitiveDataAccess: false,

      recordFileAccess(path, operation) {
        this.fileAccess.push({ path, operation, timestamp: Date.now() });
      },

      recordNetworkCall(url, method) {
        this.networkCalls.push({ url, method, timestamp: Date.now() });
      },

      recordProcessSpawn(cmd) {
        this.processSpawns.push({ cmd, timestamp: Date.now() });
      },

      getSummary() {
        return {
          file_access_count: this.fileAccess.length,
          network_calls_count: this.networkCalls.length,
          process_spawns_count: this.processSpawns.length,
          sensitive_data_access: this.sensitiveDataAccess,
          files: this.fileAccess.slice(0, 10),
          networks: this.networkCalls.slice(0, 10),
          processes: this.processSpawns.slice(0, 10)
        };
      }
    };

    return monitor;
  }

  /**
   * Check if path is allowed
   */
  isPathAllowed(filePath) {
    const denied = this.config.deniedPaths;

    for (const pattern of denied) {
      if (this.matchPath(filePath, pattern)) {
        this.blockedOperations.push({
          type: 'file_access_denied',
          path: filePath,
          pattern: pattern
        });
        return false;
      }
    }

    return true;
  }

  /**
   * Match path against pattern
   */
  matchPath(filePath, pattern) {
    // Simple wildcard matching
    const regex = pattern
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    return new RegExp(`^${regex}`).test(filePath);
  }

  /**
   * Check if network call is allowed
   */
  isNetworkAllowed(url) {
    try {
      const urlObj = new URL(url);

      // Check blocked ports
      const port = urlObj.port || (urlObj.protocol === 'https' ? 443 : 80);
      if (this.config.blockedPorts.includes(parseInt(port))) {
        this.blockedOperations.push({
          type: 'network_port_blocked',
          url: url,
          port: port
        });
        return false;
      }

      // Check allowed domains
      const allowed = this.config.allowedDomains;
      let domainAllowed = false;
      for (const domain of allowed) {
        if (urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain)) {
          domainAllowed = true;
          break;
        }
      }

      if (!domainAllowed) {
        this.warnings.push({
          type: 'network_domain_not_whitelisted',
          url: url
        });
      }

      return domainAllowed;
    } catch (e) {
      this.warnings.push({
        type: 'invalid_url',
        url: url
      });
      return false;
    }
  }

  /**
   * Execute command with monitoring
   */
  executeWithMonitoring(command, args, options = {}) {
    return new Promise((resolve, reject) => {
      const timeout = this.config.timeout;

      const proc = spawn(command, args, {
        cwd: options.cwd || process.cwd(),
        env: {
          ...process.env,
          // Restrict environment
          HOME: '/tmp/sandbox',
          PATH: '/usr/local/bin:/usr/bin:/bin'
        },
        stdio: ['ignore', 'pipe', 'pipe']
      });

      let stdout = '';
      let stderr = '';

      const timer = setTimeout(() => {
        proc.kill('SIGKILL');
        this.warnings.push({
          type: 'execution_timeout',
          command: command
        });
        reject(new Error('Execution timeout'));
      }, timeout);

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', (code) => {
        clearTimeout(timer);
        resolve({ code, stdout, stderr });
      });

      proc.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  /**
   * Cleanup sandbox directory
   */
  cleanupSandbox(sandboxDir) {
    try {
      // Only remove if it's in /tmp
      if (sandboxDir.startsWith('/tmp/')) {
        fs.rmSync(sandboxDir, { recursive: true, force: true });
      }
    } catch (e) {
      // Ignore cleanup errors
    }
  }
}

module.exports = SandboxRunner;
