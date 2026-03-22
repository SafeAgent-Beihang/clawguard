---
name: clawguard-security-checker
version: 1.0.0
description: ClawGuard Enterprise Security Checker - Advanced configuration analysis, runtime integrity verification, permission modeling, and quantum-resistant integrity checking for OpenClaw environments
author: ClawGuard Team
homepage: https://github.com/clawguard/security-checker
metadata:
  category: security
  risk: safe
  requires:
    bins: [node, python3, jq, grep, sha256sum, openssl, stat, ls]
    python: [pyyaml, cryptography]
---

# ClawGuard Security Checker (CG-SC)

Enterprise-grade security configuration analyzer and runtime integrity verifier for OpenClaw environments. Provides comprehensive security posture assessment with advanced configuration analysis, permission modeling, and quantum-resistant cryptographic verification.

## When to Use

Activate ClawGuard Checker when:
- A user asks to check the security status of the OpenClaw instance
- Periodic security review is needed
- After configuration changes

## How to Execute

Follow these steps when performing a security check:

### Step 1: Check Configuration File
- Find and read `~/.openclaw/openclaw.json`
- Verify these security settings:
  - `gateway.bind` should be "localhost" (not "0.0.0.0" or "lan")
  - `gateway.tls.enabled` should be true
  - `gateway.auth.deviceAuth` should be true
  - `tools.profile` should be "restricted" (not "full")
  - `tools.fs.workspaceOnly` should be true

### Step 2: Check for Exposed Credentials
Search for exposed secrets in:
- Config files (API keys, tokens, passwords)
- Environment files (.env)
- Log files

### Step 3: Check File Permissions
Verify these permissions:
- `~/.openclaw/openclaw.json` should be 600 (owner read/write only)
- `~/.openclaw/` directory should be 700
- SSH keys should be 600
- Not running as root user

### Step 4: Check Network Settings
- Gateway port should not be exposed to 0.0.0.0
- Trusted proxies should be limited
- Rate limiting should be enabled

### Step 5: Check Logs
Review recent logs for:
- Authentication failures
- Privilege escalation attempts
- Suspicious commands

### Step 6: Output Result
Calculate security score and output:
- Score: 0-100
- Grade: A+ to F
- List of issues found
- Recommendations

## Purpose

ClawGuard Security Checker is the second line of defense, providing continuous security posture monitoring for OpenClaw instances. It verifies:

- **Configuration Security**: Comprehensive analysis of OpenClaw configuration files
- **Runtime Integrity**: Cryptographic verification of system files and runtime components
- **Permission Modeling**: Advanced permission analysis and least-privilege enforcement
- **Network Security**: Multi-layered network policy validation
- **Log Forensics**: AI-powered anomaly detection in audit logs
- **Compliance**: Security benchmark compliance checking

## Prerequisites

### Authorization Requirements
- Read access to OpenClaw configuration directory (`~/.openclaw/`)
- Read access to system logs
- Network analysis capabilities (optional)

### Environment Setup
- Node.js 18+ runtime
- Python 3.8+ runtime
- OpenClaw instance running or recently ran

## Core Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│               CLAWGUARD SECURITY CHECKER WORKFLOW               │
└─────────────────────────────────────────────────────────────────┘

    [Scheduled/Manual Check Trigger]
                │
                ▼
    ┌───────────────────────┐
    │  1. CONFIGURATION     │ ← Parse and validate openclaw.json
    │     ANALYSIS           │
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  2. CREDENTIAL SCAN   │ ← Detect exposed secrets
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  3. PERMISSION        │ ← File/directory permission analysis
    │     MODELING           │
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  4. RUNTIME INTEGRITY │ ← SHA-256 + quantum-resistant hashes
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  5. NETWORK SECURITY  │ ← Port, firewall, proxy analysis
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  6. LOG FORENSICS     │ ← Anomaly detection in logs
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  7. COMPLIANCE        │ ← Benchmark compliance checking
    │     CHECKING           │
    └───────────┬───────────┘
                │ PASS
                ▼
         [SECURITY REPORT]
```

## Phase 1: Configuration Analysis

### Configuration File Schema

The analyzer examines `openclaw.json` for security-relevant settings:

```json
{
  "gateway": {
    "bind": "localhost",
    "port": 8080,
    "tls": {
      "enabled": true,
      "certPath": "/path/to/cert.pem",
      "keyPath": "/path/to/key.pem"
    },
    "auth": {
      "deviceAuth": true,
      "tokenExpiry": 3600
    },
    "cors": {
      "allowedOrigins": ["https://example.com"]
    }
  },
  "tools": {
    "profile": "restricted",
    "fs": {
      "workspaceOnly": true,
      "allowedPaths": ["/workspace/*"]
    },
    "network": {
      "egressRestrictions": true,
      "allowedDomains": ["api.github.com", "api.openai.com"]
    },
    "exec": {
      "allowedCommands": ["git", "npm", "node"]
    }
  },
  "security": {
    "update": {
      "checkOnStart": true,
      "autoUpdate": false
    },
    "audit": {
      "enabled": true,
      "retentionDays": 30
    }
  }
}
```

### Configuration Security Checks

| Check | Severity | Points | Detection Rule |
|-------|----------|--------|----------------|
| API Key in config | CRITICAL | -20 | Regex: `sk-*[a-zA-Z0-9]` |
| Gateway bind 0.0.0.0 | HIGH | -15 | `gateway.bind === "0.0.0.0"` |
| Gateway bind lan | HIGH | -10 | `gateway.bind === "lan"` |
| CORS * allowed | MEDIUM | -5 | `allowedOrigins.includes("*")` |
| tools.profile full | HIGH | -10 | `tools.profile === "full"` |
| Device auth disabled | HIGH | -10 | `deviceAuth === false` |
| Token expiry > 24h | MEDIUM | -5 | `tokenExpiry > 86400` |
| TLS not enabled | MEDIUM | -10 | `tls.enabled === false` |
| fs.workspaceOnly false | HIGH | -10 | `fs.workspaceOnly === false` |
| No egress restrictions | HIGH | -10 | `network.egressRestrictions === false` |

### Enhanced Credential Detection

ClawGuard uses multi-pattern detection for exposed credentials:

```javascript
const CREDENTIAL_PATTERNS = [
  // API Keys
  { pattern: /sk-[a-zA-Z0-9]{20,}/g, type: 'openai_key', severity: 'CRITICAL' },
  { pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/g, type: 'anthropic_key', severity: 'CRITICAL' },
  { pattern: /AKIA[0-9A-Z]{16}/g, type: 'aws_access_key', severity: 'CRITICAL' },
  { pattern: /ghp_[a-zA-Z0-9]{36}/g, type: 'github_token', severity: 'CRITICAL' },
  { pattern: /gho_[a-zA-Z0-9]{36}/g, type: 'github_oauth', severity: 'CRITICAL' },
  { pattern: /glpat-[a-zA-Z0-9_-]{20}/g, type: 'gitlab_token', severity: 'CRITICAL' },
  { pattern: /[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]+@/g, type: 'url_credentials', severity: 'HIGH' },

  // Private Keys
  { pattern: /-----BEGIN (RSA |DSA |EC |OPENSSH) PRIVATE KEY-----/g, type: 'private_key', severity: 'CRITICAL' },
  { pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, type: 'pgp_key', severity: 'CRITICAL' },

  // Generic Secrets
  { pattern: /api[_-]?key["\s:=]+[a-zA-Z0-9]{16,}/gi, type: 'api_key', severity: 'HIGH' },
  { pattern: /secret["\s:=]+["'][a-zA-Z0-9]{16,}["']/gi, type: 'secret', severity: 'HIGH' },
  { pattern: /password["\s:=]+["'][^"']+["']/gi, type: 'password', severity: 'HIGH' },
];
```

## Phase 2: Credential Exposure Detection

### Multi-Layer Credential Scanning

| Layer | Target | Method |
|-------|--------|--------|
| Layer 1 | Configuration files | Pattern matching |
| Layer 2 | Environment files (.env) | Direct file scan |
| Layer 3 | Log files | Historical credential check |
| Layer 4 | Memory dumps | Process memory (optional) |

### Detection Rules

| Credential Type | Pattern | Severity | Action |
|---------------|---------|----------|--------|
| AWS Access Key | `AKIA...` | CRITICAL | Alert + Rotate |
| GitHub Token | `ghp_...` | CRITICAL | Alert + Revoke |
| OpenAI Key | `sk-...` | CRITICAL | Alert + Revoke |
| Private Key | `-----BEGIN...` | CRITICAL | Alert + Alert SOC |
| Database URL | `postgres://...` | HIGH | Alert |
| Generic Secret | `api_key=...` | HIGH | Review |

## Phase 3: Permission Modeling

### File System Permission Analysis

```javascript
const CRITICAL_PATHS = [
  { path: '~/.openclaw/openclaw.json', expectedMode: '600', severity: 'HIGH' },
  { path: '~/.openclaw/', expectedMode: '700', severity: 'HIGH' },
  { path: '/workspace/', expectedMode: '750', severity: 'MEDIUM' },
  { path: '~/.ssh/', expectedMode: '700', severity: 'CRITICAL' },
  { path: '~/.aws/', expectedMode: '700', severity: 'CRITICAL' },
];
```

### Permission Check Matrix

| Check | Severity | Points | Rule |
|-------|----------|--------|------|
| Config file world-readable | CRITICAL | -20 | Mode & 007 !== 0 |
| Config file group-readable | HIGH | -10 | Mode & 070 !== 0 |
| Workspace world-writable | HIGH | -15 | Mode & 002 !== 0 |
| SSH keys world-readable | CRITICAL | -20 | Mode & 004 !== 0 |
| Running as root | CRITICAL | -25 | UID === 0 |
| Skill directory +x | MEDIUM | -5 | Mode & 001 !== 0 |

### Advanced Permission Modeling

ClawGuard performs **capability-based permission analysis**:

```javascript
const PERMISSION_MATRIX = {
  'filesystem.read': {
    'workspace': { allowed: true, scope: 'read-only' },
    'home': { allowed: false, scope: 'denied' },
    'system': { allowed: false, scope: 'denied' }
  },
  'filesystem.write': {
    'workspace': { allowed: true, scope: 'read-write' },
    'home': { allowed: false, scope: 'denied' },
    'system': { allowed: false, scope: 'denied' }
  },
  'network.egress': {
    'trusted': { allowed: true, scope: 'whitelisted domains' },
    'untrusted': { allowed: false, scope: 'denied' }
  },
  'execution': {
    'tools': { allowed: true, scope: 'tool whitelist' },
    'arbitrary': { allowed: false, scope: 'denied' }
  }
};
```

## Phase 4: Runtime Integrity Verification

### Multi-Layer Integrity Checking

#### Layer 1: SHA-256 Baseline

```javascript
const BASELINE_FILES = [
  '/usr/local/lib/openclaw/core.js',
  '/usr/local/lib/openclaw/gateway.js',
  '/usr/local/lib/openclaw/tools/*.js',
  '/workspace/skills/*/SKILL.md'
];
```

#### Layer 2: Quantum-Resistant Hashing

ClawGuard uses **SPHINCS+** signatures for future-proof integrity:

```javascript
const QUANTUM_RESISTANT_ALGORITHMS = [
  'SHAKE256',    // SHA-3 extendable output
  'SHA3-512',    // SHA-3 with 512-bit output
  'BLAKE3',      // Fast hash with HMAC
];
```

#### Layer 3: Signed Baseline

```
┌─────────────────────────────────────────────────────┐
│            INTEGRITY VERIFICATION CHAIN             │
├─────────────────────────────────────────────────────┤
│ 1. Generate file manifests                         │
│ 2. Compute SHA-256 for each file                   │
│ 3. Create merkle tree of hashes                    │
│ 4. Sign root hash with Ed25519 (hybrid: RSA-4096) │
│ 5. Store baseline in TPM (if available)           │
│ 6. On check: verify signature + all hashes        │
└─────────────────────────────────────────────────────┘
```

### Integrity Check Results

| Check | Status | Action |
|-------|--------|--------|
| Core files unchanged | ✓ | Continue |
| Core files modified | ✗ | Alert + Quarantine |
| Skill files unchanged | ✓ | Continue |
| New skill detected | ? | Trigger Auditor |
| Signature valid | ✓ | Continue |
| Signature invalid | ✗ | Alert + Verify manually |

## Phase 5: Network Security Analysis

### Port and Binding Analysis

| Check | Severity | Points | Detection |
|-------|----------|--------|-----------|
| Gateway on 0.0.0.0 | HIGH | -15 | Exposed to all interfaces |
| Gateway on lan | MEDIUM | -10 | Exposed to local network |
| Gateway on localhost | LOW | 0 | Only local access |
| Non-standard port | LOW | -2 | Port != 8080/8443 |

### Advanced Network Analysis

```javascript
const NETWORK_SECURITY_CHECKS = [
  {
    check: 'trusted_proxies',
    rule: (config) => config.trustedProxies?.length <= 2,
    severity: 'MEDIUM',
    points: -5,
    message: 'Limited proxy trust for reverse proxy setups'
  },
  {
    check: 'rate_limiting',
    rule: (config) => config.rateLimit?.enabled === true,
    severity: 'HIGH',
    points: -10,
    message: 'Rate limiting not enabled'
  },
  {
    check: 'egress_whitelist',
    rule: (config) => config.network?.allowedDomains?.length > 0,
    severity: 'HIGH',
    points: -10,
    message: 'No egress domain whitelist configured'
  },
  {
    check: 'dns_restrictions',
    rule: (config) => config.network?.dnsWhitelist?.length > 0,
    severity: 'MEDIUM',
    points: -5,
    message: 'No DNS restriction configured'
  }
];
```

### Firewall Status Verification

| Check | Severity | Points |
|-------|----------|--------|
| iptables active | LOW | 0 |
| UFW active | LOW | 0 |
| No firewall | MEDIUM | -5 |
| Docker network isolated | LOW | 0 |

## Phase 6: Log Forensics

### Log Analysis Engine

ClawGuard analyzes logs for:

1. **Authentication Failures**: Repeated failed logins
2. **Privilege Escalation**: sudo/permission change attempts
3. **Data Exfiltration**: Large data transfers
4. **Red Line Triggers**: Security policy violations
5. **Anomaly Detection**: Unusual patterns using ML

### Anomaly Detection Rules

```javascript
const LOG_ANOMALY_PATTERNS = [
  {
    name: 'brute_force',
    pattern: /authentication failure/i,
    threshold: 10,
    window: '5m',
    severity: 'HIGH'
  },
  {
    name: 'mass_file_access',
    pattern: /file read.*\.{5,}/i,
    threshold: 100,
    window: '1m',
    severity: 'MEDIUM'
  },
  {
    name: 'data_exfiltration',
    pattern: /(curl|wget).*post.*\d{4,}/i,
    threshold: 1,
    window: '1h',
    severity: 'CRITICAL'
  },
  {
    name: 'privilege_escalation',
    pattern: /(sudo|chmod|chown).*(root|777)/i,
    threshold: 1,
    window: '5m',
    severity: 'CRITICAL'
  },
  {
    name: 'red_line_trigger',
    pattern: /REDLINE:.*/i,
    threshold: 1,
    window: '0',
    severity: 'CRITICAL'
  }
];
```

## Phase 7: Compliance Checking

### Security Benchmarks

| Benchmark | Framework | Checks |
|-----------|-----------|--------|
| CIS Docker | CIS Docker Benchmark | 20 checks |
| NSA Docker | NSA Docker Guide | 15 checks |
| CISA KSC | CISA Kubernetes | 25 checks |
| Custom | ClawGuard Best Practices | 30 checks |

### Compliance Report

```
COMPLIANCE SUMMARY
═══════════════════
CIS Docker Benchmark:     15/20 (75%)
NSA Docker Guide:        12/15 (80%)
CISA KSC:               18/25 (72%)
ClawGuard Best Practices: 25/30 (83%)

OVERALL: B (80%)
```

## Security Scoring

### Scoring Formula

```
SECURITY_SCORE = 100 - CONFIG_PENALTY - CREDENTIAL_PENALTY - PERMISSION_PENALTY - INTEGRITY_PENALTY - NETWORK_PENALTY - LOG_PENALTY

Where:
- CONFIG_PENALTY = Sum of all config check points (negative)
- CREDENTIAL_PENALTY = Critical * 20 + High * 10 + Medium * 5
- PERMISSION_PENALTY = Sum of permission check points
- INTEGRITY_PENALTY = Failed checks * 15
- NETWORK_PENALTY = Sum of network check points
- LOG_PENALTY = Critical * 15 + High * 10 + Medium * 5
```

### Score Classification

| Grade | Score | Color | Action |
|-------|-------|-------|--------|
| **A+** | 95-100 | 🟢 | Excellent - Continue monitoring |
| **A** | 90-94 | 🟢 | Good - Minor improvements possible |
| **B** | 80-89 | 🟢 | Satisfactory - Address warnings |
| **C** | 70-79 | 🟡 | Fair - Fix within 1 week |
| **D** | 60-69 | 🟠 | Poor - Fix within 24 hours |
| **F** | 0-59 | 🔴 | Critical - Fix immediately |

## Output Formats

### JSON Report

```json
{
  "report_id": "CGSC-2026-0001",
  "timestamp": "2026-03-14T10:30:00Z",
  "instance": {
    "name": "openclaw-abc123",
    "version": "2026.3.11",
    "deployment": "docker"
  },
  "security_score": 82,
  "grade": "B",
  "checks": {
    "configuration": {
      "score": -15,
      "issues": [
        {
          "severity": "HIGH",
          "check": "gateway_bind_lan",
          "message": "Gateway bound to lan interface",
          "location": "openclaw.json:gateway.bind"
        }
      ]
    },
    "credentials": {
      "score": 0,
      "issues": []
    },
    "permissions": {
      "score": -5,
      "issues": [
        {
          "severity": "MEDIUM",
          "check": "workspace_permission",
          "message": "Workspace directory mode 755, recommended 750"
        }
      ]
    },
    "integrity": {
      "score": 0,
      "status": "VERIFIED",
      "files_checked": 45
    },
    "network": {
      "score": -8,
      "issues": []
    },
    "logs": {
      "score": 0,
      "anomalies": []
    }
  },
  "compliance": {
    "cis_docker": "75%",
    "nsa_docker": "80%",
    "clawguard": "83%"
  },
  "recommendations": [
    "Change gateway.bind from 'lan' to 'localhost'",
    "Set workspace directory mode to 750"
  ]
}
```

### Terminal Output

```
╔══════════════════════════════════════════════════════════════╗
║        🛡️ CLAWGUARD SECURITY CHECK REPORT v1.0.0          ║
╠══════════════════════════════════════════════════════════════╣
║ Instance: openclaw-abc123                                  ║
║ Version: 2026.3.11                                        ║
║ Deployment: Docker                                        ║
║ Time: 2026-03-14 10:30:00 UTC                            ║
╚══════════════════════════════════════════════════════════════╝

▶ CONFIGURATION SECURITY [-15]
  ⚠️ [HIGH] Gateway bind: lan (recommend: localhost)
  ✓ TLS enabled
  ✓ Device auth enabled
  ✓ Token expiry: 3600s

▶ CREDENTIAL EXPOSURE [0]
  ✓ No exposed credentials detected
  ✓ No secrets in environment
  ✓ No credentials in logs

▶ PERMISSION MODELING [-5]
  ⚠️ [MEDIUM] Workspace mode 755 (recommend 750)
  ✓ Config file mode 600
  ✓ OpenClaw directory mode 700

▶ RUNTIME INTEGRITY [0]
  ✓ Core files verified
  ✓ Signatures valid
  ✓ Baseline current

▶ NETWORK SECURITY [-8]
  ⚠️ [MEDIUM] Limited trusted proxies
  ✓ Port 8080 (non-standard)
  ✓ No direct internet exposure

▶ LOG FORENSICS [0]
  ✓ No authentication failures
  ✓ No red line triggers
  ✓ No data exfiltration attempts

▶ COMPLIANCE
  CIS Docker: 75% | NSA Docker: 80% | ClawGuard: 83%

╔══════════════════════════════════════════════════════════════╗
║ SECURITY GRADE: B (82/100)                                ║
╠══════════════════════════════════════════════════════════════╣
║ CRITICAL: 0 | HIGH: 1 | MEDIUM: 2 | LOW: 1              ║
╠══════════════════════════════════════════════════════════════╣
║ RECOMMENDATIONS:                                           ║
║ 1. Change gateway.bind to 'localhost'                      ║
║ 2. Set workspace directory mode to 750                     ║
╚══════════════════════════════════════════════════════════════╝
```

## Integration with OpenClaw

### Automatic Scanning

Configure automatic security checks in `openclaw.json`:

```json
{
  "security": {
    "clawguard": {
      "checker": {
        "enabled": true,
        "schedule": "0 2 * * *",  // Daily at 2 AM
        "auto_remediate": false,
        "alert_on_fail": true
      }
    }
  }
}
```

### Manual Check

```bash
# Run security check
clawguard check --full

# Run specific check
clawguard check --config
clawguard check --permissions
clawguard check --integrity
```

## Author

**ClawGuard Team** - Enterprise Security for Autonomous Agents

---

*ClawGuard Security Checker: Vigilant protection for your AI agents.* 🦅
