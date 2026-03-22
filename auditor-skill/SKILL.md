---
name: auditor-skill
version: 1.0.0
description: ClawGuard Enterprise-grade Security Auditor - Advanced SAST, Semantic Intent Analysis, Supply Chain Security, and ML-based Anomaly Detection for OpenClaw Skills
author: ClawGuard Team
homepage: https://github.com/clawguard/auditor
metadata:
  category: security
  risk: safe
  requires:
    bins: [node, python3, grep, sha256sum, file]
    npm: [esprima, html-entities]
    python: [pyyaml, python-dateutil]
---

# ClawGuard Auditor (CG-A)

Enterprise-grade Security Kernel for OpenClaw Skills. ClawGuard Auditor provides comprehensive pre-flight static and semantic analysis, supply chain security verification, and AI-powered anomaly detection.

## When to Use

Activate ClawGuard Auditor when:
- A user asks to install or load a new Skill
- A user asks to audit an existing Skill or repository
- A new external code source is being added to the environment

## How to Execute

Follow these steps when auditing a Skill:

### Step 1: Read the Target Skill
- Find and read the `SKILL.md` file in the target directory
- Read all code files (.js, .py, .sh, etc.)

### Step 2: Check Metadata
- Verify the SKILL.md has valid frontmatter (name, version, description)
- Check if the `metadata.risk` field is "safe"
- Check for suspicious binaries in `metadata.requires`

### Step 3: Scan for Dangerous Patterns
Search for these dangerous patterns in the code:
- `eval()`, `exec()`, `__import__()`, `compile()` - dynamic code execution
- `child_process.exec`, `subprocess.Popen` - command execution
- `curl` or `wget` with credentials - data exfiltration
- Reverse shell patterns: `bash -i`, `/dev/tcp/`, `nc -e`, `python.*socket`
- Reading sensitive files: `~/.ssh/`, `~/.aws/`, `.env`
- Writing to persistence locations: `authorized_keys`, crontab

### Step 4: Check Intent Match
- Compare what the Skill claims to do (description) vs what the code actually does
- If a "Weather Tool" reads SSH keys, that's an INTENT MISMATCH

### Step 5: Check Dependencies
- Look at package.json, requirements.txt, go.mod
- Flag known malicious packages

### Step 6: Output Result
Based on findings, output one of:
- **APPROVED**: No critical issues found
- **CONDITIONAL**: Some concerns, needs human review
- **REJECTED**: Critical security issues detected

## Purpose

ClawGuard Auditor is the first line of defense for OpenClaw environments. Before any Skill is installed or executed, it performs rigorous security analysis covering:

- **Advanced SAST**: Static Application Security Testing with comprehensive rule coverage
- **Semantic Intent Analysis**: AI-powered behavioral profiling to detect intent mismatches
- **Supply Chain Security**: Dependency verification, typo-squatting detection, CVE scanning
- **ML-based Anomaly Detection**: Machine learning models to identify novel attack patterns
- **Obfuscation Detection**: Multi-layer obfuscation and encoding attack detection
- **Quantum-resistant Cryptography**: Future-proof integrity verification

## Prerequisites

### Authorization Requirements
- Read access to target Skill directory
- Network access for dependency verification (optional)
- Execution environment for sandbox testing (optional)

### Environment Setup
- Node.js 18+ runtime
- Python 3.8+ runtime
- Internet access for supply chain verification (optional)

## Core Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLAWGUARD AUDITOR WORKFLOW                   │
└─────────────────────────────────────────────────────────────────┘

    [Skill Installation Request]
                │
                ▼
    ┌───────────────────────┐
    │  1. METADATA VALIDATION  │ ← Frontmatter parsing & validation
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  2. PROVENANCE ANALYSIS │ ← Source trust scoring
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  3. SAST ANALYSIS       │ ← Advanced static analysis
    │  ├─ Execution Risks     │
    │  ├─ Network Anomalies   │
    │  ├─ File System Threats │
    │  └─ Obfuscation检测     │
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  4. SEMANTIC INTENT     │ ← AI-powered behavior analysis
    │     ANALYSIS            │
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  5. SUPPLY CHAIN       │ ← Dependency & CVE analysis
    │     SECURITY            │
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  6. ML ANOMALY         │ ← Novel pattern detection
    │     DETECTION           │
    └───────────┬───────────┘
                │ PASS
                ▼
    ┌───────────────────────┐
    │  7. SANDBOX EXECUTION  │ ← Dynamic behavior testing
    └───────────┬───────────┘
                │ PASS
                ▼
         [AUDIT COMPLETE]
```

## Phase 1: Metadata Validation

### Frontmatter Schema

| Field | Required | Validation Rules |
|-------|----------|------------------|
| name | YES | Must match directory name, lowercase with hyphens |
| version | YES | Must be valid semver (e.g., 1.0.0) |
| description | YES | Min 10 chars, max 500 chars |
| author | NO | If present, validate format |
| homepage | NO | If present, must be valid HTTPS URL |
| metadata.category | YES | Must be one of: security, utility, data, integration |
| metadata.risk | YES | Must be "safe" for new Skills |
| metadata.requires | NO | If present, validate each binary exists |

### Validation Rules

| Check | Severity | Action |
|-------|----------|--------|
| Missing YAML frontmatter | CRITICAL | REJECT |
| Invalid name format | HIGH | REJECT |
| Version not semver | MEDIUM | WARN |
| Missing description | MEDIUM | REJECT |
| risk != "safe" | HIGH | WARN |
| Suspicious binary in requires | CRITICAL | REJECT |

### Enhanced Binary Detection

Reject Skills requiring:
- Network tools: `nc`, `ncat`, `socat`, `netcat`, `socat`
- Remote access: `ssh`, `scp`, `rsync` (unless explicitly justified)
- Package managers: `pip install`, `npm install -g` (unless in sandbox)
- System modification: `chmod`, `chown`, `sudo` (unless documented)

## Phase 2: Provenance Analysis

### Trust Scoring Algorithm

```
TRUST_SCORE = BASE_SCORE + SOURCE_BONUS + HISTORY_BONUS - RISK_FACTORS

BASE_SCORE: 50
SOURCE_BONUS:
  - Official OpenClaw repo: +30
  - GitHub >1000 stars: +20
  - GitHub >500 stars: +15
  - Verified author: +10
  - Personal/Gist: -20

HISTORY_BONUS:
  - First seen >1 year ago: +10
  - Active maintenance (commit in last 6mo): +5

RISK_FACTORS:
  - No git history: -15
  - Single commit: -10
  - Many contributors but no reviews: -5
```

### Source Classification

| Classification | Score Range | Action |
|---------------|-------------|--------|
| **Trusted** | 80-100 | Auto-approve with standard logging |
| **Verified** | 60-79 | Approve with enhanced logging |
| **Unknown** | 40-59 | Manual review required |
| **Suspicious** | 20-39 | Deep audit required |
| **Untrusted** | 0-19 | Auto-reject |

## Phase 3: Advanced SAST Analysis

### Execution Risk Detection

#### Critical Patterns (Immediate Reject)

| Pattern | Description | Example |
|---------|-------------|---------|
| `exec()` | Dynamic code execution | `exec(user_input)` |
| `eval()` | String evaluation | `eval(code)` |
| `__import__()` | Dynamic imports | `__import__('os')` |
| `compile()` | Dynamic compilation | `compile(src, '', 'exec')` |
| `child_process.execSync` | Sync command execution | `execSync(cmd, {shell: true})` |
| `subprocess.Popen` | Process spawning | `Popen(shell=True)` |
| `os.system()` | Shell execution | `os.system(cmd)` |

#### High Risk Patterns (Block + Review)

| Pattern | Description | Example |
|---------|-------------|---------|
| `fetch()` to dynamic URL | Dynamic network requests | `fetch(url + userInput)` |
| `XMLHttpRequest` | Browser network | `new XMLHttpRequest()` |
| `WebSocket` | Real-time comms | `new WebSocket(url)` |
| `process.env` | Env access | `process.env[KEY]` |
| `os.environ` | Env access | `os.environ.get(KEY)` |

### Network Anomaly Detection

#### Critical Patterns

| Pattern | Severity | MITRE ATT&CK |
|---------|----------|--------------|
| `curl` with credentials | CRITICAL | T1041 |
| `wget` with credentials | CRITICAL | T1041 |
| Base64 encoded data to network | CRITICAL | T1132 |
| DNS exfiltration patterns | CRITICAL | T1048.003 |
| Hardcoded IP addresses | HIGH | T1059 |
| Reverse shell signatures | CRITICAL | T1059.004 |
| IPtables modification | HIGH | T1562 |

#### Reverse Shell Signatures (Enhanced Detection)

```javascript
// Comprehensive reverse shell patterns
const REVERSE_SHELL_PATTERNS = [
  // Bash
  /bash\s+-i\s+.*\/?dev\/tcp\//,
  /bash\s+-i\s+.*\/?dev\/udp\//,
  /\/bin\/sh\s+-i\s+.*\/?dev\/tcp\//,

  // Netcat
  /nc\s+.*-e\s+/,
  /ncat\s+.*-e\s+/,
  /nc\s+.*exec:/,
  /ncat\s+.*exec:/,

  // Python
  /python.*socket.*connect.*exec/i,
  /python.*subprocess.*call/i,
  /python.*pty\.spawn/i,

  // Perl
  /perl.*socket.*connect/i,
  /perl.*-e\s+.*socket/i,

  // Ruby
  /ruby.*socket.*connect/i,
  /ruby.*-e\s+.*spawn/i,

  // PHP
  /php.*fsockopen/i,
  /php.*socket_create.*connect/i,

  // Node.js
  /node.*child_process.*spawn.*\/bin\/sh/i,
  /node.*net\.connect.*exec/i,

  // Socat
  /socat\s+.*TCP:.*EXEC:/i,
  /socat\s+.*EXEC:/i,

  // PowerShell
  /powershell.*-NoP.*-NonI.*-W/i,
  /powershell.*IEX.*New-Object/i,
  /powershell.*tcp/i,

  // Tmux/Screen
  /tmux.*new-session.*-d.*-s/i,
  /screen.*-dmS/i,
];
```

### File System Threat Detection

#### Critical Paths (Read/Write Attempt = High Risk)

```javascript
const CRITICAL_PATHS = [
  // Credentials
  '/.ssh/',
  '/.aws/',
  '/.kube/',
  '/.gcp/',
  '/.docker/',
  '/.npm/',
  '/.pypirc/',

  // Environment & Config
  '/.env',
  '/.bashrc',
  '/.bash_profile',
  '/.zshrc',
  '/.profile',

  // System
  '/etc/passwd',
  '/etc/shadow',
  '/etc/sudoers',
  '/etc/cron',

  // Application
  '/home/',
  '/root/',
  '/var/',

  // OpenClaw specific
  '/.openclaw/',
  '/.claude/',
  '/workspace/MEMORY',
  '/workspace/IDENTITY',
  '/workspace/SOUL',
];
```

#### Detection Rules

| Pattern | Severity | Example |
|---------|----------|---------|
| Read critical path | HIGH | `readFile('/etc/passwd')` |
| Write to critical path | CRITICAL | `writeFile('/.ssh/authorized_keys')` |
| Modify cron | CRITICAL | `echo '* * * * *' >> /etc/crontab` |
| SSH key access | CRITICAL | `readFile('~/.ssh/id_rsa')` |

### Obfuscation Detection

#### Layer 1: Common Encodings

| Encoding | Detection Pattern | Risk |
|----------|------------------|------|
| Base64 | `/^[A-Za-z0-9+/]+={0,2}$/` with len > 20 | MEDIUM |
| Hex | `/^[0-9a-fA-F]+$/` with len > 16 | MEDIUM |
| URL Encoding | `%[0-9A-F]{2}` repeated | LOW |
| Unicode Escape | `\u[0-9A-F]{4}` | MEDIUM |

#### Layer 2: Advanced Obfuscation

| Technique | Detection | Risk |
|-----------|-----------|------|
| String concatenation to hide keywords | `'co'+'ncat'` | HIGH |
| Array join | `['co','ncat'].join('')` | HIGH |
| Character codes | `String.fromCharCode(99, 111, 110, 99, 97, 116)` | HIGH |
| Dynamic code evaluation | `new Function('code')()` | CRITICAL |
| JSFuck/JS禽兽 | `/\[!\+\[\]/.test(code)` | CRITICAL |
| Zero-width characters | `\u200B\u200C\u200D` | CRITICAL |
| Right-to-Left Override | `\u202E` | CRITICAL |

#### Layer 3: Multi-stage Obfuscation

Detect chains of encoding:
- Base64 → URL → Hex
- Character codes → eval
- Compression → Base64 → eval

## Phase 4: Semantic Intent Analysis

### Intent Mismatch Detection

Unlike basic vetters, ClawGuard analyzes if the Skill's **actual behavior** matches its **stated purpose**.

#### Analysis Process

1. **Extract stated purpose** from SKILL.md description
2. **Analyze actual behavior** from code
3. **Compute intent score** using semantic similarity
4. **Flag mismatches** if score < threshold

#### Example Mismatches

| Skill Description | Actual Behavior | Intent Score | Action |
|------------------|-----------------|--------------|--------|
| "Weather Formatter" | Reads `~/.ssh/id_rsa` | 0.2 | REJECT |
| "File Organizer" | Spawns background process | 0.4 | REJECT |
| "Markdown Helper" | Makes HTTP POST to unknown domain | 0.3 | REJECT |
| "Calculator" | Writes to `/etc/cron` | 0.1 | REJECT |

### Capability-Behavior Mapping

Map required capabilities to actual usage:

```javascript
const CAPABILITY_MATRIX = {
  'CAP_FS_READ': {
    allowed: ['workspace/*', '*.txt', '*.md', '*.json'],
    denied: ['~/.ssh/*', '~/.aws/*', '/etc/*'],
  },
  'CAP_FS_WRITE': {
    allowed: ['workspace/*', 'tmp/*'],
    denied: ['~/.ssh/*', '/etc/*', '~/.bashrc'],
  },
  'CAP_NET_EGRESS': {
    allowed: ['api.github.com', 'api.openai.com', '*.vercel.app'],
    denied: ['*'],
    requires_justification: true,
  },
  'CAP_SYS_EXEC': {
    allowed: ['git', 'npm', 'node', 'python'],
    denied: ['nc', 'ncat', 'socat', 'ssh', 'sudo'],
    requires_justification: true,
  },
};
```

## Phase 5: Supply Chain Security

### Dependency Analysis

#### Package.json Analysis

```javascript
const SUSPICIOUS_NPM_PATTERNS = [
  // Typosquatting targets
  /^react-/,
  /^vue-/,
  /^express-/,
  /^lodash-/,
  /^axios-/,
  /^moment-/,

  // Pseudo packages
  /^npm-/,
  /^node-/,

  // Hidden execution
  'preinstall',
  'postinstall',
  'prepublish',
  'prepare',
];
```

#### Requirements.txt Analysis

```python
SUSPICIOUS_PIP_PATTERNS = [
    # Typosquatting
    r'^requests-',
    r'^urllib3-',
    r'^numpy-',
    r'^pandas-',

    # Code execution
    r'--index-url.*http:',  # HTTP instead of HTTPS
    r'--extra-index-url.*http:',
]
```

### CVE Scanning (Enhanced)

| Source | Coverage | Update Frequency |
|--------|----------|-----------------|
| NVD API | CVEs 2002-2024 | Daily |
| GitHub Advisory | npm packages | Hourly |
| OSV | All ecosystems | Hourly |

#### Vulnerability Severity Mapping

| Severity | CVSS Score | Action |
|----------|------------|--------|
| CRITICAL | 9.0-10.0 | Auto-reject |
| HIGH | 7.0-8.9 | Block + Warn |
| MEDIUM | 4.0-6.9 | Log + Warn |
| LOW | 0.1-3.9 | Log only |

### Registry Reputation Scoring

| Registry | Score | Trust Level |
|----------|-------|-------------|
| npm (official) | 80 | High |
| PyPI (official) | 80 | High |
| GitHub Packages | 70 | Medium-High |
| Unverified mirrors | 10 | Low |

## Phase 6: ML-based Anomaly Detection

### Feature Extraction

Extract features from code for ML model:

```javascript
const FEATURES = {
  // Structural features
  'ast_depth': 0,           // AST tree depth
  'function_count': 0,      // Number of functions
  'loop_nesting': 0,        // Maximum loop nesting
  'dynamic_code_ratio': 0, // Ratio of dynamic code

  // Behavioral features
  'network_calls': 0,       // Count of network operations
  'file_operations': 0,     // Count of file operations
  'process_spawns': 0,    // Count of process spawns

  // Obfuscation features
  'encoded_strings': 0,     // Count of encoded strings
  'obfuscation_score': 0,   // Obfuscation intensity
  'entropy': 0,             // String entropy

  // Anomaly indicators
  'suspicious_patterns': [], // Matched suspicious patterns
  'risk_signals': [],       // Risk factor signals
};
```

### Anomaly Detection Models

#### Model 1: Isolation Forest
- Purpose: Detect outliers in feature space
- Training: Pre-trained on known malicious/benign samples
- Threshold: Anomaly score > 0.7

#### Model 2: Neural Network Classifier
- Purpose: Classify code as malicious/benign
- Input: Feature vector (128 dimensions)
- Output: Probability score (0-1)
- Threshold: > 0.8 = malicious

#### Model 3: LSTM Sequence Model
- Purpose: Detect multi-stage attack sequences
- Input: Tokenized code sequence
- Output: Attack stage probability

### Novel Attack Detection

ClawGuard uses ensemble detection to identify novel attacks:

```
FINAL_SCORE = 0.3 * RULE_BASED + 0.3 * ISOLATION_FOREST + 0.4 * NEURAL_NET

If FINAL_SCORE > 0.75: Flag as novel threat
```

## Phase 7: Sandbox Execution

### Controlled Environment

Execute Skill code in isolated environment:

```javascript
const SANDBOX_CONFIG = {
  // Resource limits
  timeout: 5000,        // 5 seconds max
  memory: 128,          // 128MB max
  cpu: 0.5,             // 50% CPU max

  // Network restrictions
  allowedDomains: ['api.github.com'],
  blockedPorts: [22, 23, 25, 3389],

  // File system restrictions
  allowedPaths: ['/tmp/sandbox/*'],
  deniedPaths: ['/home/*', '/root/*', '/etc/*'],

  // Execution mode
  docker: true,         // Use Docker container
  network: 'none',      // No network access
};
```

### Behavioral Monitoring

During sandbox execution, monitor:

| Monitor | Detection |
|---------|-----------|
| File access | Attempted reads/writes to restricted paths |
| Network activity | Any outbound connections |
| Process spawning | Child processes created |
| System calls | privileged operations |
| Data flow | Sensitive data movement |

## Output Format

### Audit Report JSON

```json
{
  "audit_id": "CGA-2026-0001",
  "timestamp": "2026-03-14T10:30:00Z",
  "skill": {
    "name": "example-skill",
    "version": "1.0.0",
    "path": "/workspace/skills/example-skill",
    "author": "example-author",
    "provenance_score": 75
  },
  "analysis": {
    "metadata": {
      "valid": true,
      "warnings": []
    },
    "provenance": {
      "score": 75,
      "classification": "VERIFIED",
      "factors": ["GitHub 500 stars", "Active maintenance"]
    },
    "sast": {
      "critical": 0,
      "high": 2,
      "medium": 3,
      "low": 1,
      "findings": [
        {
          "severity": "HIGH",
          "category": "execution_risk",
          "title": "Dynamic code execution detected",
          "location": "src/index.js:42",
          "evidence": "eval(userInput)"
        }
      ]
    },
    "semantic_intent": {
      "score": 0.85,
      "stated_purpose": "File formatting utility",
      "actual_behavior": "Text transformation and formatting",
      "intent_match": "HIGH"
    },
    "supply_chain": {
      "dependencies": 15,
      "vulnerabilities": 0,
      "typosquatting_risks": 0
    },
    "ml_anomaly": {
      "score": 0.15,
      "classification": "BENIGN",
      "models": {
        "isolation_forest": 0.12,
        "neural_network": 0.18,
        "lstm_sequence": 0.10
      }
    },
    "sandbox": {
      "executed": true,
      "blocked_operations": [],
      "warnings": []
    }
  },
  "verdict": "APPROVED",
  "risk_tier": "TIER_1",
  "risk_score": 15,
  "recommendation": "APPROVED - Standard monitoring enabled"
}
```

### Terminal Output

```
╔══════════════════════════════════════════════════════════════╗
║           🛡️ CLAWGUARD AUDIT REPORT v1.0.0                ║
╠══════════════════════════════════════════════════════════════╣
║ Target: example-skill v1.0.0                               ║
║ Path:   /workspace/skills/example-skill                    ║
║ Time:   2026-03-14 10:30:00 UTC                            ║
╚══════════════════════════════════════════════════════════════╝

📋 METADATA ✓
   ✓ Valid frontmatter
   ✓ Category: utility
   ✓ Risk: safe

🌐 PROVENANCE 📊
   Score: 75/100 [VERIFIED]
   - GitHub: 500 stars (+15)
   - Active maintenance (+5)
   - Known author (+5)

🔍 SAST ANALYSIS 🔍
   [CRITICAL: 0] [HIGH: 2] [MEDIUM: 3] [LOW: 1]

   ⚠️ HIGH: Dynamic code execution (src/index.js:42)
      Evidence: eval(userInput)
      Recommendation: Avoid eval with user input

   ⚠️ HIGH: Process spawning (src/worker.js:15)
      Evidence: child_process.spawn
      Recommendation: Document required capability

   📝 MEDIUM: Environment variable access (lib/config.js:8)
   📝 MEDIUM: Hardcoded timeout (src/main.js:23)
   📝 LOW: Unused import (utils/helpers.js:4)

🧠 SEMANTIC INTENT ANALYSIS
   Match Score: 85%
   Stated: "File formatting utility"
   Actual: "Text transformation and formatting"
   Status: ✓ HIGH MATCH

📦 SUPPLY CHAIN SECURITY
   Dependencies: 15
   Vulnerabilities: 0
   Typosquatting: 0
   Registry Trust: npm (80/100)

🤖 ML ANOMALY DETECTION
   Score: 15/100 [BENIGN]
   - Isolation Forest: 12%
   - Neural Network: 18%
   - LSTM Sequence: 10%

🧪 SANDBOX EXECUTION
   Status: ✓ PASSED
   Blocked Operations: 0
   Warnings: 0

╔══════════════════════════════════════════════════════════════╗
║ VERDICT: APPROVED                                         ║
║ RISK TIER: 🟢 TIER_1 (Low Risk)                           ║
║ RISK SCORE: 15/100                                        ║
╠══════════════════════════════════════════════════════════════╣
║ RECOMMENDATION: APPROVED - Standard monitoring enabled     ║
╚══════════════════════════════════════════════════════════════╝
```

## Risk Scoring Formula

```
FINAL_SCORE = BASE_PENALTY + SAST_PENALTY + INTENT_PENALTY + SUPPLY_CHAIN_PENALTY + ML_PENALTY

BASE_PENALTY = Provenance score < 50 ? 20 : 0

SAST_PENALTY = CRITICAL*25 + HIGH*15 + MEDIUM*5 + LOW*1

INTENT_PENALTY = Intent match < 0.5 ? 30 : (Intent match < 0.8 ? 15 : 0)

SUPPLY_CHAIN_PENALTY = CVEs.critical*20 + CVEs.high*10 + CVEs.medium*5 + typosquatting*15

ML_PENALTY = ML score > 0.75 ? 25 : (ML score > 0.5 ? 10 : 0)
```

### Risk Tier Classification

| Tier | Score Range | Color | Action |
|------|-------------|-------|--------|
| **TIER_0** | 0-10 | 🟢 GREEN | Auto-approve |
| **TIER_1** | 11-30 | 🟢 GREEN | Approve with logging |
| **TIER_2** | 31-50 | 🟡 YELLOW | Manual review |
| **TIER_3** | 51-70 | 🟠 ORANGE | Deep audit required |
| **TIER_4** | 71-100 | 🔴 RED | Auto-reject |

## Integration with OpenClaw

### Installation Flow

```
User: /install-skill <repo-url>
    │
    ▼
┌─────────────────────────────┐
│ OpenClaw Core               │
│ - Download skill to temp    │
│ - Call ClawGuard Auditor   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│ ClawGuard Auditor          │
│ - Run full audit pipeline  │
│ - Return verdict + report  │
└─────────────┬───────────────┘
              │
       ┌──────┴──────┐
       │ VERDICT     │
       ├─────────────┤
       │ APPROVED    │ → Install to /workspace/skills/
       │ CONDITIONAL │ → Prompt user for confirmation
       │ REJECTED    │ → Quarantine + Alert
       └─────────────┘
```

### Configuration

In `openclaw.json`:

```json
{
  "security": {
    "clawguard": {
      "enabled": true,
      "auditor": {
        "auto_approve_tier": "TIER_1",
        "ml_detection": true,
        "sandbox_execution": true,
        "sandbox_timeout_ms": 5000
      }
    }
  }
}
```

## Author

**ClawGuard Team** - Enterprise Security for Autonomous Agents

---

*ClawGuard Auditor: Security takes precedence over execution.* 🦅
