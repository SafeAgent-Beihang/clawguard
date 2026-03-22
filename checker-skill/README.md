# 🛡️ ClawGuard Checker (CG-SC)

**ClawGuard Checker** is a comprehensive security configuration analyzer and runtime integrity verifier for OpenClaw environments. It provides continuous security posture monitoring to ensure your agent deployment is properly configured and secure.

## 🌟 Why ClawGuard Checker?

Even with a secure agent, misconfiguration can lead to vulnerabilities. ClawGuard Checker verifies:

- **Configuration Security**: Are your config files properly set up?
- **Credential Exposure**: Are API keys and secrets protected?
- **Permission Modeling**: Are file permissions correctly configured?
- **Runtime Integrity**: Have system files been tampered with?
- **Network Security**: Is your deployment properly isolated?
- **Compliance**: Do you meet security benchmarks?

## 🚀 How to Install & Load ClawGuard Checker

Place the `checker-skill` folder in your OpenClaw skills directory:

```
/workspace/skills/clawguard-checker/
```

Then load it:

> *"Please load and activate the security checker at `path/to/ClawGuard/checker-skill`"*

## 🛡️ How to Use ClawGuard Checker

### Manual Security Check

Run a full security check:

> *"Run a security check on this OpenClaw instance"*

### Automated Scheduling

Configure automatic checks in your OpenClaw configuration:

```json
{
  "security": {
    "clawguard": {
      "checker": {
        "enabled": true,
        "schedule": "0 2 * * *"
      }
    }
  }
}
```

## 🔍 What Does ClawGuard Checker Analyze?

### 1. Configuration Security

Checks your `openclaw.json` for:
- Gateway binding (should be localhost, not 0.0.0.0)
- TLS encryption enabled
- Device authentication enabled
- Proper CORS configuration
- Tools profile (should be restricted, not full)

### 2. Credential Exposure Detection

Multi-layer scanning for exposed secrets:
- API keys (OpenAI, Anthropic, AWS, GitHub, etc.)
- Private keys and certificates
- Database credentials
- Environment variables with secrets

### 3. Permission Modeling

Verifies correct file permissions:
- Config files should be 600 (owner only)
- Directories should be 700
- No world-readable sensitive files
- Not running as root

### 4. Runtime Integrity

Uses cryptographic verification:
- SHA-256 baseline hashes
- Merkle tree verification
- Signature validation

### 5. Network Security

Analyzes network configuration:
- Port binding
- Trusted proxies
- Egress restrictions
- Rate limiting

### 6. Log Forensics

Analyzes audit logs for:
- Authentication failures
- Privilege escalation attempts
- Data exfiltration patterns
- Red line triggers

## 📊 Security Grades

| Grade | Score | Color | Action |
|-------|-------|-------|--------|
| A+ | 95-100 | 🟢 | Excellent |
| A | 90-94 | 🟢 | Good |
| B | 80-89 | 🟢 | Satisfactory |
| C | 70-79 | 🟡 | Fair - Fix within 1 week |
| D | 60-69 | 🟠 | Poor - Fix within 24 hours |
| F | 0-59 | 🔴 | Critical - Fix immediately |

## 📁 Project Structure

```
checker-skill/
├── SKILL.md              # Skill definition and documentation
├── README.md             # This file
├── cli.js                # Command-line interface
└── src/
    └── checker.js        # Core security checking engine
```

## ⚠️ Disclaimer

ClawGuard Checker is a security tool designed to reduce risk, but cannot guarantee 100% protection. Always follow the principle of least privilege when deploying autonomous agents.

---

**ClawGuard Checker: Vigilant protection for your AI agents.** 🦅
