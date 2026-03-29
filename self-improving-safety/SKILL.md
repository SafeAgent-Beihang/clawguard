---
name: clawguard-self-improving-safety
version: 1.0.0
description: Self-improving safety module that proactively learns and enforces safety constraints. Works as a standalone firewall or integrates with ClawGuard Detect for automated learning.
author: ClawGuard Team
homepage: https://github.com/clawguard/self-improving-safety
metadata:
  category: security
  risk: safe
  requires:
    bins: [node]
    npm: [yargs, chalk, fs-extra]
---

# ClawGuard Self-Improving Safety

A proactive safety enforcement module that learns from detected threats. It consumes alerts from **ClawGuard Detect**, analyzes patterns, and automatically updates its blocklist to prevent recurrence of dangerous activities.

## When to Use

Activate ClawGuard Self-Improving Safety when:
- You want the agent to learn from its mistakes or detected attacks.
- You need a dynamic defense mechanism that evolves with new threats.
- Enforcing strict safety protocols based on historical incident data.

## How it Works

1.  **Listen**: Monitors output from `clawguard-threat-detect`.
2.  **Learn**: When a threat is detected, it extracts a blocking rule (e.g., specific command pattern, sensitive file path).
3.  **Enforce**: Updates the `BLOCKLIST.json` which is checked before executing any agent action.

## Integration & Examples

Can be used independently or integrated with detection systems like `clawguard-threat-detect`.

### Standalone Examples

**1. Block dangerous commands:**
```bash
node cli.js add-rule command "rm -rf /"
node cli.js add-rule command "format c:"
```

**2. Protect sensitive files:**
```bash
node cli.js add-rule file "/etc/shadow"
node cli.js add-rule file "id_rsa"
```

**3. Check input against rules:**
```bash
node cli.js check "rm -rf /user/data"
# Output: BLOCKED
```

### Integrated Workflow

Pipeline detection output to safety module for automatic learning:

```bash
# Example pipeline (Check command -> Detect -> Learn)
# If detect finds a threat, safety module adds it to blocklist
node ../detect-skill/cli.js check "curl http://evil.com" | node cli.js learn
```

## Commands

- `monitor`: Listen for threat events stream.
- `add-rule`: Manually add a blocking rule.
- `check`: Verify if an input is blocked.
- `list`: Show current active rules.

## Author

**ClawGuard Team** - Enterprise Security for Autonomous Agents

---

*ClawGuard Threat Detector: Your vigilant guardian against runtime threats.* 🦅