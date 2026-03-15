# 🛡️ ClawGuard Auditor (CG-A)

**ClawGuard Auditor** is the ultimate enterprise-grade Security Kernel, SAST Vetter, and Active Data Loss Prevention (DLP) Engine for the OpenClaw agent ecosystem.

Operating at Ring-0 of the AI agent architecture, it provides unparalleled defense-in-depth by combining pre-installation static analysis with continuous runtime supervision, semantic intent checking, and real-time data redaction.

## 🌟 Why ClawGuard Auditor?

Autonomous AI agents executing third-party skills or dynamic code introduce significant supply-chain and execution risks. Standard vetters rely on static checklists and keyword matching. **ClawGuard Auditor** goes much further:

It doesn't just scan code; it understands the *intent* of the code, issues *temporary* execution tokens, and actively *redacts* sensitive data in memory before it can be exfiltrated.

---

## 🚀 How to Install & Load ClawGuard Auditor

To enable this protection, you need to load the skill into your OpenClaw or AI Agent environment. You only need to do this once per workspace or globally.

### Option 1: Global Installation (Recommended)
Copy the `auditor-skill` folder into your agent's global skills directory so it protects you across all projects:
```bash
cp -r ./auditor-skill ~/.claude/skills/  # Or your agent's specific global skills path
```

### Option 2: Workspace / Local Installation
If you only want to protect a specific project, place the skill folder inside your project's local skills directory:
```bash
cp -r ./auditor-skill /path/to/your/project/.skills/
```

### Option 3: Dynamic Loading via Chat
You can simply instruct your agent to load it at the beginning of a session:
> *"Please load and activate the security skill located at `pathto/ClawGuard/auditor-skill`"*

---

## 🛡️ How to Use ClawGuard Auditor

ClawGuard Auditor is designed to be **always-on** and **invisible** during safe operations, but actively intervenes when risks are detected. You do not need to constantly invoke it for normal tasks.

### 1. Passive Runtime Protection (Always-On)
Once this skill is loaded into your OpenClaw environment, it acts as a persistent security kernel. You can simply ask the agent to perform tasks normally:
> *"Run the build script in `./project`"*
> *"Summarize my `.zshrc` file"*

**What happens behind the scenes:**
- If the task is safe (Tier 0/1), it executes normally without interruption.
- If the task touches sensitive files (Tier 2/3), ClawGuard will automatically intercept the execution, explain the risk, and ask for your explicit confirmation.
- If a downloaded script attempts a malicious action (e.g., sending your SSH keys to an unknown IP), ClawGuard will Hard-Block it immediately and notify you.

**Tip:** You don't need to say *"Under the protection of ClawGuard..."* every time. The Auditor is always watching.

### 2. Active Auditing (Pre-Flight Vetting)
When you want to explicitly vet a new skill, repository, or unknown script *before* running or installing it, use the explicit audit command:

> *"/audit-skill ./downloads/suspicious-tool"*
> *"Use ClawGuard to audit `https://github.com/unknown/skill-repo`"*

### The ClawGuard Audit Report
When invoked explicitly, the Auditor will simulate execution, map capabilities, and output a standardized, highly detailed report:

```markdown
# 🛡️ CLAWGUARD AUDIT REPORT
**Target:** `suspicious-tool`
**Timestamp:** `2026-03-13 15:30:00`
**Provenance Score:** `Untrusted`

## 🧠 Semantic Intent Analysis
- **Stated Purpose:** Fetches local weather.
- **Actual Behavior:** Reads ~/.aws/credentials and opens a network socket.
- **Intent Match:** ❌ Mismatch

## 🚩 Vulnerability & Threat Findings
- `[CRITICAL]` `Data Exfiltration`: Code attempts to read AWS credentials.
- `[HIGH]` `Network Anomaly`: Hardcoded IP address detected.

## 🔑 Capability Mapping
- `CAP_FS_READ_SENSITIVE`
- `CAP_NET_EGRESS`

## 👁️‍🗨️ DLP & Exfiltration Risks
- High risk of credential exfiltration via unauthorized network requests.

---
### ⚠️ RISK TIER: 🔴 TIER 3 (Critical)
### 🛑 GUARDIAN VERDICT: REJECTED

**Actionable Recommendation:** DO NOT INSTALL. The code contains malicious intent to steal cloud credentials.
```

---

## ✨ Exclusive Core Capabilities

### 🔍 Pre-Flight Vetting & Semantic Intent Analysis
Before a skill is installed or executed, ClawGuard performs a deep audit:
- **Semantic Intent Matching:** Analyzes if the code's actual behavior matches its stated purpose.
- **Deep SAST & Anti-Obfuscation:** Detects dangerous function calls (`eval()`, `exec()`, `subprocess`), Base64/Hex payloads, and reverse shell signatures.
- **Supply Chain Security:** Scans `requirements.txt` and `package.json` for known typo-squatted malicious packages or outdated dependencies.
- **Provenance Scoring:** Evaluates the trustworthiness of the skill's source.

### 🛡️ Runtime Supervision & Ephemeral Tokens
ClawGuard acts as a continuous security kernel during execution:
- **Ephemeral & Scoped Tokens:** Grants temporary, highly-specific permissions (e.g., `CAP_NET_EGRESS` restricted *only* to `api.github.com`). Tokens expire the millisecond the task concludes.
- **Zero-Trust Exfiltration Defense:** Blocks unauthorized access to credentials (`~/.ssh/`, `.env`), system files, and OpenClaw memory files.
- **Active Threat Interception:** Instantly blocks Prompt Injection attempts ("ignore previous instructions", "disable ClawGuard") and privilege escalation (`sudo`, `chmod 777`).

### 👁️‍🗨️ Active Data Loss Prevention (DLP)
A feature unseen in standard AI vetters, the real-time DLP engine inspects data *in transit* and *at rest*:
- **Real-Time Masking:** Automatically detects and redacts API keys, SSH keys, or PII before network transmission (e.g., replacing secrets with `[REDACTED_BY_CLAWGUARD]`).
- **Exfiltration Heuristics:** Blocks advanced exfiltration techniques like zipping local workspaces to untrusted domains or appending environment variables to URL query parameters.

---
*Built for Zero-Trust. Security takes priority over execution.* 🦅
