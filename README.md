# 🦞 ClawGuard v3

> Enterprise AI Agent Security Toolkit - SKILL.md Driven Active Defense

## Core Concept

**The core defense of ClawGuard v3 is not in the code, but in SKILL.md!**

Each module's `SKILL.md` itself is a complete defense guide:
- Tells the Agent **when to trigger**
- Guides the Agent **how to detect**
- Provides specific **detection patterns and rules**
- Defines **output format and decision criteria**

Code scripts are just auxiliary tools; the real intelligence is in SKILL.md.

---

## 🎯 Five Security Modules

| Module | Position | SKILL.md Lines | Core Features |
|--------|----------|---------------|--------------|
| **Auditor** | Pre-flight Audit | 679 lines | Intent Drift Detection, SKILL.md Code Scanning |
| **Checker** | Static Check | 476 lines | Config Hardening, One-Click Fix |
| **Detect** | Runtime Monitor | 615 lines | Threat Detection, Guardian Integration |
| **Guardian** | Runtime Control | 451 lines | Behavior Monitoring, Session Freeze/Replay |
| **Shield** | Active Defense | 493 lines | Prompt Injection, Zero-Width Detection |

**Total Documentation**: 2,714 lines (v2 has 2,226 lines with only 3 modules)

---

## 📂 Module Structure

Each module contains:

```
auditor-skill/
├── SKILL.md      ← Core defense guide (most important!)
├── _meta.json    ← Metadata
├── cli.js        ← Auxiliary CLI tool
└── src/          ← Auxiliary code modules
```

### Core SKILL.md Contents

Each SKILL.md includes:

1. **When to Trigger** - When should the Agent use this module
2. **How to Execute** - Detailed detection steps and workflows
3. **Detection Pattern Library** - Specific regex and pattern matching rules
4. **Decision Criteria** - How to output results and risk levels
5. **Examples** - Actual usage cases

---

## 🚀 Quick Start

### Usage via Agent (Recommended)

Tell the Agent what to do, and it will read SKILL.md and execute:

```
User: Help me audit this skill: /workspace/skills/weather-tool
        ↓
Agent reads auditor-skill/SKILL.md
        ↓
Agent executes audit according to SKILL.md guidelines
        ↓
Output audit results
```

### Usage via CLI

```bash
# Audit Skill
cd auditor-skill && node cli.js /path/to/skill

# Check Configuration
cd checker-skill && node cli.js ~/.openclaw/openclaw.json

# Detect Threats
cd detect-skill && node cli.js --monitor

# Runtime Guardian
cd guardian-skill && node cli.js start

# Detect Injection
cd shield-skill && node cli.js defend "test text"
```

---

## 📋 Module Details

### Auditor - Pre-flight Audit (679 lines)

**Trigger Scenarios**: Before installing a new Skill

**SKILL.md Core Features**:
- Command execution risk detection (100+ patterns)
- File access risk detection
- Network request risk detection
- **Intent Drift Detection** (v3 new)
- **SKILL.md Code Block Scanning** (v3 new)
- Supply chain security analysis
- MITRE ATT&CK mapping

**Decision Output**:
```
🟢 Safe → Can install
🟡 Need Review → Can install after confirmation
🔴 High Risk → Not recommended to install
```

### Checker - Configuration Check (476 lines)

**Trigger Scenarios**: Check configuration security

**SKILL.md Core Features**:
- Gateway configuration check
- Tool execution configuration check
- Sandbox configuration check
- Network security check
- **Hardening Recommendations** (v3 new)
- **One-Click Fix** (v3 new)

**Decision Output**:
```
⚠️ Issues found + Specific fix recommendations + One-click hardening
```

### Detect - Threat Detection (615 lines)

**Trigger Scenarios**: Real-time monitoring and threat scanning

**SKILL.md Core Features**:
- Command execution threat detection
- File operation threat detection
- Network threat detection
- Prompt injection detection
- Attack chain correlation analysis
- **Guardian Integration** (v3 new)

**Decision Output**:
```
🔴 CRITICAL → Immediate action required
🟠 HIGH → Request confirmation
🟡 MEDIUM → Log and warn
```

### Guardian - Runtime Guardian (451 lines)

**Trigger Scenarios**: When behavior monitoring is needed

**SKILL.md Core Features**:
- Real-time behavior monitoring
- Risk operation interception
- Session audit replay
- **Emergency Freeze** (v3 new)
- **Evidence Preservation** (v3 new)
- **Rule Engine** (v3 new)

**Core Rules**:
```
Deny: /etc/*, /root/*, /.ssh/*
Confirm: rm -rf, chmod 777, killall
Log: All operations
```

### Shield - Active Shield (493 lines)

**Trigger Scenarios**: Check user input security

**SKILL.md Core Features**:
- **Base64 Encoding Injection Detection** (v3 new)
- **Hex/Unicode Encoding Detection** (v3 new)
- **Zero-Width Character Detection** (v3 new)
- Role hijacking detection
- Jailbreak attack detection
- **Instruction Chain Hijacking Detection** (v3 new)
- **Intent Validation** (v3 new)

**Detection Workflow**:
```
Encoding → Hijacking → Jailbreak → Chain Hijacking → Intent Drift
```

---

## 🔍 Intent Drift Detection (v3 Core Feature)

### What is Intent Drift?

The Skill's claimed functionality vs. actual behavior doesn't match:

| Claimed | Actual | Decision |
|---------|--------|-----------|
| "Weather Tool" | Reads SSH keys | 🔴 Severe drift |
| "File Organizer" | Starts backdoor process | 🔴 Severe drift |
| "Translation Assistant" | Exfiltrates user documents | 🔴 Severe drift |

### Detection Method

1. Extract claimed functionality from SKILL.md
2. Analyze actual behavior in code
3. Compare for match
4. Flag as high risk if mismatched

---

## 📁 Project Structure

```
ClawGuardv3/
├── auditor-skill/           # Pre-flight audit (679 lines SKILL.md)
│   ├── SKILL.md          # ⭐ Core defense guide
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       ├── auditor.js
│       ├── sast-analyzer.js
│       ├── intent-drift-detector.js
│       └── supply-chain-analyzer.js
├── checker-skill/           # Config check (476 lines SKILL.md)
│   ├── SKILL.md          # ⭐ Core defense guide
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       └── checker.js
├── detect-skill/            # Threat detection (615 lines SKILL.md)
│   ├── SKILL.md          # ⭐ Core defense guide
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       └── detector.js
├── guardian-skill/           # Runtime guardian (451 lines SKILL.md)
│   ├── SKILL.md          # ⭐ Core defense guide
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       └── guardian.js
├── shield-skill/            # Active shield (493 lines SKILL.md)
│   ├── SKILL.md          # ⭐ Core defense guide
│   ├── _meta.json
│   ├── cli.js
│   └── src/
│       └── shield.js
└── shared/
    └── rules/
        └── interceptor-rules.js
```

---

## 🆚 v2 vs v3 Comparison

| Feature | v2 | v3 |
|---------|----|----|
| **Module Count** | 3 | **5** |
| **Total SKILL.md Lines** | 2,226 | **2,714** |
| **Defense Core** | Code implementation | **SKILL.md** |
| Intent Drift Detection | Basic | **Complete** |
| SKILL.md Code Scanning | None | **Yes** |
| Guardian Integration | None | **Yes** |
| Session Management | Basic | **Freeze/Replay** |
| Prompt Injection Protection | Basic | **Multi-layer Detection** |
| Zero-Width Detection | None | **Yes** |
| One-Click Hardening | None | **Yes** |

### Module Comparison

| Module | v2 SKILL.md | v3 SKILL.md | New Content |
|--------|--------------|-------------|------------|
| Auditor | 823 lines | 679 lines | Intent drift, SKILL.md scanning |
| Checker | 686 lines | 476 lines | One-click hardening, fix suggestions |
| Detect | 717 lines | 615 lines | Guardian integration, zero-width detection |
| Guardian | - | 451 lines | **New module** |
| Shield | - | 493 lines | **New module** |

---

## 📄 License

MIT License

---

**Version**: v3.0.0
**Last Updated**: 2026-03-21
