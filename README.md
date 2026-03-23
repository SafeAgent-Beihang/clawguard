# ClawGuard 🛡️

[中文版](./README.zh-CN.md)

**ClawGuard** is a security toolkit designed to mitigate risks associated with autonomous agents, such as **OpenClaw** and other LLM-driven entities. As agents gain more autonomy to execute code, access APIs, and manage files, ClawGuard provides necessary guardrails to help reduce security risks.

## 📖 Why ClawGuard?

Autonomous agents are versatile but introduce unique security attack vectors:

- **Prompt Injection:** Malicious inputs that hijack the agent's logic.
- **Privilege Escalation:** Agents performing unauthorized system-level operations.
- **Data Exfiltration:** Accidental leaking of PII (Personally Identifiable Information) or API keys to LLM providers.
- **Resource Exhaustion:** Infinite loops or recursive tasks leading to massive token costs.

ClawGuard is a **comprehensive security solution** that uses multiple security modules working together to help reduce security risks faced by agents. Each module has its specific responsibilities and can be used independently or deployed together.

**Currently released three security modules:**
1. **Auditor**: Pre-installation audit
2. **Checker**: Configuration check
3. **Detect**: Runtime monitoring

**More security modules will be released in the future** to expand the protection capabilities.

🤝 **Future Collaboration**: We will collaborate with open-source projects like **[AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard)** to co-build security capabilities.

ClawGuard is particularly suitable for scenarios where agents need to execute code, access files, or call external APIs.

## 🧩 Modules

ClawGuard is a modular security solution, with each module responsible for specific security functions. Currently released modules:

- **[ClawGuard Auditor](./auditor-skill/)**: Provides pre-installation static analysis, runtime capability enforcement, zero-trust execution, and real-time data redaction for OpenClaw Skills. Includes:
  - Advanced SAST (Static Application Security Testing)
  - Semantic Intent Analysis
  - Supply Chain Security (dependency verification, CVE scanning)
  - ML-based Anomaly Detection
  - Sandbox Execution

- **[ClawGuard Checker](./checker-skill/)**: Security configuration analyzer and runtime integrity verifier. Includes:
  - Configuration Security Analysis
  - Credential Exposure Detection (multi-pattern scanning)
  - Permission Modeling
  - Runtime Integrity Verification (SHA-256)
  - Network Security Analysis
  - Log Forensics
  - Compliance Checking (CIS, NSA, CISA benchmarks)

- **[ClawGuard Detect](./detect-skill/)**: Real-time behavioral monitoring and threat detection system. Includes:
  - Real-time Command Monitoring
  - File Access Monitoring
  - Network Traffic Analysis
  - Prompt Injection Detection
  - Multi-stage Attack Chain Detection
  - MITRE ATT&CK Coverage
  - ML-based Anomaly Detection

## Architecture

ClawGuard's modules can be used independently or deployed together to form a complete protection system:

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLAWGUARD SECURITY FLOW                      │
└─────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────┐
    │       Scenario 1: Install New Skill     │
    └─────────────────────────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Auditor (Audit)    │  ← Check if Skill is safe
              │  Pre-installation   │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Pass → Install    │
              │  Reject → Abort   │
              └─────────────────────┘

    ┌─────────────────────────────────────────┐
    │       Scenario 2: Check Security Status │
    └─────────────────────────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Checker (Check)   │  ← Verify configuration
              │  Manual/Periodic   │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Security Score    │
              │  + Recommendations │
              └─────────────────────┘

    ┌─────────────────────────────────────────┐
    │      Scenario 3: Agent Running Tasks    │
    └─────────────────────────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Detect (Monitor) │  ← Real-time threat detection
              │  Continuous        │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Block / Warn     │
              │  / Allow          │
              └─────────────────────┘
```

**Three scenarios are independent** and can be selected based on actual needs:

| Module | Auditor | Checker | Detect |
|--------|---------|---------|--------|
| **Role** | Security gate | Regular inspection | Security camera |
| **When** | Before skill installation | Manual/periodic | During runtime |
| **Target** | Third-party Skill source | OpenClaw config/system | Agent commands/operations |
| **Focus** | Malicious code in Skill | System configuration security | Active attacks |
| **Use Case** | Installing new Skill | Check system security status | Monitor for threats |

### Auditor - Pre-installation Audit

**When to use**: When someone wants to install a new third-party Skill for the Agent

**Main checks**:
- Does the Skill contain malicious code (reverse shell, data exfiltration)
- Does the Skill's claimed functionality match its actual behavior (intent analysis)
- Are dependencies safe, any potential supply chain poisoning

### Checker - Configuration Check

**When to use**: When checking if the OpenClaw system itself is securely configured

**Main checks**:
- Are API keys exposed in configuration files
- Are file permissions correct (config files shouldn't be readable by others)
- Is network properly isolated
- Is running as root user (dangerous)

### Detect - Runtime Monitoring

**When to use**: While the Agent is executing tasks, monitoring for dangerous behavior in real-time

**Main checks**:
- Is the current command dangerous (e.g., curl with credentials)
- Is there a Prompt injection attempt
- Are there abnormal file access or network requests

## 🤝 Contributing

We welcome contributions to make autonomous agents safer!

1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the Branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## ⚠️ Disclaimer

ClawGuard is a security tool designed to reduce risk, but cannot guarantee 100% protection against all possible LLM vulnerabilities. Always follow the principle of least privilege (PoLP) when deploying autonomous agents.

---

**Secure your agents. Protect your systems. Use ClawGuard.**

[Documentation](docs/) | [Report Bug](issues/) | [Contact Team](mailto:nyale1024@gmail.com)
