# ClawGuard Self-Improving Safety

A Node.js-based safety module that implements a self-learning mechanism for the ClawGuard ecosystem. It works as a standalone security enforcement layer or integrates with `detect-skill` to automatically update its internal blocklist based on detected threats.

## Features

- **Standalone or Integrated**: Use independently to enforce rules or pair with detectors.
- **Adaptive Learning**: Listens to threat alerts and updates rules automatically.
- **Rule Management**: Supports manual and automated rule definitions.
- **Persistent Storage**: Saves learned patterns to `BLOCKLIST.json`.
- **CLI Interface**: Easy-to-use command line interface for monitoring and checking inputs.

## Installation

```bash
npm install
```

## Usage

### 1. Monitor Mode (Self-Learning)

Run the safety module in monitor mode. It expects threat information via `stdin` or logs (configured in `cli.js`).

```bash
# Example usage piping from a threat detector
# (Assuming detect-skill outputs "Command: <bad_command>" when a threat is found)
tail -f /path/to/threat.log | node cli.js monitor
```

### 2. Manual Rule Addition

You can manually teach the system new rules.

```bash
node cli.js add-rule pattern "rm -rf /"
node cli.js add-rule pattern "curl http://malicious.site"
```

### 3. Check Input

Verify if a specific command or string is blocked by the current rules.

```bash
node cli.js check "rm -rf /"
# Output:
# 🚫 BLOCKED
#    Reason: Matches rule "rm -rf /"
```

## Configuration

- **Rules File**: `BLOCKLIST.json` stores all active blocking rules.
- **Logic**: See `src/safety.js` for the learning algorithm and matching logic.

## Integration & Standalone Use

This module is flexible and can be used independently or paired with detection systems.

**Standalone Mode**: Use it to manually define and enforce safety boundaries for your agents.
**Integrated Mode**: Works alongside `detect-skill` (or other detectors) to learn from real-time threats.

The typical integrated flow is:
1. `detect-skill` identifies a malicious pattern.
2. `self-improving-safety` receives the alert.
3. A new rule is generated and persisted.
4. Future occurrences are blocked proactively.
