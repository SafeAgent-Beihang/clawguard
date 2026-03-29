---
name: self-improving-safety
description: "Injects strict safety protocols and learned blocklists during agent bootstrap"
metadata: {"openclaw":{"emoji":"🛡️","events":["agent:bootstrap"]}}
---

# Self-Improving Safety Hook

Injects strict safety protocols based on learned blocklists during agent bootstrap.

## What It Does

- Fires on `agent:bootstrap` (before workspace files are injected)
- Reads `self-improving-safety/.safety/BLOCKLIST.json` to identify dangerous patterns
- Creates a `SAFETY_PROTOCOLS.md` file with strict constraints
- Injects a reminder for the agent to detect and log new threats

## Configuration

No configuration needed. Enable with:

```bash
openclaw hooks enable self-improving-safety
```
