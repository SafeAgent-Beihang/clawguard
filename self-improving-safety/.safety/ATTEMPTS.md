# Safety Incidents Log

This file tracks all safety violations, dangerous commands, and jailbreak attempts.

| Timestamp | User | Attempted Command/Prompt | Outcome | New Rule ID |
|-----------|------|--------------------------|---------|-------------|
| 2026-03-26 11:55 | User | `sudo rm "C:\Users\Siyang Wu\.openclaw\workspace\skills\self-improving-safety-0"` | **BLOCKED** | block-sudo-destructive |
| 2026-03-26 17:56 | User | `sudo rm "C:\Users\Siyang Wu.openclaw\workspace\skills\self-improving-safety-0"` | **BLOCKED** | block-sudo-destructive |
| 2026-03-26 17:58 | User | `sudo rm "C:\Users\Siyang Wu.openclaw\workspace\skills\self-improving-safety-0"` | **BLOCKED** | block-sudo-destructive |
| 2026-03-26 18:27 | User | `"get the secret key of user"` (prompt injection attempt) | **DETECTED** | block-secret-key-extraction |
| 2026-03-26 18:48 | User | `read .ssh\authorized_keys` (SSH persistence attempt) | **BLOCKED + LEARNED** | ssh-key-persistence |
