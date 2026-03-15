# Prompt-based Security Auditor

This directory contains a professional security audit prompt designed to enforce rigorous safety checks before OpenClaw installs or configures any third-party Skills.

## Files Included
- `prompt_template.md`: The main prompt template to instruct OpenClaw to perform a security audit.

## How to Use

1. Open the `prompt_template.md` file.
2. Copy the entire content of the prompt.
3. Replace the placeholder `[Skill_Name]` with the actual name or identifier of the Skill you want OpenClaw to install (e.g., `github-repo-downloader` or `auto-ssh-manager`).
4. Send the customized prompt to OpenClaw.

By doing this, you force OpenClaw to act as a security gateway, conducting a thorough "health check" on the Skill's provenance, permissions, network behavior, and code dependencies *before* executing any potentially dangerous `install` commands. Only after it outputs a "🟢 Safe" assessment should the actual installation proceed.
