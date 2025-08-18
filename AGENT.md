# AGENT.md

This document describes how AI agents (Claude, ChatGPT, or local GPT-OSS
models) will be used in Jess Ford's IT & cybersecurity operations.

## Purpose

To provide a clear framework for delegating documentation, automation,
and monitoring tasks to AI agents while keeping human-in-the-loop for
all critical decisions.

## Usage Guidelines

1.  **Documentation Support**
    -   Agents assist in drafting, editing, and maintaining Markdown
        documentation in the GitHub repo.
    -   All outputs must be reviewed before merging to `main`.
2.  **Automation & Scripting**
    -   Agents can generate PowerShell, Python, or Bash scripts for IT
        automation (e.g., Intune policies, Defender reports).
    -   Scripts must run first in a test environment before production
        deployment.
3.  **Security Monitoring**
    -   Agents summarize Microsoft Defender, Entra, and Intune logs into
        daily/weekly reports.
    -   Agents may propose automated remediations, but execution
        requires manual approval.
4.  **AI Model Boundaries**
    -   **Claude Code**: best for PowerShell/365 scripting and workflow
        agents.
    -   **ChatGPT**: best for documentation, strategy, and broad
        technical Q&A.
    -   **GPT-OSS (DGX Spark)**: reserved for local log analysis,
        chatbot, and sensitive workflows where cloud AI is not
        acceptable.

## Human-in-the-Loop

-   No automation runs unattended without explicit human approval.
-   Security changes (MFA, CA policies, backups) must be logged and
    reviewed.

## Workflow

1.  User drafts or requests automation via GitHub Issues.
2.  AI agent proposes implementation (script, config, doc).
3.  User tests in sandbox → Approves → Deploys.
4.  Documentation updated automatically by agent.

------------------------------------------------------------------------

This AGENT.md will evolve as workflows mature. Always prioritize
**security, clarity, and minimal human error**.
