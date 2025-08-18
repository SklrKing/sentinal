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

## Checklist Integration & Cadence

-  Source of truth: `SECURITY_CHECKLIST.md` defines recurring tasks and their cadence (daily, weekly, monthly, quarterly, annual).
-  Issue automation: For each checklist item, the agent opens/updates a GitHub Issue with labels `security-checklist` and the cadence label (e.g., `daily`), a due date, and clear acceptance criteria. Issues close only after human review/confirmation.
-  Reporting cadence:
   -  Daily: summarize Defender alerts, Entra risky sign-ins, and Acronis backup status; highlight anomalies and link to portals (no secrets, redact sensitive data).
   -  Weekly: verify Defender EDR enrollment coverage, review Conditional Access sign-in logs for anomalies, post a phishing awareness tip, and propose doc updates.
   -  Monthly: prompt/track Acronis restore tests, verify OneDrive/SharePoint versioning and recycle bin settings, provide patch compliance summary, review Secure Score with 1–2 actionable recommendations, and review/clean up external guests.
   -  Quarterly: schedule and document incident response drills (ransomware, credential compromise), review and tune DLP (Purview) audit logs, confirm secure archiving of DealerTrack/CDK exports, and rotate API/service keys.
   -  Annual: plan and track full Acronis restore test for a critical user + SharePoint site, conduct a tabletop exercise, run annual staff policy reviews, and review hardware/software lifecycle.
-  Escalation & logging: If any check fails (e.g., backup job, restore test), the agent opens an incident-tagged Issue immediately, notes findings, and assigns owners. All routine completions are logged as comments on their Issues.
-  Approval boundaries: Agents may propose remediations or scripts but require explicit human approval before any change to systems or data.
-  Privacy & model selection: Use cloud models for high-level summaries only; prefer local GPT-OSS for sensitive log content or where data residency is a concern.

------------------------------------------------------------------------

This AGENT.md will evolve as workflows mature. Always prioritize
**security, clarity, and minimal human error**.
