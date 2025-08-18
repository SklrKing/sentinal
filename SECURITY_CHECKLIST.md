# SECURITY_CHECKLIST.md

This file tracks recurring cybersecurity tasks for Jess Ford's IT
environment.

------------------------------------------------------------------------

## 🔒 Daily

-   [ ] Review Microsoft Defender portal for new alerts (endpoint,
    email, identity).\
-   [ ] Check Entra (Azure AD) risky sign-ins report.\
-   [ ] Spot-check Acronis backup dashboard for failed jobs.

## 📅 Weekly

-   [ ] Verify all devices are reporting into Defender EDR.\
-   [ ] Review Conditional Access sign-in logs for anomalies.\
-   [ ] Run phishing awareness reminder in staff chat (tip of the
    week).\
-   [ ] Update documentation (if new policy/script rolled out).

## 📆 Monthly

-   [ ] Test **Acronis restore** (mailbox item, SharePoint file,
    OneDrive folder). Document time-to-recover.\
-   [ ] Verify OneDrive/SharePoint versioning settings (500 versions,
    93-day recycle bin).\
-   [ ] Patch audit: confirm all endpoints and the on-prem server are up
    to date.\
-   [ ] Review Secure Score and implement 1--2 recommended
    improvements.\
-   [ ] Review external guest accounts in SharePoint/Teams --- remove
    unused.

## 📆 Quarterly

-   [ ] Simulate **incident response drill**:
    -   Ransomware (restore test + isolate endpoint).\
    -   Credential compromise (lock account, force password reset,
        revoke sessions).\
-   [ ] Update **Incident Response Plan** with lessons learned.\
-   [ ] Review DLP (Purview) policy audit logs. Adjust if too noisy or
    missing coverage.\
-   [ ] Confirm DealerTrack/CDK data exports are archived securely.\
-   [ ] Rotate any API/service account keys.

## 🗓️ Annual

-   [ ] Full restore test of Acronis for a critical user + SharePoint
    site.\
-   [ ] Tabletop exercise with leadership (walk through breach
    scenario).\
-   [ ] Review/renew IT policies with staff (MFA, phishing, acceptable
    use).\
-   [ ] Hardware/software lifecycle review (phase out unsupported
    OS/apps).

------------------------------------------------------------------------

✅ **Rule of Thumb:** Each task should be logged (GitHub Issue, Notion,
or checklist tick) when done. If something fails (e.g., backup job,
restore test), open a ticket immediately and resolve before closing the
cycle.
