import pypandoc

# Original full plan in Markdown (from previous detailed output)
full_plan_text = """# Scoping Automation and Security Goals for a Cloud-Centric Environment

## Environment Overview and Challenges
You’ve described a **cloud-first IT environment** using Microsoft 365 Business Premium (with Defender for Endpoint EDR), OneDrive/SharePoint for file storage, and a dealership management system (DMS) currently on CDK Drive and soon moving to DealerTrack. Aside from an experimental on-prem server, all core systems are cloud-based. This setup offers flexibility and easy access, but it also introduces critical **security challenges** – notably the threats of **ransomware** and **stolen credentials**. You’ve already experienced a scare with a compromised login token, underscoring the need for robust security measures. The user base has generally low technical skill, meaning any solutions should be **highly automated and user-friendly**.

**Available Tools:** Fortunately, your Microsoft 365 Business Premium subscription provides a strong security foundation – including **Microsoft Defender for Business** (endpoint protection/EDR), **Microsoft Entra ID (Azure AD) Plan 1** for identity and access management, **advanced multifactor authentication** (MFA), and **data protection tools like Purview DLP**. These can help secure identities, devices, and data if configured properly. The upcoming addition of an NVIDIA **DGX Spark** (an AI-focused server) opens possibilities to leverage AI (e.g. open-source GPT models) for automation and security tasks.

**Key Concern:** You’re unsure what processes to automate or protect first. Below, we’ll **scope out major security and automation goals** – prioritizing defenses against ransomware and credential theft – and propose a high-level roadmap. Each goal is chosen to reduce risk and improve efficiency given your environment and will include **actionable steps** and considerations for scheduling.

## Key Security Threats to Address
- **Ransomware Attacks:** Ransomware is a top concern for any business. A recent example in the auto dealership industry was the **June 2024 attack on CDK Global’s DMS platform**, which disrupted operations at ~15,000 dealerships and **crippled critical sales and service functions**. That incident involved a major ransomware infection that shut down CDK’s core systems, causing chaos for dealerships dependent on that DMS. This underscores that a successful ransomware attack can **grind business to a halt**. 

- **Stolen Credentials and Account Takeovers:** Credential theft (phishing, malware stealing passwords or tokens) is another serious risk – in fact, **over 60% of breaches involve weak or stolen passwords** according to Verizon’s 2024 Data Breach report. Attackers who steal a user’s password or session token can impersonate that user and access sensitive data. For example, around the same time as the CDK incident, cloud provider Snowflake revealed hackers accessed many customer accounts using **stolen login credentials obtained via infostealer malware**. Your own recent token compromise is a warning sign: **if an attacker gains a foothold with stolen creds, they can bypass your defenses**. Preventing unauthorized access (through MFA, monitoring, etc.) is absolutely critical.

## Automation and Security Goals

### 1. Strengthen Identity Security and Access Controls
- Enforce **Multi-Factor Authentication (MFA) for all users**. MFA blocks over 99% of account takeover attacks. Use authenticator apps or FIDO2 keys where possible.  
- Configure **Conditional Access Policies**: block legacy auth, enforce MFA on risky sign-ins, restrict foreign logins.  
- Implement **Single Sign-On (SSO)** for DealerTrack and other SaaS if possible.  
- Set up **account monitoring & incident response**: alerts for risky logins, auto-revoke sessions, scripted account lockdown.  
- Launch **phishing awareness training** quarterly with Microsoft’s built-in Attack Simulator.

### 2. Enhance Endpoint Protection and Ransomware Resilience
- Maximize **Defender for Endpoint**: ASR rules, ransomware protection, Controlled Folder Access, Tamper Protection, automated remediation.  
- Verify **OneDrive/SharePoint versioning & recycle bin** (500 versions, 93-day recovery). Use OneDrive File Restore (30 days).  
- Add **third-party or immutable backups** for M365 data and offline archives for DMS exports.  
- Secure the **on-prem server**: patch, Defender for Servers license, firewall/VPN only, no public RDP. Backup/snapshot regularly.

### 3. Secure Cloud Services and Data Governance
- Create **Purview DLP policies** for PII/financial data. Start in audit mode, then enforce.  
- Restrict **external sharing** in SharePoint/OneDrive. Review guest access biannually.  
- For **DealerTrack migration**: enforce MFA, least privilege accounts, decommission CDK accounts post-cutover. Archive CDK exports securely.  
- Adopt **Zero Trust**: least privilege, always verify, device compliance required.

### 4. Leverage AI and Automation for IT Operations
- Use DGX Spark + GPT-OSS to analyze Defender/Intune/Entra logs for anomalies.  
- Build **internal chatbot** for user FAQs and IT support.  
- Automate **user on/off-boarding** via Power Automate/Intune.  
- Automate compliance reports (patch status, risky logins, Secure Score).  
- Use GPT locally to generate/test scripts safely.

### 5. User Engagement and Policy Enforcement
- Update **Acceptable Use Policies**: MFA required, no password reuse, data handling rules.  
- Run **regular drills/tests**: simulate ransomware recovery, account breach response.  
- Monitor **Secure Score** monthly and automate reports.  
- Maintain **hardware/software lifecycle**: phase out unsupported OS/apps.

## Implementation Roadmap

**Phase 1 – Immediate (0–1 month)**  
- Enforce MFA for all users.  
- Confirm Defender deployment, enable Cloud Protection.  
- Audit OneDrive/SharePoint recovery settings.  
- Launch phishing simulation.  
- Start DealerTrack security planning.  

**Phase 2 – Short Term (2–3 months)**  
- Conditional Access policies live.  
- Enforce ASR rules, Controlled Folder Access, Tamper Protection.  
- Add 3rd-party backup.  
- Create Purview DLP policies.  
- Execute secure DealerTrack cutover.  

**Phase 3 – Medium Term (4–6 months)**  
- Deploy DGX Spark, experiment with log analysis AI.  
- Build IT assistant chatbot.  
- Automate on/off-boarding workflows.  
- Stand up compliance dashboards.  

**Phase 4 – Long Term (6+ months)**  
- Formalize Incident Response Plan, run tabletop exercises.  
- Expand AI use-cases to business data.  
- Biannual recovery drills.  
- Ongoing patching, Secure Score tracking, user training.  

## Conclusion
This roadmap strengthens defenses against ransomware and credential theft with layered security (MFA, EDR, backups, DLP) while introducing automation to reduce manual burden. AI (Claude, ChatGPT, GPT-OSS) will augment IT operations, enabling a sustainable one-person IT/security department to keep Jess Ford secure and resilient.
"""

# Save full plan to markdown file
full_plan_file = "/mnt/data/jess_ford_cybersecurity_plan_full.md"
pypandoc.convert_text(full_plan_text, 'md', format='md', outputfile=full_plan_file, extra_args=['--standalone'])

full_plan_file
