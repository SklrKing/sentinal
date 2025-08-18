# Scoping Automation and Security Goals for a Cloud-Centric Environment

## Environment Overview and Challenges

You've described a **cloud-first IT environment** using Microsoft 365
Business Premium (with Defender for Endpoint EDR), OneDrive/SharePoint
for file storage, and a dealership management system (DMS) currently on
CDK Drive and soon moving to DealerTrack. Aside from an experimental
on-prem server, all core systems are cloud-based. This setup offers
flexibility and easy access, but it also introduces critical **security
challenges** -- notably the threats of **ransomware** and **stolen
credentials**. You've already experienced a scare with a compromised
login token, underscoring the need for robust security measures. The
user base has generally low technical skill, meaning any solutions
should be **highly automated and user-friendly**.

**Available Tools:** Fortunately, your Microsoft 365 Business Premium
subscription provides a strong security foundation -- including
**Microsoft Defender for Business** (endpoint protection/EDR),
**Microsoft Entra ID (Azure AD) Plan 1** for identity and access
management, **advanced multifactor authentication** (MFA), and **data
protection tools like Purview DLP**【17†L519-L527】【17†L584-L588】.
These can help secure identities, devices, and data if configured
properly. The upcoming addition of an NVIDIA **DGX Spark** (an
AI-focused server) opens possibilities to leverage AI (e.g. open-source
GPT models) for automation and security tasks.

**Key Concern:** You're unsure what processes to automate or protect
first. Below, we'll **scope out major security and automation goals** --
prioritizing defenses against ransomware and credential theft -- and
propose a high-level roadmap. Each goal is chosen to reduce risk and
improve efficiency given your environment and will include **actionable
steps** and considerations for scheduling.

## Key Security Threats to Address

Before defining automation goals, it's important to identify the main
threats and their implications:

-   **Ransomware Attacks:** Ransomware is a top concern for any
    business. A recent example in the auto dealership industry was the
    **June 2024 attack on CDK Global's DMS platform**, which disrupted
    operations at \~15,000 dealerships and **crippled critical sales and
    service functions**【6†L199-L207】. That incident involved a major
    ransomware infection that shut down CDK's core systems, causing
    chaos for dealerships dependent on that DMS【6†L208-L212】. This
    underscores that a successful ransomware attack can **grind business
    to a halt**. Given that your data is primarily in cloud services
    (OneDrive, SharePoint, SaaS DMS), ransomware could manifest through
    infected endpoints syncing encrypted files or an attacker gaining
    access to accounts and encrypting or deleting data.

-   **Stolen Credentials and Account Takeovers:** Credential theft
    (phishing, malware stealing passwords or tokens) is another serious
    risk -- in fact, **over 60% of breaches involve weak or stolen
    passwords** according to Verizon's 2024 Data Breach
    report【21†L173-L180】. Attackers who steal a user's password or
    session token can impersonate that user and access sensitive data.
    For example, around the same time as the CDK incident, cloud
    provider Snowflake revealed hackers accessed many customer accounts
    using **stolen login credentials obtained via infostealer
    malware**【6†L215-L223】. This led to leaked passwords and potential
    exposure of millions of records. Your own recent token compromise is
    a warning sign: **if an attacker gains a foothold with stolen creds,
    they can bypass your defenses**. Preventing unauthorized access
    (through MFA, monitoring, etc.) is absolutely critical.

## Automation and Security Goals

### 1. Strengthen Identity Security and Access Controls

... (full text continues as above) ...
