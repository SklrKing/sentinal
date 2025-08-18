# Conditional Access Policy Setup for Jess Ford

This document outlines recommended Conditional Access (CA) policies to secure DealerTrack (via Azure AD SSO) and other Microsoft 365 apps for an ~80-user dealership environment.

---

## 1. Baseline MFA
- **Policy Name:** `Require MFA - All Users`
- **Assignments:**
  - Users: All users
  - Exclude: Break-glass admin accounts
  - Cloud apps: All cloud apps
- **Controls:**
  - Grant → Require multi-factor authentication
- **MFA Methods:** Microsoft Authenticator app or FIDO2 security keys preferred

---

## 2. Sign-in Frequency
- **Policy Name:** `Session Control - Standard Users`
- **Assignments:**
  - Users: All users
  - Cloud apps: Office 365, DealerTrack SSO, other enterprise apps
- **Controls:**
  - Session → Sign-in frequency: **7–14 days**
  - Persistent browser session: **Allow**

---

## 3. Device Compliance
- **Policy Name:** `Require Compliant Device - Long Sessions`
- **Assignments:**
  - Users: All users
  - Cloud apps: All
- **Controls:**
  - Grant → Require device to be marked compliant OR hybrid Azure AD joined
- **Notes:**
  - Managed devices = BitLocker, password-protected, inactivity timeout
  - BYOD/unmanaged devices → Shorter lifetime or always MFA

---

## 4. Risk-Based MFA
*(Requires Entra ID P2)*
- **Policy Name:** `Conditional MFA - Risk Based`
- **Assignments:**
  - Users: All users
  - Cloud apps: All
- **Controls:**
  - Sign-in risk = Medium → Require MFA
  - Sign-in risk = High → Block

---

## 5. DealerTrack / CDK App Control
- **Policy Name:** `DealerTrack SSO Protection`
- **Assignments:**
  - Users: DealerTrack users
  - Cloud apps: DealerTrack Enterprise App
- **Controls:**
  - Require MFA
  - Apply same session rules as O365

---

## 6. Shared Computers (Dealership Kiosks)
- **Policy Name:** `Shared Device Policy`
- **Assignments:**
  - Users: Shared PC users (group)
  - Devices: Shared PC device group
- **Controls:**
  - Sign-in frequency: **Every time**
  - Persistent browser session: **Block**

---

## 7. Emergency Controls
- Keep **2 break-glass admin accounts** excluded from all CA policies.
- Protect these with unique hardware keys and strong passwords.
- Store credentials securely offline.

---

## 8. Revocation
- In the event of compromise:
  - Use Entra → User → **Revoke Sessions** to force sign-in and MFA.
