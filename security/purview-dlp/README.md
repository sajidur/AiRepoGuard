# AI Data Protection with Microsoft Purview Endpoint DLP

Goal: stop sensitive content — secrets, source code, customer data, internal
IDs — from being pasted or uploaded into generative-AI websites, with the
events reported to a central console your security team can review.

This uses **Microsoft Purview**, which is admin-managed and visible to users
(that's deliberate — it's what makes it defensible to security, legal, and the
people whose devices it runs on). It does not replace your repo scanner
(`AiRepoGuard`); it complements it: the scanner is dev-side preflight, Purview
is the endpoint backstop.

## What's in this folder

| File | Purpose |
|------|---------|
| `custom-sits.xml` | Custom Sensitive Information Types for your internal patterns (`INT-` tokens, `EMP-` employee IDs), mirrored from `dlp-policy.sample.json`. |
| `Deploy-AiDlpPolicy.ps1` | Imports the custom SITs and creates an endpoint DLP policy + rule in **audit (test) mode**. |
| `README.md` | This guide. |

## Prerequisites

- **Licensing:** Microsoft 365 E5, E5 Compliance, or E5 Information Protection &
  Governance (endpoint DLP + custom SITs need this tier).
- **Roles:** Compliance Administrator or Compliance Data Administrator, plus the
  DLP Compliance Management role for the PowerShell cmdlets.
- **Module:** `Install-Module ExchangeOnlineManagement -Scope CurrentUser`.
- **A pilot device group** — never pilot on everyone at once.

## Rollout steps

### 1. Onboard devices to endpoint DLP (portal)
Purview portal → **Settings → Device onboarding** → turn on. Onboard Windows 10/11
and macOS devices via Intune, Group Policy, or the local script Microsoft
provides. Confirm devices appear under **Settings → Device onboarding → Devices**.
Endpoint DLP sees nothing until devices are onboarded.

### 2. Install the browser extension
- **Microsoft Edge:** native, nothing to install.
- **Chrome / Firefox:** deploy the **Microsoft Purview** extension (via Intune or
  your management tool). Without it, upload/paste restrictions to AI sites are not
  enforced in those browsers.

### 3. Import the custom SITs
```powershell
# Regenerate the GUIDs in custom-sits.xml first (see the comment at its top),
# then from this folder:
.\Deploy-AiDlpPolicy.ps1 -UserPrincipalName you@company.com -WhatIf   # preview
.\Deploy-AiDlpPolicy.ps1 -UserPrincipalName you@company.com           # apply
```
The script connects, imports `custom-sits.xml`, and creates the policy + rule in
`TestWithNotifications` mode. Custom SITs can take a few minutes to propagate —
test one with **Settings → Classifiers → Sensitive info types → (your SIT) → Test**.

### 4. Define the AI domain group (portal)
Purview portal → **Settings → Data loss prevention → Endpoint settings →
Browser and domain restrictions → Sensitive service domain groups** → create a
group, e.g. **"Generative AI sites"**, and add the domains you want to govern:
```
chatgpt.com
chat.openai.com
claude.ai
gemini.google.com
copilot.microsoft.com
poe.com
perplexity.ai
```
Keep this list under version control / change review — it's the heart of the policy.

### 5. Attach the domain group + set the egress action (portal)
Edit the **"Sensitive content to AI sites"** rule the script created:
- **Condition:** *Content is shared ... with* → add the sensitive info types; and
  the endpoint condition *Upload to a restricted cloud service domain / access from
  unallowed browser* scoped to your **Generative AI sites** group.
- **Action:** *Audit or restrict activities on devices* → for the browser egress
  activities (upload to cloud service, paste to browser) start with **Audit only**.

### 6. Measure, then enforce
- Review hits under **Activity Explorer** and **Alerts** for 1–2 weeks on the pilot.
- Tune SIT confidence levels and `minCount` to cut false positives.
- When the signal is clean, raise the action from **Audit** to **Block with
  override** (lets users justify a legit case) or **Block**, and change the policy
  `-Mode` to `Enable`. Expand from the pilot group to broader scope gradually.

## Central reporting

Purview already centralizes this: **Activity Explorer**, **Alerts**, and
**Content Explorer** in the portal. To pull it into your own SIEM/dashboard,
stream **Microsoft Purview Audit** / DLP events to **Microsoft Sentinel** or via
the **Office 365 Management Activity API**. If you want, I can help wire that
ingestion to a dashboard.

## Honest limitations

- Endpoint DLP covers onboarded, managed devices with the extension present. It
  does not cover unmanaged/BYOD browsers, mobile apps, or a user photographing
  the screen.
- Pattern/SIT detection has false positives and negatives — review, don't trust
  blindly.
- Treat this as one layer. Pair it with the repo scanner, least-privilege
  accounts, network/egress controls, and clear user-facing policy so people know
  monitoring is in place.
