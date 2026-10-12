# Network traffic & app-usage visibility

This covers the part the Management Activity API **does not**: actual network
egress — which sites and cloud/AI services devices connect to, and uploads
leaving the network. The `collect` audit feed shows M365 *activity*
(DLP matches, sign-ins, file access); the tools below show *traffic*.

## Scope this deliberately (read first)

"Monitor all traffic" is rarely what you actually want, and in several
jurisdictions you can't do it lawfully without notice/consent and data
minimization. Monitor **work-relevant egress** — cloud/AI app usage, uploads of
sensitive data, connections to risky destinations — rather than capturing the
full content of every connection (which sweeps in personal and TLS-encrypted
traffic). The tools below are built for that scoped, admin-managed, auditable
model, and they are visible to users by policy rather than covert.

Decide and document, before turning anything on:
- **Whose** devices (company-managed only), and are users notified?
- **What** is captured — metadata/destinations vs. content — and retained how long?
- **Who** can read it, and what's the lawful basis?

## The supported pipeline

```
Managed devices / network
   |  (1) Defender for Endpoint  -> device network connection events
   |  (2) Defender for Cloud Apps Cloud Discovery -> which cloud/AI apps, data volume
   |  (3) Secure web gateway (Global Secure Access / 3rd-party) -> egress logs + control
   v
Microsoft Sentinel (or your SIEM)  <-- central store, hunting, alerts, dashboards
```

### 1. Defender for Endpoint — device network events
Onboarded devices report outbound connections. Query centrally with Advanced
Hunting:
```kusto
DeviceNetworkEvents
| where RemoteUrl has_any ("openai.com","chatgpt.com","claude.ai","gemini.google.com")
| summarize Connections=count(), Devices=dcount(DeviceId) by RemoteUrl, InitiatingProcessAccountUpn
| order by Connections desc
```
Turn on **Network protection** (Intune/MDE) to also *block* risky destinations,
not just observe them.

### 2. Defender for Cloud Apps — Cloud Discovery
Shows which cloud and generative-AI apps are in use, by whom, and how much data
is uploaded — built from MDE telemetry or uploaded firewall/proxy logs. Use it
to inventory AI/cloud usage and tag apps sanctioned / unsanctioned, then enforce
with session or access policies.

### 3. Secure web gateway (egress control)
For enforcement and full egress logging, route traffic through a gateway:
**Microsoft Entra Internet Access (Global Secure Access)** or a third-party SWG
(Zscaler, Netskope). These give per-user egress logs and allow/block by category
or domain — including an AI-sites category — and stream logs to Sentinel.

## Centralize in Sentinel

Connect **Defender XDR**, **Defender for Cloud Apps**, and **Global Secure
Access** data connectors, then build one workbook over `DeviceNetworkEvents`,
`CloudAppEvents`, and the network-access logs. Alert on, e.g., sensitive-data
uploads to unsanctioned AI apps. This is your single pane for traffic + the DLP
matches `airepoguard collect` already gathers.

## How this repo's pieces fit

| Need | Tool |
|------|------|
| Sensitive data heading to AI sites (content-aware) | Purview endpoint DLP — [`security/purview-dlp`](../security/purview-dlp/README.md) |
| Central store of DLP / M365 activity + dashboard | [`airepoguard collect`](dlp-collector.md) |
| Which sites/apps devices actually reach (traffic) | Defender for Endpoint / Cloud Apps / SWG (this doc) |
| Pre-commit repo scan for secrets | AiRepoGuard |

Layer them; none is sufficient alone, and all should be disclosed to users.
