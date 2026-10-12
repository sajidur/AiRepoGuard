# `collect` — central DLP event collector + dashboard

The `collect` subcommand pulls Purview DLP events from the **Office 365
Management Activity API** (your tenant's own audit feed) into a local store and
renders an HTML dashboard. It's the "central reporting" piece downstream of the
Purview policy in [`security/purview-dlp`](../security/purview-dlp/README.md).

It reads Microsoft's official audit API for your own tenant through an
admin-consented app registration. It does not run on user devices and surfaces
nothing beyond what Purview already logs.

## How it fits together

```
Endpoint DLP policy (Purview)  ->  Management Activity API (DLP.All)
                                         |
                            airepoguard collect pull    -> data/events.jsonl
                            airepoguard collect report  -> data/dashboard.html
```

## 1. Register the app (one time, needs a Global/Application admin)

1. Entra ID → **App registrations → New registration** (single tenant).
2. **API permissions → Add → Office 365 Management APIs → Application
   permissions → `ActivityFeed.Read`** → **Grant admin consent**.
3. **Certificates & secrets → New client secret**. Copy the value.
4. Note the **Directory (tenant) ID** and **Application (client) ID**.

Prefer a certificate over a client secret for anything long-lived.

## 2. Provide credentials (never commit them)

```powershell
$env:AIDLP_TENANT_ID     = "<tenant-guid>"
$env:AIDLP_CLIENT_ID     = "<app-client-id>"
$env:AIDLP_CLIENT_SECRET = "<client-secret>"   # use a secret store in production
$env:AIDLP_DATA_DIR      = "C:\dlp-data"        # optional; defaults to .\data
```

Or pass `--tenant`, `--client`, `--secret`, `--data` on the command line.

## 3. Run

```powershell
cd src/AiRepoGuard
dotnet run -- collect subscribe              # once: turns on the DLP.All feed
dotnet run -- collect pull --hours 24        # pull the last 24h of events (max 168)
dotnet run -- collect report                 # build data/dashboard.html
```

Schedule `collect pull` (Task Scheduler, every 30–60 min) to keep the store
current. `pull` de-duplicates by event ID, so overlapping windows are safe. Open
`data/dashboard.html` for events/day, by workload, top users, by policy, and by
sensitive-info type, plus the 100 most recent events.

### Broader activity (optional)

`--content-type` selects the Management Activity API stream (default `DLP.All`).
Supported: `DLP.All`, `Audit.General`, `Audit.AzureActiveDirectory`,
`Audit.Exchange`, `Audit.SharePoint`. Run `subscribe` once per type, then `pull`:

```powershell
dotnet run -- collect subscribe --content-type Audit.AzureActiveDirectory
dotnet run -- collect pull      --content-type Audit.AzureActiveDirectory --hours 24
```

These are governed, org-owned audit streams — not raw packet capture. For actual
network egress visibility, see [`traffic-visibility.md`](traffic-visibility.md).
Broaden only to streams you have a disclosed, lawful reason to collect.

## Exit codes

- `0` success · `1` HTTP/API error · `2` usage or missing configuration

## Keep out of source control

The event store contains user identities and policy-match metadata — it is
git-ignored (`**/data/`, `*.jsonl`, `**/dashboard.html`). Restrict who can read it.

## Sentinel alternative

If you already run Microsoft Sentinel, enable the **Microsoft 365 / Microsoft
Purview** data connector and query DLP events with KQL instead:

```kusto
CloudAppEvents
| where ActionType has "DLPRuleMatch"
| summarize Events = count() by bin(Timestamp, 1d), AccountDisplayName
| order by Timestamp desc
```

## Honest limitations

- Reports only what Purview detects and logs.
- The Management Activity API retains content ~7 days; `pull` regularly. `--hours`
  is capped at 168.
- Protect the data store, rotate the client secret, review as one signal of several.
