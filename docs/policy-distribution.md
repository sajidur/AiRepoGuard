# Central URL-policy distribution (self-hosted server + agent)

Push the block/monitor policy to one server; every host fetches it and applies
the browser URL blocklist automatically. No per-machine clicking.

```
   admin                     PolicyServer (ASP.NET)            each host
  ───────                   ──────────────────────          ─────────────
  PUT /policy  ─────────▶   stores url-policy.json   ◀─────  PolicyAgent (SYSTEM
  (X-Api-Key)               GET /policy (ETag)               scheduled task, 15 min)
                                                             └─ applies Edge/Chrome
                                                                URLBlocklist in HKLM
```

**Scope:** the agent applies *declarative blocklist policy only* — it writes the
Edge/Chrome `URLBlocklist` registry policy. It does not execute remote commands,
install software, or capture traffic. Run it on company-managed devices with
monitoring disclosed to users.

## 1. Run the server

```powershell
# pick a data dir and an admin API key (use a secret store in production)
$env:POLICY_DIR     = "C:\policy-data"
$env:POLICY_API_KEY = "<long-random-key>"
$env:ASPNETCORE_URLS = "https://0.0.0.0:8080"   # terminate TLS here or at a reverse proxy
airepoguard serve
```

Endpoints:
- `GET /policy` → current JSON (sends `ETag`; honors `If-None-Match` with `304`)
- `GET /policy/version` → `{ "version": "<hash>" }`
- `PUT /policy` → replace policy; requires header `X-Api-Key`; validates JSON has a `block` array
- `GET /healthz` → `ok`

Host it as a Windows service / behind IIS or a reverse proxy with real TLS. The
policy isn't a secret (it's a domain list), but require HTTPS and restrict who
can reach `PUT`.

## 2. Push a policy update

```powershell
curl -X PUT https://policy.corp.example:8080/policy `
     -H "X-Api-Key: <key>" -H "Content-Type: application/json" `
     --data-binary "@security/url-policy/url-policy.json"
# -> {"version":"...."}
```

Edit `security/url-policy/url-policy.json`, re-`PUT`, and every agent picks up the
change on its next run. Keep that file under change review.

## 3. Install the agent on each host

```powershell
# elevated, on each managed machine
security/url-policy/Install-PolicyAgent.ps1 `
    -ServerUrl https://policy.corp.example:8080 -ApiKey <agent-key>
# runs PolicyAgent as SYSTEM at startup and every 15 min
security/url-policy/Install-PolicyAgent.ps1 -Remove   # uninstall the task
```

The agent stores the last-applied version in
`%ProgramData%\AIRepoGuard\agent-version.txt` and does nothing when the policy is
unchanged. Blocklist changes take effect on the next browser launch (or
`chrome://policy` → Reload policies).

## Honest limitations

- Covers **Edge + Chrome/Chromium on managed Windows hosts**. Not Firefox, not
  other apps, and a user with local admin can edit the policy back. For stronger
  enforcement push the same blocklist via Intune/GPO, or block at a DNS filter /
  secure web gateway (`blocklist-domains.txt`).
- The agent owns the `URLBlocklist` key and replaces it each run — don't also set
  that policy by hand on managed machines.
- The API key sits in the scheduled task arguments (readable by local admins);
  rotate it and prefer per-host keys if that matters.
- This distributes a block list; it is not a full endpoint-management platform.
