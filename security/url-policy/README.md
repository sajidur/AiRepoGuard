# URL / domain policy

One JSON file lists the destinations you **monitor** and the ones you **block**;
a compiler turns it into the import formats each enforcement point needs. Edit
the JSON, recompile, re-import — the four consoles never drift out of sync.

## Files

| File | Purpose |
|------|---------|
| `url-policy.json` | The source of truth: `monitor[]` and `block[]` domain lists. |
| `url-policy.schema.json` | JSON Schema for editor validation / CI. |
| `out/` | Generated exports (git-ignored; recompile anytime). |

## Edit the policy

```jsonc
{
  "defaults": { "monitorAction": "Audit", "blockAction": "Block" },
  "monitor": [ { "domain": "claude.ai", "category": "GenAI-Sanctioned", "reason": "..." } ],
  "block":   [ { "domain": "*.pastebin.com", "category": "Exfil-Risk", "reason": "..." } ]
}
```

- `domain` accepts `example.com`, `*.example.com`, or a full URL (reduced to its host).
- Optional per-entry `action` overrides the list default.
  Monitor: `Audit` | `Warn` | `Allowed`. Block: `Block` | `Warn` | `BlockAndRemediate`.
- A domain in **both** lists, an invalid domain, or a bad action fails the build.

## Compile

```powershell
cd src/AiRepoGuard
dotnet run -- url-policy ..\..\security\url-policy\url-policy.json
# -> writes security/url-policy/out/*
```

## Compiling does not block — apply one of these

Running `url-policy` only *generates* files. Until you apply one, blocked sites
still load. Pick an enforcement point:

| Output | Apply it to | Effect |
|--------|-------------|--------|
| `browser-urlblocklist.reg` | This device, admin: `reg import` (or push via Intune/GPO) | **Blocks the sites in Edge & Chrome** |
| `hosts.txt` | `C:\Windows\System32\drivers\etc\hosts` (admin) | Local DNS block (DoH can bypass) |
| `blocklist-domains.txt` | Secure web gateway / DNS filter (see [`../../docs/traffic-visibility.md`](../../docs/traffic-visibility.md)) | Network-layer block (most robust) |
| `defender-indicators.csv` | Defender > Settings > Endpoints > **Indicators** (import) | Block / audit on all onboarded devices |
| `purview-sensitive-domains.txt` | Purview **sensitive service domain group** (see [`../purview-dlp`](../purview-dlp/README.md)) | Content-aware DLP on egress to monitored sites |
| `monitor-kql.txt` | Defender Advanced Hunting / Sentinel | Report connections to monitored domains |

### Quickest in-browser block on this machine

```powershell
# from an elevated (Administrator) PowerShell
cd src/AiRepoGuard
dotnet run -- url-policy ..\..\security\url-policy\url-policy.json
cd ..\..\security\url-policy
./Apply-BrowserBlocklist.ps1            # imports the .reg into HKLM
#   ...then restart Edge/Chrome. Verify at edge://policy.
./Apply-BrowserBlocklist.ps1 -Remove    # undo
```

This blocks Edge + Chrome/Chromium on this device. It does **not** cover other
browsers, other apps, or a user with admin rights who edits the policy. For
device-wide or org-wide enforcement, push the `.reg` via Intune/GPO or use a DNS
filter / secure web gateway. The block list enforces; the monitor list is where
you watch for sensitive egress. Keep monitoring disclosed to users and the
policy file under change review.
