# Application control (block executables)

Block named executables from running, OS-enforced, via **AppLocker**. One JSON
file lists what to block; `airepoguard app-policy` compiles it to AppLocker XML;
you apply it locally or distribute it through PolicyServer + PolicyAgent.

This is admin-managed, visible (secpol.msc / event log), and reversible. It
denies specific executables by path / publisher / hash — it does **not** hook or
kill processes, capture traffic, or collect device data.

## 1. Edit the policy — `security/app-policy/app-policy.json`

```jsonc
{
  "enforcementMode": "AuditOnly",   // AuditOnly (log only) | Enabled (enforce)
  "block": [
    { "type": "path",      "name": "Block Downloads", "path": "%OSDRIVE%\\Users\\*\\Downloads\\*.exe", "reason": "..." },
    { "type": "path",      "name": "Block Tor",       "path": "*\\tor.exe" },
    { "type": "publisher", "name": "Block uTorrent",  "publisher": "O=BITTORRENT, INC., ... C=US" },
    { "type": "hash",      "name": "Known-bad tool",  "path": "C:\\tools\\bad.exe" }  // hashed at compile time
  ]
}
```

- **path** — AppLocker path with wildcards and variables (`%OSDRIVE%`, `%PROGRAMFILES%`, …).
- **publisher** — signer subject; blocks all signed binaries from that publisher (use `product`/`binary` to narrow).
- **hash** — `path` points to a local file; the compiler reads it and emits a SHA256 rule.

Start in **AuditOnly**: nothing is blocked, but would-be blocks are logged.
Review, then set `enforcementMode: "Enabled"` and recompile.

## 2. Compile

```powershell
cd src/AiRepoGuard
dotnet run -- app-policy ..\..\security\app-policy\app-policy.json
# -> security/app-policy/out/AppLocker.xml
```

The compiler always adds a baseline *Allow all* rule so only your explicit Deny
rules block (a non-empty AppLocker collection otherwise blocks everything).

## 3a. Apply on one machine

```powershell
# elevated
security/app-policy/Apply-AppLockerPolicy.ps1              # sets policy + starts AppIDSvc
security/app-policy/Apply-AppLockerPolicy.ps1 -Remove      # clear it
```

## 3b. Distribute to all machines (server + agent)

```powershell
# admin: push the compiled XML to PolicyServer
curl -X PUT https://policy.corp.example:8080/app-policy `
     -H "X-Api-Key: <key>" -H "Content-Type: application/xml" `
     --data-binary "@security/app-policy/out/AppLocker.xml"

# each host: let the agent apply it (opt-in flag)
airepoguard agent --server https://policy.corp.example:8080 --apply-app-policy
#   preview only, applies nothing:
airepoguard agent --server https://policy.corp.example:8080 --apply-app-policy --dry-run
```

To enable app-policy in the scheduled task, add `--apply-app-policy` to the
`Install-PolicyAgent.ps1` agent arguments (edit the `$argline`). The agent tracks
the AppLocker policy version separately and re-applies only on change.

## Important: Windows edition

AppLocker **enforcement** requires Windows **Enterprise or Education**. On
Windows **Pro** you can set and **audit** the policy, but it will not block.
For blocking on Pro / all editions, use **App Control for Business (WDAC)** —
author with `New-CIPolicy` / `ConvertFrom-CIPolicy` and deploy via Intune or
`C:\Windows\System32\CodeIntegrity`. The `app-policy.json` model maps to WDAC
rules too; ask if you want a WDAC compiler target added.

## Honest limitations

- Covers executables AppLocker evaluates (Exe collection here; Msi/Script/DLL
  can be added). A user with local admin can change the policy back.
- Enforcement is edition-gated (above). Audit everywhere first.
- This blocks named programs; it is not a full endpoint-protection product. Pair
  with Defender/EDR for malware, and keep the policy disclosed to users.
