# AI Repo Guard (.NET 10) — unified security CLI

A .NET CLI toolkit for AI-safety and data-loss prevention around a codebase and
an organization. One project, one solution, one executable with subcommands
(the only external dependency is Microsoft's ETW library, used by `netreport`):

| Subcommand | What it does | More |
|------------|--------------|------|
| `audit` / `preflight` / `init` | Repo preflight: sensitive paths, Git state, secrets, Claude deny rules | this file |
| `scan` | Content DLP: classify files for PII/PCI/PHI/secrets + EDM, optional redact/quarantine | `OrgDlp.Core` engine |
| `url-policy` | Compile one monitor/block domain JSON into Defender / Purview / SWG / KQL exports + browser blocklist | [security/url-policy](security/url-policy/README.md) |
| `app-policy` | Compile an executable blocklist (path/publisher/hash) into an AppLocker policy XML | [docs/app-control.md](docs/app-control.md) |
| `collect` | Pull Purview DLP events from the M365 audit API into a local store + dashboard | [docs/dlp-collector.md](docs/dlp-collector.md) |

Everything is **one project / one executable**. More subcommands:

| Subcommand | What it does | More |
|------------|--------------|------|
| `serve` | ASP.NET policy server: stores/serves/versions the url- and app-policies (admins `PUT`, agents `GET`) | [docs/policy-distribution.md](docs/policy-distribution.md) |
| `agent` | On each host (SYSTEM task): fetches policy and applies the URL blocklist (and, opt-in, AppLocker) | same |
| `netreport` | Per-endpoint / per-process network-usage report (bytes sent/received) via kernel ETW | [docs/net-report.md](docs/net-report.md) |

Related config and guidance:
[Purview endpoint DLP](security/purview-dlp/README.md) ·
[network/traffic visibility](docs/traffic-visibility.md) ·
[URL block/monitor policy](security/url-policy/README.md).

> These pieces are admin-managed and meant to be **disclosed to users**. The
> toolkit does not silently intercept traffic or control endpoints; it leans on
> Microsoft's supported, auditable enforcement points.

## Requirements

- .NET 10 SDK
- Git available on PATH (for `audit`/`preflight`)
- Run against a local Git repository (for the repo commands)

## Run from source

With **no arguments** it runs a default pipeline (audit + scan + url-policy +
app-policy) driven by [airepoguard.json](src/AiRepoGuard/airepoguard.json) — no
parameters to pass. Edit that file to change paths or toggle steps. Each step is
also a subcommand you can run on its own:

```powershell
cd src/AiRepoGuard
dotnet run                                  # run the default pipeline (airepoguard.json)
dotnet run -- run                           # same, explicit
dotnet run -- init C:\work\my-repo
dotnet run -- audit C:\work\my-repo
dotnet run -- preflight C:\work\my-repo
dotnet run -- scan C:\work\my-repo --policy dlp-policy.sample.json
dotnet run -- url-policy ..\..\security\url-policy\url-policy.json
dotnet run -- collect report
```

Or build the whole solution: `dotnet build AiRepoGuard.slnx -c Release`.

Build a runnable app:

```powershell
dotnet publish .\src\AiRepoGuard\AiRepoGuard.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o .\publish\win-x64
```

Then:

```powershell
.\publish\win-x64\AiRepoGuard.exe preflight C:\work\my-repo
```

Use `--policy C:\secure-policy\enterprise-policy.json` to load a policy stored outside the repository. Keep enterprise policy read-only to developers.

## Exit codes

- `0`: no blocking findings
- `1`: preflight blocked
- `2`: usage/path error
- `3`: audit found blocking findings

## Important limitations

This is a starter, not a certified endpoint DLP product. It does **not** intercept model API requests, prevent all exfiltration, install Windows Firewall rules, enforce centrally managed Claude settings, protect backups, or guarantee secret detection. Pattern-based secret scanning has false positives and false negatives. It checks some file paths and text patterns only. A determined or compromised process may bypass repository-local controls.

For enterprise enforcement, pair this tool with:

1. Centrally deployed, administrator-protected Claude Code managed settings.
2. OS sandboxing and least-privilege accounts.
3. Windows Defender/EDR and firewall or secure web gateway egress rules.
4. Organization-controlled AI accounts and verified contractual data handling.
5. Git server branch protection, PR review, CI secret scanning, and immutable backups.
6. A local inference path for repositories classified `LocalOnly`; the tool intentionally blocks preflight for this classification because it cannot enforce that network policy itself.

## Production hardening before rollout

- Validate Claude Code setting keys against the currently installed version.
- Expand secret detection using a maintained secret scanner (for example, Gitleaks) and run it on Git history as well as the working tree.
- Add signed policy files, policy versioning, centralized event collection, and tamper-resistant audit storage.
- Implement a Windows service/device-management deployment and network controls separately.
- Add unit/integration tests and test on representative Windows/WSL2 endpoints.
- Do not treat a clean scan as proof that a repository is safe for cloud processing.
