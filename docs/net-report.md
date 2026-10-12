# `netreport` — network usage by endpoint

Measures how much data this machine sends/receives **per remote endpoint and per
process** over a capture window, using the Windows kernel network ETW provider
(the same source Resource Monitor uses), then writes a JSON + HTML report.

This is a **local report an admin runs and reads** — byte counts only, no packet
contents, no machine control, nothing streamed to a server. Requires an elevated
console (kernel ETW needs admin).

```powershell
# elevated
cd src/AiRepoGuard
dotnet run -- netreport --seconds 20 --out C:\reports
# or the built exe:
AiRepoGuard.exe netreport --seconds 20 --top 50 --out C:\reports
```

| Option | Meaning |
|--------|---------|
| `--seconds N` | capture window (default 20) |
| `--top N` | rows per table (default 50) |
| `--out <dir>` | output dir (default current dir) → `netreport.json` + `netreport.html` |

The HTML shows totals, top endpoints (bytes sent/received with bars), and a
per-process breakdown. The JSON has the same data for further processing.

## Notes & limits

- It samples a **window**, not a persistent meter. For continuous history,
  schedule periodic runs or use Defender for Endpoint network telemetry centrally.
- Byte counts are what the kernel reports per connection during the window.
- For fleet-wide, centralized network visibility, use **Microsoft Defender for
  Endpoint** (`DeviceNetworkEvents`) + Sentinel — see
  [traffic-visibility.md](traffic-visibility.md). This tool is the local,
  on-demand view.
