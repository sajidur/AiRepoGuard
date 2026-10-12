<#
.SYNOPSIS
    Applies the generated AppLocker executable blocklist on THIS machine.

.DESCRIPTION
    Sets the local AppLocker policy from AppLocker.xml (produced by
    `airepoguard app-policy`) and ensures the Application Identity service is
    running, which AppLocker needs to enforce. AppLocker is admin-managed and
    transparent (see secpol.msc > Application Control Policies). Use on
    company-managed devices with the policy disclosed to users.

    Start with the policy in EnforcementMode "AuditOnly" (the compiler default):
    nothing is blocked, but would-be blocks are written to the event log
    (Applications and Services Logs > Microsoft > Windows > AppLocker > EXE and DLL).
    Switch app-policy.json to "Enabled" and re-run only after reviewing those.

    Use -Remove to clear the local AppLocker policy.

.NOTES
    AppLocker ENFORCEMENT requires Windows Enterprise or Education. On Windows Pro
    you can set and audit the policy, but it will not block. For Pro/all editions,
    use App Control for Business (WDAC) instead - see docs/app-control.md.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $XmlPolicy = "$PSScriptRoot/out/AppLocker.xml",
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this in an elevated (Administrator) PowerShell.' }

Import-Module AppLocker -ErrorAction Stop

if ($Remove) {
    if ($PSCmdlet.ShouldProcess('Local AppLocker policy', 'Clear')) {
        $empty = Join-Path $env:TEMP 'applocker-empty.xml'
        '<AppLockerPolicy Version="1"></AppLockerPolicy>' | Set-Content -Path $empty -Encoding UTF8
        Set-AppLockerPolicy -XmlPolicy $empty
        Remove-Item $empty -ErrorAction SilentlyContinue
        Write-Host 'Cleared local AppLocker policy.'
    }
    return
}

if (-not (Test-Path $XmlPolicy)) {
    throw "Not found: $XmlPolicy. Generate it:  dotnet run -- app-policy <app-policy.json>"
}

# Application Identity service must run for AppLocker to take effect.
$svc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($svc) {
    if ($PSCmdlet.ShouldProcess('AppIDSvc', 'Set to automatic and start')) {
        Set-Service -Name AppIDSvc -StartupType Automatic
        if ($svc.Status -ne 'Running') { Start-Service -Name AppIDSvc }
    }
}
else { Write-Warning 'AppIDSvc not found; AppLocker may not enforce on this edition.' }

if ($PSCmdlet.ShouldProcess($XmlPolicy, 'Set local AppLocker policy')) {
    Set-AppLockerPolicy -XmlPolicy $XmlPolicy
    $mode = ([xml](Get-Content $XmlPolicy -Raw)).AppLockerPolicy.RuleCollection.EnforcementMode
    Write-Host "Applied AppLocker policy (EnforcementMode=$mode)."
    if ($mode -eq 'AuditOnly') {
        Write-Host 'AuditOnly: nothing is blocked yet. Check would-be blocks under'
        Write-Host '  Event Viewer > Applications and Services Logs > Microsoft > Windows > AppLocker.'
    }
}
