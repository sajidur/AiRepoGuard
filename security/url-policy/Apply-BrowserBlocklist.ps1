<#
.SYNOPSIS
    Applies the generated Edge/Chrome enterprise URL blocklist on THIS machine.

.DESCRIPTION
    Imports browser-urlblocklist.reg (produced by `airepoguard url-policy`) into
    HKLM so Microsoft Edge and Google Chrome block the configured domains in the
    browser. This is an admin-managed, transparent policy: users can see it at
    edge://policy / chrome://policy. It requires local administrator rights and
    should only be run on company-managed devices with monitoring disclosed.

    Use -Remove to clear the policy keys again.

.NOTES
    In-browser blocklist covers Edge + Chrome/Chromium on this device. It does
    not cover other browsers or apps; for device- or network-wide enforcement,
    push browser-urlblocklist.reg via Intune/GPO, or use a DNS filter / secure
    web gateway with blocklist-domains.txt. See README.md.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $RegFile = "$PSScriptRoot/out/browser-urlblocklist.reg",
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this in an elevated (Administrator) PowerShell.' }

$keys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge\URLBlocklist',
    'HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlocklist'
)

if ($Remove) {
    foreach ($k in $keys) {
        if ((Test-Path $k) -and $PSCmdlet.ShouldProcess($k, 'Remove URL blocklist policy')) {
            Remove-Item $k -Recurse -Force
            Write-Host "Removed $k"
        }
    }
    Write-Host 'Done. Restart Edge/Chrome to drop the policy.'
    return
}

if (-not (Test-Path $RegFile)) {
    throw "Not found: $RegFile. Generate it first:  dotnet run -- url-policy <url-policy.json>"
}

if ($PSCmdlet.ShouldProcess($RegFile, 'reg import')) {
    & reg.exe import $RegFile
    if ($LASTEXITCODE -ne 0) { throw "reg import failed (exit $LASTEXITCODE)." }
    Write-Host 'Imported. Restart Microsoft Edge and Google Chrome, then verify at edge://policy.'
}
