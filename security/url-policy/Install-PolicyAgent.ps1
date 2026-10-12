<#
.SYNOPSIS
    Installs PolicyAgent as a SYSTEM scheduled task on this host so it fetches the
    central URL policy and applies the browser blocklist automatically.

.DESCRIPTION
    Registers a scheduled task that runs PolicyAgent.exe at startup and every
    -IntervalMinutes. The agent pulls url-policy.json from -ServerUrl and applies
    ONLY the Edge/Chrome URL blocklist (declarative policy, no remote commands).
    Requires local administrator rights; the task runs as SYSTEM so it can write
    machine policy. Use on company-managed devices with monitoring disclosed.

    Use -Remove to unregister the task.

.EXAMPLE
    ./Install-PolicyAgent.ps1 -ServerUrl https://policy.corp.example:8080 -ApiKey <agent-key>
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Install')]
    [string] $ServerUrl,

    [Parameter(ParameterSetName = 'Install')]
    [string] $ApiKey,

    [Parameter(ParameterSetName = 'Install')]
    [string] $AgentExe = "$PSScriptRoot/../../src/AiRepoGuard/bin/Release/net10.0-windows/AiRepoGuard.exe",

    [Parameter(ParameterSetName = 'Install')]
    [switch] $ApplyAppPolicy,

    [Parameter(ParameterSetName = 'Install')]
    [ValidateRange(5, 1440)]
    [int] $IntervalMinutes = 15,

    [string] $TaskName = 'AIRepoGuard URL Policy Agent',

    [Parameter(Mandatory = $true, ParameterSetName = 'Remove')]
    [switch] $Remove
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this in an elevated (Administrator) PowerShell.' }

if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host "Removed scheduled task '$TaskName'. (Browser policy already applied is left in place;"
            Write-Host " run Apply-BrowserBlocklist.ps1 -Remove to clear it.)"
        }
    }
    else { Write-Host "No scheduled task named '$TaskName'." }
    return
}

$AgentExe = (Resolve-Path $AgentExe).Path
if (-not (Test-Path $AgentExe)) { throw "Agent not found: $AgentExe. Build it: dotnet build -c Release." }

# The agent is the `agent` subcommand of the single AiRepoGuard.exe.
$argline = "agent --server `"$ServerUrl`""
if ($ApiKey) { $argline += " --key `"$ApiKey`"" }
if ($ApplyAppPolicy) { $argline += " --apply-app-policy" }

$action    = New-ScheduledTaskAction -Execute $AgentExe -Argument $argline
$atStartup = New-ScheduledTaskTrigger -AtStartup
$recurring = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
                -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

if ($PSCmdlet.ShouldProcess($TaskName, "Register scheduled task (every $IntervalMinutes min, SYSTEM)")) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $atStartup, $recurring `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Installed '$TaskName' (every $IntervalMinutes min as SYSTEM)."
    Write-Host "Note: the API key is stored in the task's arguments, readable by local admins."
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Kicked off a first run. Check it with:  Get-ScheduledTaskInfo -TaskName '$TaskName'"
}
