<#
.SYNOPSIS
    Deploys a Microsoft Purview endpoint DLP policy aimed at keeping sensitive
    content (secrets, source, internal IDs) out of generative-AI websites.

.DESCRIPTION
    Scripts the parts of a Purview DLP rollout that script cleanly:
      1. Connects to Security & Compliance PowerShell.
      2. Imports the custom Sensitive Information Types in custom-sits.xml.
      3. Creates an endpoint DLP policy + rule in TEST mode (audit only, with
         user notifications) so you can measure impact before enforcing.

    The AI-domain restriction itself (the "sensitive service domain group"
    listing chatgpt.com, claude.ai, gemini.google.com, etc.) and device
    onboarding are configured in the portal - see README.md steps 2 and 5.
    This script deliberately starts in audit mode; flip to enforce only after
    reviewing activity explorer. Nothing here monitors users silently: endpoint
    DLP activity is visible to admins and, when you enable notifications, to the
    user on the device.

.NOTES
    Requires: the ExchangeOnlineManagement module, a Compliance Admin / DLP
    role, and E5 / E5 Compliance (or equivalent) licensing. Run as yourself;
    do not hard-code credentials.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string] $UserPrincipalName,

    [string] $PolicyName = 'AI Data Protection (Endpoint)',

    [string] $RuleName = 'Sensitive content to AI sites',

    [string] $SitRulePackPath = "$PSScriptRoot/custom-sits.xml",

    # Audit first. Switch to 'Enable' only after reviewing Activity Explorer.
    [ValidateSet('TestWithNotifications', 'TestWithoutNotifications', 'Enable')]
    [string] $Mode = 'TestWithNotifications'
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string] $Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }

# --- 1. Connect -------------------------------------------------------------
Write-Step "Connecting to Security & Compliance PowerShell as $UserPrincipalName"
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    throw "ExchangeOnlineManagement module not found. Install with: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
}
Import-Module ExchangeOnlineManagement
Connect-IPPSSession -UserPrincipalName $UserPrincipalName

# --- 2. Import custom SITs ---------------------------------------------------
Write-Step "Importing custom Sensitive Information Types from $SitRulePackPath"
if (-not (Test-Path $SitRulePackPath)) { throw "SIT rule pack not found: $SitRulePackPath" }
if ($PSCmdlet.ShouldProcess($SitRulePackPath, 'Import DLP SIT rule package')) {
    try {
        New-DlpSensitiveInformationTypeRulePackage -FileData ([System.IO.File]::ReadAllBytes($SitRulePackPath)) | Out-Null
        Write-Host "    Rule package imported." -ForegroundColor Green
    }
    catch {
        # Re-running? Update the existing pack instead of failing outright.
        Write-Warning "Create failed ($($_.Exception.Message)). If the pack already exists, update it with Set-DlpSensitiveInformationTypeRulePackage."
    }
}

# Sanity check that the custom SITs resolved.
$customSitNames = @('Company Internal Service Token', 'Company Employee ID')
foreach ($name in $customSitNames) {
    if (-not (Get-DlpSensitiveInformationType -Identity $name -ErrorAction SilentlyContinue)) {
        Write-Warning "Custom SIT '$name' not found yet - it can take a few minutes to propagate."
    }
}

# --- 3. Content to match -----------------------------------------------------
# Built-in SITs cover common cloud/secret material; custom SITs cover your
# internal patterns. Tune confidence/counts to your false-positive tolerance.
# Tuned for a software company: cloud/service credentials + your internal
# patterns. Add/remove to match your real data classifications; comment out
# anything that produces noise in your environment.
$sensitiveTypes = @(
    # --- Secrets / cloud credentials (the main AI-leak risk for a dev team) ---
    @{ Name = 'Azure Storage Account Key';                      minCount = '1' }
    @{ Name = 'Azure Storage Account Key (Generic)';            minCount = '1' }
    @{ Name = 'Azure Service Bus Connection String';            minCount = '1' }
    @{ Name = 'Azure SQL Connection String';                    minCount = '1' }
    @{ Name = 'Amazon S3 Client Secret Access Key';             minCount = '1' }
    @{ Name = 'Google API Key';                                 minCount = '1' }
    @{ Name = 'General Symmetric Key';                          minCount = '1' }
    @{ Name = 'Client Secret / API Key';                        minCount = '1' }
    @{ Name = 'GitHub Personal Access Token';                   minCount = '1' }
    @{ Name = 'Private key (PKCS)';                             minCount = '1' }

    # --- Your internal patterns (from custom-sits.xml) ---
    @{ Name = 'Company Internal Service Token';                 minCount = '1' }
    @{ Name = 'Company Employee ID';                            minCount = '1' }

    # --- Regulated data: enable the ones your company actually handles ---
    @{ Name = 'Credit Card Number';                             minCount = '1' }
    # @{ Name = 'U.S. Social Security Number (SSN)';             minCount = '1' }
    # @{ Name = 'EU Passport Number';                           minCount = '1' }
)
# NOTE: built-in SIT names vary by tenant/version. Confirm each exists with
#   Get-DlpSensitiveInformationType | Select Name | Sort Name
# and drop any that don't resolve before switching the policy to Enable.

# --- 4. Policy + rule (endpoint / Devices), TEST mode ------------------------
Write-Step "Creating endpoint DLP policy '$PolicyName' in mode '$Mode'"
if (-not (Get-DlpCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($PolicyName, 'Create DLP policy for Devices')) {
        New-DlpCompliancePolicy -Name $PolicyName `
            -EndpointDlpLocation 'All' `
            -Mode $Mode `
            -Comment 'Keeps secrets, source, and internal IDs out of generative-AI sites. See security/purview-dlp/README.md.' | Out-Null
        Write-Host "    Policy created." -ForegroundColor Green
    }
}
else {
    Write-Host "    Policy already exists; leaving it as-is." -ForegroundColor Yellow
}

Write-Step "Creating rule '$RuleName'"
if (-not (Get-DlpComplianceRule -Identity $RuleName -ErrorAction SilentlyContinue)) {
    if ($PSCmdlet.ShouldProcess($RuleName, 'Create DLP rule')) {
        # Audit + notify in test mode. BlockAccess is intentionally left off here;
        # turn on blocking in the portal once the AI domain group is attached and
        # you have reviewed Activity Explorer. See README step 6.
        New-DlpComplianceRule -Name $RuleName `
            -Policy $PolicyName `
            -ContentContainsSensitiveInformation $sensitiveTypes `
            -GenerateAlert $UserPrincipalName `
            -NotifyUser 'Owner' `
            -Comment 'Attach the AI sensitive-service-domain group and set the egress action in the portal.' | Out-Null
        Write-Host "    Rule created." -ForegroundColor Green
    }
}
else {
    Write-Host "    Rule already exists; leaving it as-is." -ForegroundColor Yellow
}

Write-Step "Done. Next: attach the AI domain group and review Activity Explorer (README steps 5-6) before switching Mode to 'Enable'."
