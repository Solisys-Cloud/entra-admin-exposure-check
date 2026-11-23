<#
.SYNOPSIS
    Read-only check of what a phishing campaign against your Entra ID administrators would find.

.DESCRIPTION
    Lists, without changing anything:
      1. The tenant technical and security notification email addresses.
      2. Members of highly privileged directory roles (active and, if available, PIM-eligible).
      3. Whether each of those administrators has a phishing-resistant method registered
         (passkey or FIDO2 key, Windows Hello for Business, platform credential, certificate).
      4. Whether an enabled Conditional Access policy requires the built-in
         "Phishing-resistant MFA" authentication strength for directory roles.

    It does not tell you what was exposed in an incident. It shows where an attacker who
    already knows your admin email addresses would hit the weakest point.

.NOTES
    Written by Olivier Lumeau
    https://github.com/Solisys-Cloud/entra-admin-exposure-check

    Requires the Microsoft Graph PowerShell SDK:  Install-Module Microsoft.Graph -Scope CurrentUser
    Run it as a Global Reader (least privileged role that can read other users' authentication methods).
    All permissions requested are read-only.
    If a cmdlet fails to load, update all Microsoft.Graph modules to the same version:
        Update-Module Microsoft.Graph
#>

[CmdletBinding()]
param(
    # Optional path to export the administrator table as CSV.
    [string]$CsvPath
)

$scopes = @(
    'Organization.Read.All',
    'RoleManagement.Read.Directory',
    'UserAuthenticationMethod.Read.All',
    'Policy.Read.All'
)
Connect-MgGraph -Scopes $scopes -NoWelcome

# Roles Microsoft recommends protecting with phishing-resistant MFA at a minimum.
$privilegedRoles = @(
    'Global Administrator', 'Application Administrator', 'Authentication Administrator',
    'Billing Administrator', 'Cloud Application Administrator', 'Conditional Access Administrator',
    'Exchange Administrator', 'Helpdesk Administrator', 'Password Administrator',
    'Privileged Authentication Administrator', 'Privileged Role Administrator',
    'Security Administrator', 'SharePoint Administrator', 'User Administrator'
)

$phishingResistantTypes = @(
    '#microsoft.graph.fido2AuthenticationMethod',
    '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
    '#microsoft.graph.platformCredentialAuthenticationMethod',
    '#microsoft.graph.x509CertificateAuthenticationMethod'
)

# 1. Notification contacts
$org = Get-MgOrganization
Write-Host "`n=== Tenant notification contacts ===" -ForegroundColor Cyan
Write-Host ("Technical notification emails : {0}" -f (($org.TechnicalNotificationMails) -join ', '))
Write-Host ("Security notification emails  : {0}" -f (($org.SecurityComplianceNotificationMails) -join ', '))

# 2. Privileged role members (active)
try {
    $definitions = Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop |
        Where-Object { $_.DisplayName -in $privilegedRoles }
}
catch {
    Write-Error "Could not read role definitions: $($_.Exception.Message)"
    Write-Error 'Check that all Microsoft.Graph modules are installed in the same version, and that RoleManagement.Read.Directory was consented.'
    Disconnect-MgGraph | Out-Null
    return
}
$definitionById = @{}
$definitions | ForEach-Object { $definitionById[$_.Id] = $_.DisplayName }

$assignments = @()
foreach ($definition in $definitions) {
    $active = Get-MgRoleManagementDirectoryRoleAssignment -All -Filter "roleDefinitionId eq '$($definition.Id)'"
    foreach ($a in $active) {
        $assignments += [pscustomobject]@{ PrincipalId = $a.PrincipalId; Role = $definition.DisplayName; Type = 'Active' }
    }
}

# PIM-eligible assignments (needs Entra ID P2; skipped if unavailable)
try {
    $eligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
    foreach ($e in $eligible | Where-Object { $definitionById.ContainsKey($_.RoleDefinitionId) }) {
        $assignments += [pscustomobject]@{ PrincipalId = $e.PrincipalId; Role = $definitionById[$e.RoleDefinitionId]; Type = 'Eligible' }
    }
}
catch {
    Write-Warning 'PIM-eligible assignments could not be read (no Entra ID P2, or missing permission). Active assignments only.'
}

# 3. Authentication methods per privileged user
$results = foreach ($group in $assignments | Group-Object PrincipalId) {
    $principalId = $group.Name
    $user = Get-MgUser -UserId $principalId -Property DisplayName, UserPrincipalName, Mail -ErrorAction SilentlyContinue
    if (-not $user) {
        # Groups and service principals can hold roles too: report them, do not inspect methods.
        [pscustomobject]@{
            Admin = $principalId; Email = '(not a user: group or service principal)'
            Roles = (($group.Group | ForEach-Object { "$($_.Role) [$($_.Type)]" }) -join '; ')
            PhishingResistant = 'n/a'; Methods = ''
        }
        continue
    }
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $principalId -ErrorAction Stop
    }
    catch {
        $reason = if ($user.UserPrincipalName -like '*#EXT#*') {
            '(guest account: its methods are managed in its home tenant)'
        }
        else {
            '(cannot read methods: Global Reader role and UserAuthenticationMethod.Read.All needed)'
        }
        [pscustomobject]@{
            Admin = $user.UserPrincipalName; Email = $user.Mail
            Roles = (($group.Group | ForEach-Object { "$($_.Role) [$($_.Type)]" }) -join '; ')
            PhishingResistant = 'Unknown'; Methods = $reason
        }
        continue
    }
    $types = $methods | ForEach-Object { $_.AdditionalProperties['@odata.type'] }
    $hasPhishingResistant = [bool]($types | Where-Object { $_ -in $phishingResistantTypes })
    [pscustomobject]@{
        Admin             = $user.UserPrincipalName
        Email             = $user.Mail
        Roles             = (($group.Group | ForEach-Object { "$($_.Role) [$($_.Type)]" }) -join '; ')
        PhishingResistant = if ($hasPhishingResistant) { 'Yes' } else { 'NO' }
        Methods           = (($types | ForEach-Object { $_ -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', '' }) -join ', ')
    }
}

Write-Host "`n=== Privileged administrators ===" -ForegroundColor Cyan
$results | Sort-Object PhishingResistant, Admin | Format-Table Admin, PhishingResistant, Roles, Methods -AutoSize -Wrap

# 4. Conditional Access: phishing-resistant strength required for directory roles?
$phishingResistantStrengthId = '00000000-0000-0000-0000-000000000004'
$policies = Get-MgIdentityConditionalAccessPolicy -All
$matching = $policies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.Users.IncludeRoles.Count -gt 0 -and
    $_.GrantControls.AuthenticationStrength.Id -eq $phishingResistantStrengthId
}

Write-Host "`n=== Conditional Access ===" -ForegroundColor Cyan
if ($matching) {
    $matching | ForEach-Object { Write-Host ("Enabled policy requiring phishing-resistant MFA for roles: {0}" -f $_.DisplayName) -ForegroundColor Green }
}
else {
    Write-Host 'No enabled policy requires the Phishing-resistant MFA strength for directory roles.' -ForegroundColor Yellow
}

# Summary
$weak = @($results | Where-Object PhishingResistant -eq 'NO')
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host ("Privileged principals checked              : {0}" -f @($results).Count)
$unknown = @($results | Where-Object PhishingResistant -eq 'Unknown')
Write-Host ("Admins without a phishing-resistant method : {0}" -f $weak.Count) -ForegroundColor ($(if ($weak.Count) { 'Yellow' } else { 'Green' }))
$guests = @($results | Where-Object { $_.Admin -like '*#EXT#*' })
Write-Host ("Guest accounts holding privileged roles    : {0}" -f $guests.Count) -ForegroundColor ($(if ($guests.Count) { 'Yellow' } else { 'Green' }))
if ($unknown.Count) { Write-Host ("Admins whose methods could not be read     : {0}" -f $unknown.Count) -ForegroundColor Yellow }

if ($CsvPath) {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to $CsvPath"
}

Disconnect-MgGraph | Out-Null
