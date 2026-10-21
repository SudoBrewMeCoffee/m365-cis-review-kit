<#
.SYNOPSIS
    Read-only evidence collector for a CIS Microsoft 365 Foundations Benchmark v7.0.0 review.
    Works against ANY Microsoft 365 tenant - nothing tenant-specific is built in.

.DESCRIPTION
    Signs in interactively (MFA supported) and reads every tenant setting the CIS v7.0.0 audit
    procedures test, writing them to one JSON evidence file that Invoke-M365CISAssessment.ps1 scores.

    READ-ONLY. Every call is a Get / HTTP GET. Nothing in the tenant is created, changed or
    deleted. No app registration, client secret or admin consent is created - sign-in uses
    Microsoft's own first-party PowerShell clients with delegated permissions, so the collector
    can never see more than the signed-in account is allowed to see.

    Workloads: Graph (Entra, Intune, SharePoint settings, admin-centre settings), Exchange Online /
    Defender for Office, Purview (Security & Compliance), Teams, SharePoint Online, Fabric / Power BI,
    public DNS (SPF / DKIM / DMARC).

    Expect up to six sign-in prompts (Graph, Exchange, Purview, Teams, SharePoint, Fabric). Each one
    is for the same account. Anything the account cannot read is recorded as an error in the JSON
    and scored as "Not assessed" rather than guessed.

.PARAMETER UserPrincipalName
    Admin account to sign in with, e.g. admin@contoso.com. Global Reader is enough for Graph,
    Exchange, Teams and SharePoint reads; Purview needs Compliance Administrator or Global Reader
    with the Security & Compliance "View-Only" roles; Fabric tenant settings need Fabric Administrator.

.PARAMETER ClientName
    Short name for the client used in the output file name (letters, digits, hyphen). Default: the
    tenant's default domain.

.PARAMETER OutputPath
    Folder for the evidence file. Default: .\Evidence

.PARAMETER SkipWorkload
    Any of Graph, Exchange, Purview, Teams, SharePoint, Fabric, DNS. Useful if one sign-in fails and
    you want the rest anyway; re-run later with -Only to add the missing workload.

.PARAMETER Only
    Collect just these workloads (same names as SkipWorkload). The output is a separate JSON file;
    the assessment script merges every JSON in the evidence folder.

.PARAMETER PerUserMfaCap
    Maximum number of users to query for legacy per-user MFA state (one Graph call each). Default 600.

.EXAMPLE
    .\Get-M365CISEvidence.ps1 -UserPrincipalName admin@contoso.com -ClientName Contoso

.EXAMPLE
    .\Get-M365CISEvidence.ps1 -UserPrincipalName admin@contoso.com -ClientName Contoso -Only SharePoint,Fabric

.NOTES
    Kit version 1.0 - M365 CIS v7 Review Kit (github.com/SudoBrewMeCoffee/m365-cis-review-kit). Requires PowerShell 7 (pwsh) on Windows.
    Run .\Install-Prerequisites.ps1 first.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $UserPrincipalName,
    [string] $ClientName,
    [string] $OutputPath = (Join-Path (Get-Location).Path 'Evidence'),
    [ValidateSet('Graph','Exchange','Purview','Teams','SharePoint','Fabric','DNS')] [string[]] $SkipWorkload = @(),
    [ValidateSet('Graph','Exchange','Purview','Teams','SharePoint','Fabric','DNS')] [string[]] $Only = @(),
    [int] $PerUserMfaCap = 600
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$KitVersion = '1.0'

if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "This script needs PowerShell 7. You are on $($PSVersionTable.PSVersion)." -ForegroundColor Red
    Write-Host "  Windows: winget install Microsoft.PowerShell   (then open 'PowerShell 7' and run again)" -ForegroundColor Yellow
    return
}
function Want([string]$w) { if ($Only.Count -gt 0) { return ($w -in $Only) } ; return ($w -notin $SkipWorkload) }

$evidence = [ordered]@{
    meta = [ordered]@{
        collectedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        collectedBy   = $UserPrincipalName
        kitVersion    = $KitVersion
        benchmark     = 'CIS Microsoft 365 Foundations Benchmark v7.0.0'
        psVersion     = $PSVersionTable.PSVersion.ToString()
        os            = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        workloads     = @()
    }
    errors = [System.Collections.ArrayList]::new()
}

function Add-Evidence {
    param([string] $Key, [scriptblock] $Script, [string] $Control = '')
    Write-Host ("  {0,-46}" -f $Key) -NoNewline
    try {
        $result = & $Script
        if ($null -eq $result) { $evidence[$Key] = @(); Write-Host "empty (collected, nothing configured)" -ForegroundColor DarkYellow }
        else {
            # always store arrays as arrays so the assessment never has to guess
            $evidence[$Key] = @($result)
            Write-Host "ok ($(@($result).Count))" -ForegroundColor Green
        }
    }
    catch {
        $msg = $_.Exception.Message
        $evidence.Remove($Key)
        [void]$evidence.errors.Add([ordered]@{ key = $Key; control = $Control; error = $msg })
        Write-Host "FAILED" -ForegroundColor Red
        Write-Host ("      {0}" -f $msg) -ForegroundColor DarkRed
    }
}
function Require-Module([string]$Name) {
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Installing $Name from PSGallery (current user) ..." -ForegroundColor Cyan
        Install-Module $Name -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
    }
    Import-Module $Name -ErrorAction Stop
}

# ============================================================== Microsoft Graph
if (Want 'Graph') {
    Write-Host "`n=== Microsoft Graph (Entra ID, Intune, admin-centre settings) ===" -ForegroundColor Cyan
    Require-Module Microsoft.Graph.Authentication
    $scopes = @(
        'Directory.Read.All','Policy.Read.All','Policy.Read.ConditionalAccess','RoleManagement.Read.Directory',
        'Application.Read.All','Group.Read.All','User.Read.All','Organization.Read.All','Domain.Read.All',
        'Reports.Read.All','AuditLog.Read.All','UserAuthenticationMethod.Read.All','SecurityEvents.Read.All',
        'SharePointTenantSettings.Read.All','DeviceManagementConfiguration.Read.All',
        'DeviceManagementServiceConfig.Read.All','DeviceManagementManagedDevices.Read.All',
        'AccessReview.Read.All','RoleEligibilitySchedule.Read.Directory','RoleAssignmentSchedule.Read.Directory',
        'RoleManagementPolicy.Read.Directory','OrgSettings-AppsAndServices.Read.All','OrgSettings-Forms.Read.All',
        'OrgSettings-Microsoft365Install.Read.All','ReportSettings.Read.All'
    )
    try { Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop }
    catch {
        Write-Host "Full scope set refused ($($_.Exception.Message)); retrying with a core set." -ForegroundColor Yellow
        [void]$evidence.errors.Add([ordered]@{ key = 'Connect-MgGraph(full)'; error = $_.Exception.Message })
        Connect-MgGraph -Scopes @('Directory.Read.All','Policy.Read.All','Application.Read.All','Group.Read.All','User.Read.All','Reports.Read.All','AuditLog.Read.All') -NoWelcome
    }
    $ctx = Get-MgContext
    $evidence.meta.tenantId      = $ctx.TenantId
    $evidence.meta.grantedScopes = @($ctx.Scopes)
    $evidence.meta.workloads    += 'Graph'
    Write-Host ("Connected to tenant {0} as {1}" -f $ctx.TenantId, $ctx.Account) -ForegroundColor Green

    function Get-Graph {
        param([string] $Uri, [string] $Version = 'v1.0')
        $all = @(); $next = "https://graph.microsoft.com/$Version/$Uri"
        while ($next) {
            $r = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -Headers @{ ConsistencyLevel = 'eventual' }
            if ($null -ne $r.value) { $all += $r.value } else { return $r }
            $next = $r.'@odata.nextLink'
        }
        return $all
    }

    # tenant / licensing
    Add-Evidence 'graph.organization'        { Get-Graph 'organization' } '1.x 5.1.8.1'
    Add-Evidence 'graph.subscribedSkus'      { Get-Graph 'subscribedSkus' } 'licensing (N/A decisions)'
    Add-Evidence 'graph.domains'             { Get-Graph 'domains' } '1.3.1 2.1.x'
    # policies
    Add-Evidence 'graph.authorizationPolicy'          { Get-Graph 'policies/authorizationPolicy' } '5.1.2.x 5.1.3.1 5.1.4.6 5.1.5.1 5.1.6.x 5.2.4.1'
    Add-Evidence 'graph.securityDefaults'             { Get-Graph 'policies/identitySecurityDefaultsEnforcementPolicy' } '5.2.2.x'
    Add-Evidence 'graph.activityBasedTimeoutPolicies' { Get-Graph 'policies/activityBasedTimeoutPolicies' } '1.3.2'
    Add-Evidence 'graph.authenticationMethodsPolicy'  { Get-Graph 'policies/authenticationMethodsPolicy' 'beta' } '5.2.3.x'
    Add-Evidence 'graph.authenticationFlowsPolicy'    { Get-Graph 'policies/authenticationFlowsPolicy' } 'context'
    Add-Evidence 'graph.adminConsentRequestPolicy'    { Get-Graph 'policies/adminConsentRequestPolicy' } '5.1.5.2'
    Add-Evidence 'graph.defaultAppManagementPolicy'   { Get-Graph 'policies/defaultAppManagementPolicy' 'beta' } '5.1.5.3-6'
    Add-Evidence 'graph.appManagementPolicies'        { Get-Graph 'policies/appManagementPolicies' 'beta' } '5.1.5.3-6'
    Add-Evidence 'graph.crossTenantAccessDefault'     { Get-Graph 'policies/crossTenantAccessPolicy/default' } '5.1.6.1'
    Add-Evidence 'graph.crossTenantPartners'          { Get-Graph 'policies/crossTenantAccessPolicy/partners' } '5.1.6.1'
    Add-Evidence 'graph.permissionGrantPolicies'      { Get-Graph 'policies/permissionGrantPolicies' } '5.1.5.1'
    Add-Evidence 'graph.deviceRegistrationPolicy'     { Get-Graph 'policies/deviceRegistrationPolicy' 'beta' } '5.1.4.1-5'
    Add-Evidence 'graph.b2bManagementPolicy'          { Get-Graph 'legacy/policies' 'beta' } '5.1.6.1'
    # conditional access
    Add-Evidence 'graph.conditionalAccessPolicies'    { Get-Graph 'identity/conditionalAccess/policies' } '5.2.2.1-17'
    Add-Evidence 'graph.namedLocations'               { Get-Graph 'identity/conditionalAccess/namedLocations' } '5.2.2.14-15'
    Add-Evidence 'graph.authenticationStrengthPolicies' { Get-Graph 'identity/conditionalAccess/authenticationStrength/policies' } '5.2.2.5'
    # directory settings
    Add-Evidence 'graph.groupSettings'                { Get-Graph 'groupSettings' } '5.1.3.4 5.2.3.2-3 5.2.3.8-9'
    Add-Evidence 'graph.groupSettingTemplates'        { Get-Graph 'groupSettingTemplates' } 'context'
    # roles
    Add-Evidence 'graph.directoryRoles' {
        $roles = Get-Graph 'directoryRoles'
        foreach ($r in $roles) {
            $members = Get-Graph "directoryRoles/$($r.id)/members"
            $r | Add-Member -NotePropertyName membersResolved -NotePropertyValue @($members | Select-Object id, '@odata.type', displayName, userPrincipalName, accountEnabled) -Force
        }
        $roles
    } '1.1.1-4 5.3.1'
    Add-Evidence 'graph.roleEligibilitySchedules'     { Get-Graph 'roleManagement/directory/roleEligibilitySchedules' } '1.1.3 5.3.1'
    Add-Evidence 'graph.roleAssignmentSchedules'      { Get-Graph 'roleManagement/directory/roleAssignmentSchedules' } '5.3.1'
    Add-Evidence 'graph.roleManagementPolicyAssignments' { Get-Graph "policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=policy(`$expand=rules)" } '5.3.4-5'
    Add-Evidence 'graph.accessReviewDefinitions'      { Get-Graph 'identityGovernance/accessReviews/definitions' } '5.3.2-3'
    # users / groups / apps
    Add-Evidence 'graph.users' { Get-Graph "users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,assignedLicenses,createdDateTime,signInActivity&`$top=999" } '1.1.x 1.2.2 5.1.2.1'
    Add-Evidence 'graph.groups' { Get-Graph "groups?`$select=id,displayName,visibility,groupTypes,securityEnabled,mailEnabled,membershipRule,createdDateTime&`$top=999" } '1.2.1'
    Add-Evidence 'graph.applications' { Get-Graph "applications?`$select=id,appId,displayName,signInAudience,passwordCredentials,keyCredentials,createdDateTime&`$top=999" } '5.1.5.x'
    Add-Evidence 'graph.servicePrincipals' { Get-Graph "servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,tags&`$top=999" } '1.3.7 5.1.5.x'
    Add-Evidence 'graph.mfaRegistrationDetails' { Get-Graph "reports/authenticationMethods/userRegistrationDetails?`$top=999" } '5.2.3.4'
    # legacy per-user MFA state (one call per enabled member, capped)
    Add-Evidence 'graph.perUserMfaStates' {
        $users = @($evidence['graph.users'] | Where-Object { $_.accountEnabled -and $_.userType -eq 'Member' } | Select-Object -First $PerUserMfaCap)
        $out = @(); $i = 0
        foreach ($u in $users) {
            $i++; if ($i % 50 -eq 0) { Write-Host "." -NoNewline }
            try { $req = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$($u.id)/authentication/requirements" -OutputType PSObject
                  $out += [pscustomobject]@{ userPrincipalName = $u.userPrincipalName; perUserMfaState = $req.perUserMfaState } }
            catch { $out += [pscustomobject]@{ userPrincipalName = $u.userPrincipalName; perUserMfaState = "error: $($_.Exception.Message)" } }
        }
        if ($users.Count -eq $PerUserMfaCap) { Write-Host " (capped at $PerUserMfaCap users)" -NoNewline -ForegroundColor DarkYellow }
        $out
    } '5.1.2.1'
    # reports / score
    Add-Evidence 'graph.secureScores'                 { Get-Graph 'security/secureScores?$top=1' } 'context'
    Add-Evidence 'graph.secureScoreControlProfiles'   { Get-Graph 'security/secureScoreControlProfiles' } 'Appendix D'
    # SharePoint tenant settings via Graph (fallback if SharePoint module unavailable)
    Add-Evidence 'graph.sharePointSettings'           { Get-Graph 'admin/sharepoint/settings' } '7.2.x'
    # admin-centre org settings
    Add-Evidence 'graph.appsAndServicesSettings'      { Get-Graph 'admin/appsAndServices/settings' 'beta' } '1.3.4'
    Add-Evidence 'graph.formsSettings'                { Get-Graph 'admin/forms/settings' 'beta' } '1.3.5'
    Add-Evidence 'graph.swaySettings'                 { Get-Graph 'admin/sway/settings' 'beta' } '1.3.8'
    # Intune
    Add-Evidence 'graph.deviceManagementSettings'     { Get-Graph 'deviceManagement?$select=settings' 'beta' } '4.1'
    Add-Evidence 'graph.deviceCompliancePolicies'     { Get-Graph 'deviceManagement/deviceCompliancePolicies' } '4.1'
    Add-Evidence 'graph.deviceEnrollmentConfigurations' { Get-Graph 'deviceManagement/deviceEnrollmentConfigurations' 'beta' } '4.2'
    Add-Evidence 'graph.managedDevicesSummary'        { Get-Graph 'deviceManagement/managedDeviceOverview' } 'context'
    Add-Evidence 'graph.devices'                      { Get-Graph "devices?`$select=id,displayName,operatingSystem,trustType,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime&`$top=999" } 'context'
}

# ============================================================== Exchange Online
if (Want 'Exchange') {
    Write-Host "`n=== Exchange Online / Defender for Office 365 ===" -ForegroundColor Cyan
    Require-Module ExchangeOnlineManagement
    try {
        Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ErrorAction Stop
        $evidence.meta.workloads += 'Exchange'
        Add-Evidence 'exo.organizationConfig'      { Get-OrganizationConfig } '1.3.3 1.3.6 1.3.9 6.1.1 6.5.x'
        Add-Evidence 'exo.adminAuditLogConfig'     { Get-AdminAuditLogConfig } '3.1.1'
        Add-Evidence 'exo.transportConfig'         { Get-TransportConfig } '6.5.4'
        Add-Evidence 'exo.acceptedDomains'         { Get-AcceptedDomain } '2.1.8-10'
        Add-Evidence 'exo.antiPhishPolicy'         { Get-AntiPhishPolicy } '2.1.7 2.4.1'
        Add-Evidence 'exo.antiPhishRule'           { Get-AntiPhishRule } '2.1.7'
        Add-Evidence 'exo.safeLinksPolicy'         { Get-SafeLinksPolicy } '2.1.1'
        Add-Evidence 'exo.safeLinksRule'           { Get-SafeLinksRule } '2.1.1'
        Add-Evidence 'exo.safeAttachmentPolicy'    { Get-SafeAttachmentPolicy } '2.1.4'
        Add-Evidence 'exo.safeAttachmentRule'      { Get-SafeAttachmentRule } '2.1.4'
        Add-Evidence 'exo.atpPolicyForO365'        { Get-AtpPolicyForO365 } '2.1.5'
        Add-Evidence 'exo.hostedContentFilter'     { Get-HostedContentFilterPolicy } '2.1.14'
        Add-Evidence 'exo.hostedOutboundSpam'      { Get-HostedOutboundSpamFilterPolicy } '2.1.6 2.1.15 6.2.1'
        Add-Evidence 'exo.hostedConnectionFilter'  { Get-HostedConnectionFilterPolicy } '2.1.12-13'
        Add-Evidence 'exo.malwareFilterPolicy'     { Get-MalwareFilterPolicy } '2.1.2 2.1.3 2.1.11'
        Add-Evidence 'exo.eopProtectionPolicyRule' { Get-EOPProtectionPolicyRule } '2.4.2'
        Add-Evidence 'exo.atpProtectionPolicyRule' { Get-ATPProtectionPolicyRule } '2.4.2'
        Add-Evidence 'exo.teamsProtectionPolicy'   { Get-TeamsProtectionPolicy } '2.4.4'
        Add-Evidence 'exo.reportSubmissionPolicy'  { Get-ReportSubmissionPolicy } '8.6.1'
        Add-Evidence 'exo.userTags'                { Get-UserTag -ErrorAction SilentlyContinue } '2.4.1'
        Add-Evidence 'exo.transportRules' {
            Get-TransportRule | Select-Object Name, State, Mode, Priority, Description, RedirectMessageTo, BlindCopyTo, CopyTo,
                SetSCL, SenderDomainIs, FromAddressContainsWords, SubjectContainsWords, DeleteMessage, Quarantine
        } '6.2.1-2'
        Add-Evidence 'exo.dkimSigningConfig'       { Get-DkimSigningConfig } '2.1.9'
        Add-Evidence 'exo.owaMailboxPolicy'        { Get-OwaMailboxPolicy } '6.3.2 6.5.3'
        Add-Evidence 'exo.sharingPolicy'           { Get-SharingPolicy } '1.3.3'
        Add-Evidence 'exo.remoteDomain'            { Get-RemoteDomain } '6.2.1'
        Add-Evidence 'exo.externalInOutlook'       { Get-ExternalInOutlook } '6.2.3'
        Add-Evidence 'exo.roleAssignmentPolicy'    { Get-RoleAssignmentPolicy } '6.3.1'
        Add-Evidence 'exo.roleGroups'              { Get-RoleGroup | Select-Object Name, Description, Members } 'context'
        Add-Evidence 'exo.mailboxes' {
            Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName, UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails,
                AuditEnabled, AuditLogAgeLimit, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
        } '1.2.2 6.1.2 6.2.1'
        Add-Evidence 'exo.mailboxAuditBypass'      { Get-MailboxAuditBypassAssociation -ResultSize Unlimited | Select-Object Identity, AuditBypassEnabled } '6.1.3'
        Add-Evidence 'exo.quarantinePolicy'        { Get-QuarantinePolicy } 'context'
    }
    catch {
        Write-Host "Exchange Online sign-in failed: $($_.Exception.Message)" -ForegroundColor Red
        [void]$evidence.errors.Add([ordered]@{ key = 'Connect-ExchangeOnline'; error = $_.Exception.Message })
    }
}

# ============================================================== Purview
if (Want 'Purview') {
    Write-Host "`n=== Microsoft Purview (Security & Compliance PowerShell) ===" -ForegroundColor Cyan
    Require-Module ExchangeOnlineManagement
    try {
        Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ErrorAction Stop
        $evidence.meta.workloads += 'Purview'
        Add-Evidence 'scc.dlpCompliancePolicy' { Get-DlpCompliancePolicy | Select-Object Name, Mode, Enabled, Workload, ExchangeLocation, SharePointLocation, OneDriveLocation, TeamsLocation, EndpointDlpLocation } '3.2.1-3'
        Add-Evidence 'scc.dlpComplianceRule'   { Get-DlpComplianceRule | Select-Object Name, Policy, Disabled, BlockAccess } '3.2.2'
        Add-Evidence 'scc.sensitivityLabels'   { Get-Label | Select-Object Name, DisplayName, Disabled, ContentType, Priority } '3.3.1'
        Add-Evidence 'scc.labelPolicies'       { Get-LabelPolicy | Select-Object Name, Enabled, Labels, ExchangeLocation, SharePointLocation } '3.3.1'
        Add-Evidence 'scc.protectionAlerts'    { Get-ProtectionAlert | Select-Object Name, Category, Severity, Disabled, NotifyUser, ThreatType, Filter } '2.2.1'
        Add-Evidence 'scc.retentionCompliancePolicy' { Get-RetentionCompliancePolicy | Select-Object Name, Enabled, Mode, Workload } 'context'
        Add-Evidence 'scc.auditConfig'         { Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled } '3.1.1'
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Purview sign-in failed: $($_.Exception.Message)" -ForegroundColor Red
        [void]$evidence.errors.Add([ordered]@{ key = 'Connect-IPPSSession'; error = $_.Exception.Message })
    }
}

# ============================================================== Teams
if (Want 'Teams') {
    Write-Host "`n=== Microsoft Teams ===" -ForegroundColor Cyan
    Require-Module MicrosoftTeams
    try {
        Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
        $evidence.meta.workloads += 'Teams'
        Add-Evidence 'teams.federationConfiguration' { Get-CsTenantFederationConfiguration } '8.2.1-4'
        Add-Evidence 'teams.clientConfiguration'     { Get-CsTeamsClientConfiguration } '8.1.1-2'
        Add-Evidence 'teams.meetingPolicy'           { Get-CsTeamsMeetingPolicy } '8.5.1-9'
        Add-Evidence 'teams.meetingConfiguration'    { Get-CsTeamsMeetingConfiguration } 'context'
        Add-Evidence 'teams.messagingPolicy'         { Get-CsTeamsMessagingPolicy } '8.6.1'
        Add-Evidence 'teams.appPermissionPolicy'     { Get-CsTeamsAppPermissionPolicy } '8.4.1'
        Add-Evidence 'teams.appSetupPolicy'          { Get-CsTeamsAppSetupPolicy } 'context'
        Add-Evidence 'teams.guestMeetingConfiguration' { Get-CsTeamsGuestMeetingConfiguration } 'context'
        Add-Evidence 'teams.guestMessagingConfiguration' { Get-CsTeamsGuestMessagingConfiguration } 'context'
    }
    catch {
        Write-Host "Teams sign-in failed: $($_.Exception.Message)" -ForegroundColor Red
        [void]$evidence.errors.Add([ordered]@{ key = 'Connect-MicrosoftTeams'; error = $_.Exception.Message })
    }
}

# ============================================================== SharePoint Online
if (Want 'SharePoint') {
    Write-Host "`n=== SharePoint Online ===" -ForegroundColor Cyan
    try {
        if (-not (Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell)) { Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force -AllowClobber -Repository PSGallery }
        try { Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop }
        catch { Write-Host "Loading the SharePoint module through Windows PowerShell compatibility ..." -ForegroundColor DarkGray; Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell -ErrorAction Stop }
        # derive the admin URL from the tenant's .onmicrosoft.com domain
        $onms = $null
        if ($evidence['graph.domains']) { $onms = ($evidence['graph.domains'] | Where-Object { $_.id -like '*.onmicrosoft.com' -and $_.id -notlike '*.mail.onmicrosoft.com' } | Select-Object -First 1).id }
        if (-not $onms -and $evidence['exo.acceptedDomains']) { $onms = ($evidence['exo.acceptedDomains'] | Where-Object { $_.DomainName -like '*.onmicrosoft.com' -and $_.DomainName -notlike '*.mail.onmicrosoft.com' } | Select-Object -First 1).DomainName }
        if (-not $onms) { $onms = Read-Host "Enter the tenant's .onmicrosoft.com domain (e.g. contoso.onmicrosoft.com)" }
        $adminUrl = "https://$($onms -replace '\.onmicrosoft\.com$','')-admin.sharepoint.com"
        Write-Host "Connecting to $adminUrl" -ForegroundColor DarkGray
        Connect-SPOService -Url $adminUrl -ErrorAction Stop
        $evidence.meta.workloads += 'SharePoint'
        Add-Evidence 'spo.tenant' { Get-SPOTenant } '7.2.1-11 7.3.1'
        Add-Evidence 'spo.tenantSyncClientRestriction' { Get-SPOTenantSyncClientRestriction } 'context'
        Disconnect-SPOService -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "SharePoint Online failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  (The Graph admin/sharepoint/settings dataset covers most of section 7; 7.2.2, 7.2.8, 7.2.10 and 7.3.1 need this module.)" -ForegroundColor DarkYellow
        [void]$evidence.errors.Add([ordered]@{ key = 'Connect-SPOService'; error = $_.Exception.Message })
    }
}

# ============================================================== Fabric / Power BI
if (Want 'Fabric') {
    Write-Host "`n=== Microsoft Fabric / Power BI tenant settings ===" -ForegroundColor Cyan
    try {
        Require-Module MicrosoftPowerBIMgmt
        Connect-PowerBIServiceAccount -ErrorAction Stop | Out-Null
        $evidence.meta.workloads += 'Fabric'
        Add-Evidence 'fabric.tenantSettings' {
            $r = Invoke-PowerBIRestMethod -Url 'admin/tenantsettings' -Method Get -ErrorAction Stop | ConvertFrom-Json
            $r.tenantSettings
        } '9.1.1-12'
        Disconnect-PowerBIServiceAccount -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Fabric failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  If the tenant has no Power BI / Fabric licence this is expected - section 9 is scored N/A." -ForegroundColor DarkYellow
        [void]$evidence.errors.Add([ordered]@{ key = 'Fabric'; error = $_.Exception.Message })
    }
}

# ============================================================== Public DNS (SPF / DKIM / DMARC)
if (Want 'DNS') {
    Write-Host "`n=== Public DNS: SPF, DKIM, DMARC, MX ===" -ForegroundColor Cyan
    $domains = @()
    if ($evidence['exo.acceptedDomains']) { $domains = @($evidence['exo.acceptedDomains'] | Where-Object { $_.DomainName -notlike '*.onmicrosoft.com' } | Select-Object -ExpandProperty DomainName) }
    elseif ($evidence['graph.domains']) { $domains = @($evidence['graph.domains'] | Where-Object { $_.isVerified -and $_.id -notlike '*.onmicrosoft.com' } | Select-Object -ExpandProperty id) }
    if ($domains.Count -eq 0) { $domains = @((Read-Host "No accepted domains collected. Enter mail domains to check, comma-separated") -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    function Get-Txt([string]$name) {
        try { if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) { return @((Resolve-DnsName -Name $name -Type TXT -ErrorAction Stop | Where-Object { $_.Strings }) | ForEach-Object { ($_.Strings -join '') }) }
              else { $o = & nslookup -type=TXT $name 2>$null; return @(($o | Select-String '"' ) | ForEach-Object { ($_ -replace '^.*?"','' -replace '"\s*$','' -replace '"\s+"','') }) } }
        catch { return @() }
    }
    function Get-Mx([string]$name) {
        try { if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) { return @((Resolve-DnsName -Name $name -Type MX -ErrorAction Stop | Where-Object { $_.NameExchange }).NameExchange) }
              else { $o = & nslookup -type=MX $name 2>$null; return @(($o | Select-String 'mail exchanger') | ForEach-Object { ($_ -replace '^.*=\s*','').Trim() }) } }
        catch { return @() }
    }
    function Get-Cname([string]$name) {
        try { if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) { return ((Resolve-DnsName -Name $name -Type CNAME -ErrorAction Stop | Where-Object { $_.NameHost } | Select-Object -First 1).NameHost) }
              else { $o = & nslookup -type=CNAME $name 2>$null; return (($o | Select-String 'canonical name') | ForEach-Object { ($_ -replace '^.*=\s*','').Trim() } | Select-Object -First 1) } }
        catch { return $null }
    }
    Add-Evidence 'dns.records' {
        $out = @()
        foreach ($d in $domains) {
            Write-Host "." -NoNewline
            $mx = Get-Mx $d
            $spf = (Get-Txt $d | Where-Object { $_ -match '^v=spf1' } | Select-Object -First 1)
            $dmarc = (Get-Txt "_dmarc.$d" | Where-Object { $_ -match '^v=DMARC1' } | Select-Object -First 1)
            $out += [pscustomobject]@{
                Domain = $d; MailRouting = ($mx.Count -gt 0); MX = ($mx -join ', ')
                SPF = $spf; DMARC = $dmarc
                DKIM1 = Get-Cname "selector1._domainkey.$d"; DKIM2 = Get-Cname "selector2._domainkey.$d"
                CheckedUtc = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
        $out
    } '2.1.8-10'
}

# ============================================================== write out
if (-not $ClientName) {
    $ClientName = if ($evidence['graph.organization']) { (($evidence['graph.organization'][0].verifiedDomains | Where-Object { $_.isDefault }).name -replace '[^A-Za-z0-9-]','') } else { 'tenant' }
    if (-not $ClientName) { $ClientName = 'tenant' }
}
$evidence.meta.clientName = $ClientName
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$stamp = (Get-Date).ToString('yyyyMMdd-HHmm')
$suffix = if ($Only.Count -gt 0) { '-' + ($Only -join '') } else { '' }
$file = Join-Path $OutputPath "$ClientName-M365-CIS-evidence-$stamp$suffix.json"
$evidence | ConvertTo-Json -Depth 15 -Compress:$false | Out-File -FilePath $file -Encoding utf8

Write-Host "`n------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Evidence written to: $file" -ForegroundColor Green
$collected = ($evidence.Keys | Where-Object { $_ -notin 'meta','errors' -and $null -ne $evidence[$_] }).Count
$failed = $evidence.errors.Count
Write-Host ("Collected: {0} datasets   Failed: {1}" -f $collected, $failed) -ForegroundColor $(if ($failed) { 'Yellow' } else { 'Green' })
if ($failed) {
    Write-Host "`nFailures (these controls will be scored 'Not assessed' unless you re-run that workload):" -ForegroundColor Yellow
    $evidence.errors | ForEach-Object { Write-Host ("  - {0}: {1}" -f $_.key, $_.error) -ForegroundColor DarkYellow }
}
Write-Host "`nNext: .\Invoke-M365CISAssessment.ps1 -EvidencePath '$OutputPath' -ClientName '$ClientName'" -ForegroundColor Cyan
Write-Host "The evidence file contains account names and configuration detail - treat it as Confidential and share only via restricted SharePoint links." -ForegroundColor DarkYellow

Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue | Out-Null
