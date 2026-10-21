#!/usr/bin/env python3
"""
Builds the control catalogue for the M365 CIS v7 Review Kit.

Inputs : cis7.json  (CIS Microsoft 365 Foundations Benchmark v7.0.0 control definitions,
                     machine-readable, sourced from Prowler's open-source compliance data)
Outputs: controls/cis-m365-v7-controls.json   - engine input (tests, evidence keys, references)
         reference/CIS-M365-v7-Control-Catalogue.xlsx - human reference (all 160 controls)

Each control carries:
  short      short title used in registers and reports
  keys       evidence keys the test reads (collector output)
  test       PowerShell scriptblock text evaluated by Invoke-M365CISAssessment.ps1
             (None = manual / portal-only control)
  portal     where to read it by hand (from CIS audit procedure)
  ce         UK Cyber Essentials control area
  ncsc       NCSC guidance reference (title | url)
"""
import json, re, os

SRC = json.load(open("cis7.json"))["Requirements"]

# ---------------------------------------------------------------------------
# NCSC / Cyber Essentials references (used by the ncsc= field)
# ---------------------------------------------------------------------------
NCSC = {
    "mfa":    ("NCSC: Multi-factor authentication for online services", "https://www.ncsc.gov.uk/guidance/multi-factor-authentication-online-services"),
    "pwd":    ("NCSC: Password administration for system owners", "https://www.ncsc.gov.uk/collection/passwords"),
    "email":  ("NCSC: Email security and anti-spoofing", "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing"),
    "phish":  ("NCSC: Phishing attacks - defending your organisation", "https://www.ncsc.gov.uk/guidance/phishing"),
    "device": ("NCSC: Device Security Guidance", "https://www.ncsc.gov.uk/collection/device-security-guidance"),
    "log":    ("NCSC: Introduction to logging for security purposes", "https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes"),
    "admin":  ("NCSC: Secure system administration", "https://www.ncsc.gov.uk/collection/secure-system-administration"),
    "cloud":  ("NCSC: Cloud security principles", "https://www.ncsc.gov.uk/collection/cloud/the-cloud-security-principles"),
    "zt":     ("NCSC: Zero trust architecture design principles", "https://www.ncsc.gov.uk/collection/zero-trust-architecture"),
    "saas":   ("NCSC: Using SaaS securely", "https://www.ncsc.gov.uk/collection/saas-security"),
    "data":   ("NCSC: Protecting bulk personal data", "https://www.ncsc.gov.uk/collection/protecting-bulk-personal-data"),
    "ce":     ("NCSC: Cyber Essentials requirements for IT infrastructure", "https://www.ncsc.gov.uk/cyberessentials/overview"),
}
CE_AREAS = {
    "UAC": "User access control",
    "SC":  "Secure configuration",
    "MP":  "Malware protection",
    "FW":  "Firewalls and internet gateways",
    "SUM": "Security update management",
    "-":   "Not directly mapped (good practice beyond Cyber Essentials)",
}

# Short titles (register / report wording, UK English)
SHORT = {
"1.1.1":"Administrative accounts are cloud-only","1.1.2":"Two emergency-access (break-glass) accounts configured",
"1.1.3":"Between two and four Global Administrators","1.1.4":"Administrative accounts hold no application licences",
"1.2.1":"Only organisationally managed/approved public groups exist","1.2.2":"Sign-in blocked for shared mailboxes",
"1.3.1":"Password expiration policy set to never expire","1.3.2":"Idle session timeout <= 3 hours for M365 web apps",
"1.3.3":"External calendar sharing disabled","1.3.4":"Users cannot install Office Store add-ins / start trials",
"1.3.5":"Forms internal phishing protection enabled","1.3.6":"Customer Lockbox enabled",
"1.3.7":"Third-party storage disabled in Microsoft 365 on the web","1.3.8":"Sway external sharing disabled",
"1.3.9":"Shared Bookings disabled (or restricted)",
"2.1.1":"Safe Links policy enabled for Office applications","2.1.2":"Common Attachment Types Filter is enabled",
"2.1.3":"Notifications for internally sent malware are enabled","2.1.4":"Safe Attachments policy is enabled",
"2.1.5":"Safe Attachments for SharePoint, OneDrive and Teams is enabled","2.1.6":"Outbound spam policy notifies administrators",
"2.1.7":"Anti-phishing policy is configured","2.1.8":"SPF records are published for all Exchange domains",
"2.1.9":"DKIM is enabled for all Exchange domains","2.1.10":"DMARC records are published for all Exchange domains",
"2.1.11":"Comprehensive attachment filtering is applied","2.1.12":"Connection filter IP allow list is not used",
"2.1.13":"Connection filter safe list is off","2.1.14":"Inbound anti-spam policies have no allowed domains",
"2.1.15":"Outbound spam filter policy limits are configured","2.2.1":"Emergency-access account activity is monitored and alerted",
"2.4.1":"Priority accounts are identified and tagged","2.4.2":"Preset security policies are assigned",
"2.4.3":"Microsoft Defender for Cloud Apps is enabled","2.4.4":"Zero-hour auto purge (ZAP) is enabled for Teams",
"2.4.5":"Automated Investigation and Response (AIR) is configured",
"3.1.1":"Unified audit log search is enabled","3.2.1":"DLP policies are enabled for Exchange and SharePoint",
"3.2.2":"The default Teams DLP policy rule is enabled","3.2.3":"DLP policies are scoped to Microsoft 365 Copilot",
"3.3.1":"Sensitivity labels are published and applied",
"4.1":"Devices without a compliance policy are marked non-compliant","4.2":"Personally owned device enrolment blocked by default",
"5.1.2.1":"Per-user (legacy) MFA is disabled","5.1.2.2":"Users cannot register applications","5.1.2.3":"Users cannot create tenants",
"5.1.2.4":"Access to the Entra admin centre restricted for non-admins","5.1.2.5":"'Stay signed in?' prompt hidden",
"5.1.2.6":"LinkedIn account connections disabled","5.1.3.1":"Users cannot create security groups",
"5.1.3.2":"User access to My Groups features restricted","5.1.3.3":"Owners manage membership requests in My Groups",
"5.1.3.4":"Users cannot create Microsoft 365 groups","5.1.4.1":"Joining devices to Entra ID restricted to selected users",
"5.1.4.2":"Maximum devices per user <= 50","5.1.4.3":"Global Administrator not added as local admin on Entra-joined devices",
"5.1.4.4":"Registering user not added as local admin","5.1.4.5":"Windows LAPS enabled",
"5.1.4.6":"Users cannot self-service recover BitLocker keys","5.1.5.1":"User consent to applications is not allowed",
"5.1.5.2":"Admin consent request workflow enabled","5.1.5.3":"Password (secret) addition is blocked for applications",
"5.1.5.4":"Application password lifetime <= 180 days","5.1.5.5":"New application passwords are system-generated",
"5.1.5.6":"Application certificate lifetime <= 180 days","5.1.6.1":"Guest invitations restricted to specified domains",
"5.1.6.2":"Guest user access is restricted","5.1.6.3":"Guest invitation restricted to admins and guest inviters",
"5.1.8.1":"Password hash sync enabled (hybrid)",
"5.2.2.1":"MFA enforced for administrative roles","5.2.2.2":"MFA enforced for all users","5.2.2.3":"Legacy authentication blocked",
"5.2.2.4":"Sign-in frequency and non-persistent browser sessions for admins","5.2.2.5":"Phishing-resistant MFA required for administrators",
"5.2.2.6":"User-risk policy: high risk -> MFA + password change","5.2.2.7":"Sign-in-risk policy: medium/high -> MFA",
"5.2.2.8":"Sign-in-risk policy blocks medium/high risk","5.2.2.9":"Managed (compliant) devices required for all users",
"5.2.2.10":"Managed device required to register security information","5.2.2.11":"Sign-in frequency 'every time' for Intune enrolment",
"5.2.2.12":"Device code flow blocked","5.2.2.13":"Periodic re-authentication <= 7 days for all users",
"5.2.2.14":"Trusted IP named locations defined","5.2.2.15":"Exclusionary geographic access controls enforced",
"5.2.2.16":"Token Protection enforced for sign-in sessions","5.2.2.17":"Authentication transfer blocked",
"5.2.3.1":"Microsoft Authenticator context (app name, location) shown","5.2.3.2":"Custom banned password list configured",
"5.2.3.3":"Password protection enforced for on-premises AD","5.2.3.4":"All member users are MFA capable",
"5.2.3.5":"Weak authentication methods (SMS, Voice) disabled","5.2.3.6":"System-preferred MFA enabled",
"5.2.3.7":"Email OTP authentication method disabled","5.2.3.8":"Smart lockout threshold <= 10",
"5.2.3.9":"Smart lockout duration >= 60 seconds","5.2.3.10":"Microsoft Authenticator on companion apps (Authenticator Lite) disabled",
"5.2.4.1":"Self-service password reset enabled","5.2.4.2":"Two methods required for password reset",
"5.2.4.3":"SSPR registration and re-confirmation required","5.2.4.4":"Users notified on password resets",
"5.2.4.5":"All admins notified when other admins reset passwords",
"5.3.1":"PIM used to manage privileged roles (no standing active assignments)","5.3.2":"Access reviews for guest users configured",
"5.3.3":"Access reviews for privileged roles configured","5.3.4":"Approval required to activate Global Administrator",
"5.3.5":"Approval required to activate Privileged Role Administrator",
"6.1.1":"Mailbox auditing is on by default for the organisation","6.1.2":"Mailbox auditing is enabled for all user mailboxes",
"6.1.3":"No mailbox has audit bypass enabled","6.2.1":"Automatic external email forwarding is blocked",
"6.2.2":"Mail transport rules do not whitelist specific domains","6.2.3":"External sender callouts are enabled in Outlook",
"6.3.1":"Users cannot install Outlook add-ins","6.3.2":"Personal account integration in Outlook on the web is disabled",
"6.5.1":"Modern authentication for Exchange Online is enabled","6.5.2":"MailTips are enabled for end users",
"6.5.3":"Additional storage providers are restricted in Outlook on the web","6.5.4":"SMTP AUTH is disabled","6.5.5":"Direct Send is disabled",
"7.2.1":"Modern authentication required for SharePoint apps","7.2.2":"SharePoint and OneDrive integrated with Entra B2B",
"7.2.3":"External content sharing restricted","7.2.4":"OneDrive content sharing restricted",
"7.2.5":"SharePoint guest users cannot share items they don't own","7.2.6":"External sharing restricted by domain (allow/block list)",
"7.2.7":"Link sharing restricted (default link = specific people)","7.2.8":"External sharing restricted to specific security groups",
"7.2.9":"Guest access to a site or OneDrive expires automatically","7.2.10":"Re-authentication with verification code restricted",
"7.2.11":"Default sharing link permission is View","7.3.1":"Infected file download blocked (Defender for Office 365)",
"8.1.1":"External file sharing in Teams restricted to approved providers","8.1.2":"Email into Teams channels is disabled",
"8.2.1":"External domains are restricted to an approved list","8.2.2":"Communication with unmanaged Teams users is disabled",
"8.2.3":"Unmanaged users cannot initiate contact","8.2.4":"External access with Teams trial tenants is blocked",
"8.4.1":"App permission policies restrict available apps","8.5.1":"Anonymous users cannot join a meeting",
"8.5.2":"Anonymous users cannot start a meeting","8.5.3":"Only people in the organisation can bypass the lobby",
"8.5.4":"Dial-in users cannot bypass the lobby","8.5.5":"Meeting chat is restricted for anonymous participants",
"8.5.6":"Only organisers and co-organisers can present","8.5.7":"External participants cannot request control",
"8.5.8":"External meeting chat with untrusted organisations is off","8.5.9":"Meeting recording is turned off",
"8.6.1":"Users can report malicious messages in Teams",
"9.1.1":"Guest user access to Fabric restricted","9.1.2":"External user invitations restricted (Fabric)",
"9.1.3":"Guest access to browse Fabric content restricted","9.1.4":"'Publish to web' restricted",
"9.1.5":"R and Python visuals disabled","9.1.6":"Sensitivity labels enabled in Fabric","9.1.7":"Shareable links restricted to people in the organisation",
"9.1.8":"External dataset sharing restricted","9.1.9":"ResourceKey authentication blocked",
"9.1.10":"Service principals restricted from calling Fabric public APIs","9.1.11":"Service principal profiles restricted",
"9.1.12":"Service principal access to admin APIs restricted",
}

# ---------------------------------------------------------------------------
# Test rules.  PowerShell, evaluated with these helpers in scope:
#   Ev 'key'      -> array of objects for an evidence key (empty array if missing)
#   Has 'key'     -> $true if the key was collected (non-null)
#   One 'key'     -> first object
#   Pass/Fail/Partial/NA/Review/Manual 'text'  -> result
#   $Ctx          -> licence/tenant context (HasP1, HasP2, HasMDO1, HasMDO2, HasIntune,
#                    HasMDCA, HasLockbox, HasE5Compliance, HasFabric, Hybrid, BreakGlass[],
#                    AdminUpns[], GAUpns[], Users (graph.users))
#   CA helpers    -> Get-CA (enabled), CA-AllUsers $p, CA-AdminRoles $p, CA-AllApps $p,
#                    CA-Grant $p 'mfa'|'block'|'compliantDevice'..., CA-Names $list
#   Pct a b       -> percentage string
# ---------------------------------------------------------------------------
R = {}
def rule(id, keys, test, ce="-", ncsc="cloud", portal=None):
    R[id] = dict(keys=keys, test=test, ce=ce, ncsc=ncsc, portal=portal)

# ---- 1  Microsoft 365 admin center -----------------------------------------
rule("1.1.1", ["graph.directoryRoles","graph.users"], r'''
$admins = Get-AdminUsers
if (-not $admins) { return Review "No directory role members were returned - check Graph permissions." }
$synced = @($admins | Where-Object { $_.onPremisesSyncEnabled -eq $true })
if ($synced.Count -eq 0) { Pass "All $($admins.Count) role-holding accounts are cloud-only (onPremisesSyncEnabled is not true for any)." }
else { Fail "$($synced.Count) of $($admins.Count) role-holding accounts are synchronised from on-premises AD: $(($synced.userPrincipalName | Select -First 10) -join ', ')" }
''', "UAC", "admin")

rule("1.1.2", ["graph.directoryRoles","graph.users"], r'''
$ga = Get-GAUsers
$bg = @($ga | Where-Object { $_.userPrincipalName -like '*.onmicrosoft.com' -and -not $_.assignedLicenses })
$named = @($Ctx.BreakGlass)
if ($named.Count -ge 2) { return Review "Break-glass accounts supplied: $($named -join ', '). Confirm both are cloud-only, unlicensed, excluded from Conditional Access and monitored (see 2.2.1)." }
if ($bg.Count -ge 2) { Review "$($bg.Count) unlicensed .onmicrosoft.com Global Administrators look like break-glass accounts: $($bg.userPrincipalName -join ', '). Confirm with the customer and re-run with -BreakGlassAccounts." }
elseif ($bg.Count -eq 1) { Partial "Only one candidate break-glass account found ($($bg[0].userPrincipalName)). CIS requires two." }
else { Fail "No account is identifiable as emergency access (no unlicensed .onmicrosoft.com Global Administrator). $($ga.Count) Global Administrators in total." }
''', "UAC", "admin", "Entra admin centre > Roles & admins > Global Administrator > Assignments")

rule("1.1.3", ["graph.directoryRoles","graph.roleEligibilitySchedules"], r'''
$ga = Get-GAUsers
$n = $ga.Count
$list = ($ga.userPrincipalName | Select -First 8) -join ', '
if ($n -ge 2 -and $n -le 4) { Pass "$n Global Administrators (active + PIM-eligible): $list" }
elseif ($n -lt 2) { Fail "$n Global Administrator - fewer than the two CIS requires for resilience: $list" }
else { Fail "$n Global Administrators (active + PIM-eligible), above the CIS maximum of four: $list" }
''', "UAC", "admin")

rule("1.1.4", ["graph.directoryRoles","graph.users"], r'''
$admins = Get-AdminUsers
$lic = @($admins | Where-Object { $_.assignedLicenses -and $_.userPrincipalName -notin $Ctx.BreakGlass })
if (-not $admins) { return Review "No role members returned." }
if ($lic.Count -eq 0) { Pass "None of the $($admins.Count) role-holding accounts carries an application licence." }
else { Fail "$($lic.Count) of $($admins.Count) role-holding accounts are licensed daily-use accounts: $(($lic.userPrincipalName | Select -First 10) -join ', '). CIS expects dedicated, unlicensed admin accounts (Entra ID P1/P2 only where needed)." }
''', "UAC", "admin")

rule("1.2.1", ["graph.groups"], r'''
$g = Ev 'graph.groups'
$pub = @($g | Where-Object { $_.groupTypes -contains 'Unified' -and $_.visibility -eq 'Public' })
if ($pub.Count -eq 0) { Pass "$($g.Count) groups; no Microsoft 365 group has visibility = Public." }
else { Review "$($pub.Count) of $($g.Count) groups are Public Microsoft 365 groups: $(($pub.displayName | Select -First 10) -join ', '). Confirm each is approved and organisationally managed." }
''', "UAC", "saas")

rule("1.2.2", ["exo.mailboxes","graph.users"], r'''
$sh = @(Ev 'exo.mailboxes' | Where-Object { $_.RecipientTypeDetails -eq 'SharedMailbox' })
if ($sh.Count -eq 0) { return NA "No shared mailboxes exist in the tenant." }
$users = Ev 'graph.users'
$enabled = @()
foreach ($m in $sh) { $u = $users | Where-Object { $_.userPrincipalName -eq $m.UserPrincipalName } | Select -First 1; if ($u -and $u.accountEnabled) { $enabled += $m.PrimarySmtpAddress } }
if ($enabled.Count -eq 0) { Pass "All $($sh.Count) shared mailboxes have sign-in blocked (accountEnabled = false)." }
else { Fail "$($enabled.Count) of $($sh.Count) shared mailboxes still allow sign-in: $(($enabled | Select -First 10) -join ', ')" }
''', "UAC", "admin")

rule("1.3.1", ["graph.domains"], r'''
$d = @(Ev 'graph.domains' | Where-Object { $_.isVerified })
$bad = @($d | Where-Object { $_.passwordValidityPeriodInDays -ne 2147483647 })
if ($bad.Count -eq 0) { Pass "All $($d.Count) verified domains have passwordValidityPeriodInDays = 2147483647 (never expire)." }
else { Fail "$($bad.Count) of $($d.Count) verified domains still expire passwords: $(($bad | % { "$($_.id)=$($_.passwordValidityPeriodInDays)d" }) -join ', ')" }
''', "UAC", "pwd")

rule("1.3.2", ["graph.activityBasedTimeoutPolicies"], r'''
$p = Ev 'graph.activityBasedTimeoutPolicies'
if ($p.Count -eq 0) { return Fail "policies/activityBasedTimeoutPolicies is empty - no idle session timeout is configured." }
$txt = ($p | % { ($_.definition -join ' ') }) -join ' | '
if ($txt -match 'WebSessionIdleTimeout.*?"?(\d+):(\d+):(\d+)') { $h=[int]$matches[1]; if ($h -le 3) { Pass "Idle timeout policy present: $txt" } else { Fail "Idle timeout is $h h - CIS requires 3 hours or less: $txt" } }
else { Review "Idle timeout policy present but duration could not be parsed: $txt" }
''', "SC", "saas", "Microsoft 365 admin centre > Settings > Org settings > Security & privacy > Idle session timeout")

rule("1.3.3", ["exo.sharingPolicy"], r'''
$sp = Ev 'exo.sharingPolicy'
$open = @($sp | Where-Object { $_.Enabled -and (($_.Domains -join ';') -match 'Anonymous:|\*:') })
if ($open.Count -eq 0) { Pass "No enabled sharing policy permits anonymous or all-domain calendar sharing. Policies: $(($sp | % { "$($_.Name) [$($_.Domains -join ';')]" }) -join '; ')" }
else { Fail "Enabled sharing policy allows external calendar sharing: $(($open | % { "$($_.Name) [$($_.Domains -join ';')]" }) -join '; ')" }
''', "SC", "saas")

rule("1.3.4", ["graph.appsAndServicesSettings"], r'''
$s = One 'graph.appsAndServicesSettings'
if (-not $s) { return Manual "Microsoft 365 admin centre > Settings > Org settings > Services > User owned apps and services: both boxes must be unchecked." }
if ($s.isOfficeStoreEnabled -eq $false -and $s.isAppAndServicesTrialEnabled -eq $false) { Pass "isOfficeStoreEnabled = false; isAppAndServicesTrialEnabled = false." }
else { Fail "isOfficeStoreEnabled = $($s.isOfficeStoreEnabled); isAppAndServicesTrialEnabled = $($s.isAppAndServicesTrialEnabled)." }
''', "SC", "saas")

rule("1.3.5", ["graph.formsSettings"], r'''
$s = One 'graph.formsSettings'
if (-not $s) { return Manual "Microsoft 365 admin centre > Settings > Org settings > Services > Microsoft Forms: 'Add internal phishing protection' must be checked." }
if ($s.isInOrgFormsPhishingScanEnabled) { Pass "isInOrgFormsPhishingScanEnabled = true." } else { Fail "isInOrgFormsPhishingScanEnabled = $($s.isInOrgFormsPhishingScanEnabled)." }
''', "MP", "phish")

rule("1.3.6", ["exo.organizationConfig"], r'''
$o = One 'exo.organizationConfig'
if (-not $Ctx.HasLockbox) { return NA "Customer Lockbox requires an E5 / Customer Lockbox add-on licence that the tenant does not hold (CustomerLockboxEnabled = $($o.CustomerLockboxEnabled))." }
if ($o.CustomerLockboxEnabled) { Pass "organizationConfig: CustomerLockboxEnabled = True." } else { Fail "organizationConfig: CustomerLockboxEnabled = False although the licence is held." }
''', "-", "cloud")

rule("1.3.7", ["graph.servicePrincipals"], r'''
$sp = Ev 'graph.servicePrincipals' | Where-Object { $_.appId -eq 'c1f33bc0-bdb4-4248-ba9b-096807ddb43e' } | Select -First 1
if (-not $sp) { return Manual "Microsoft 365 admin centre > Settings > Org settings > Services > Microsoft 365 on the web: 'Let users open files stored in third-party storage services' must be unchecked (service principal c1f33bc0... not present, so the setting has never been toggled - default is ON)." }
if ($sp.accountEnabled -eq $false) { Pass "Service principal 'Office 365 on the web third-party storage' (c1f33bc0...) accountEnabled = false." } else { Fail "Third-party storage service principal accountEnabled = $($sp.accountEnabled) - users can open files from third-party storage in Microsoft 365 on the web." }
''', "SC", "saas")

rule("1.3.8", ["graph.swaySettings"], r'''
$s = One 'graph.swaySettings'
if (-not $s) { return Manual "Microsoft 365 admin centre > Settings > Org settings > Services > Sway: 'Let people in your organization share their sways with people outside' must be unchecked." }
if ($s.isExternalSharingEnabled -eq $false) { Pass "Sway isExternalSharingEnabled = false." } else { Fail "Sway isExternalSharingEnabled = $($s.isExternalSharingEnabled)." }
''', "SC", "saas")

rule("1.3.9", ["exo.organizationConfig"], r'''
$o = One 'exo.organizationConfig'
if ($o.BookingsEnabled -eq $false) { Pass "organizationConfig: BookingsEnabled = False." }
else {
  $guards = @(); foreach ($p in 'BookingsAddressEntryRestricted','BookingsAuthEnabled','BookingsCreationOfCustomQuestionsRestricted','BookingsExposureOfStaffDetailsRestricted','BookingsNotesEntryRestricted','BookingsPhoneNumberEntryRestricted','BookingsSocialSharingRestricted') { if ($o.$p) { $guards += $p } }
  if ($guards.Count -ge 5) { Partial "Bookings is enabled but restricted ($($guards.Count) guardrails on: $($guards -join ', '))." } else { Fail "organizationConfig: BookingsEnabled = True with only $($guards.Count) of 7 guardrails set." }
}
''', "SC", "saas")

# ---- 2  Defender ------------------------------------------------------------
rule("2.1.1", ["exo.safeLinksPolicy","exo.safeLinksRule"], r'''
if (-not $Ctx.HasMDO1) { return NA "Safe Links requires Defender for Office 365 Plan 1 (not licensed)." }
$pol = Ev 'exo.safeLinksPolicy'; $rules = @(Ev 'exo.safeLinksRule' | Where-Object { $_.State -eq 'Enabled' })
$good = @($pol | Where-Object { $_.EnableSafeLinksForEmail -and $_.EnableSafeLinksForTeams -and $_.EnableSafeLinksForOffice -and $_.TrackClicks -and -not $_.AllowClickThrough -and $_.ScanUrls -and $_.EnableForInternalSenders -and $_.DeliverMessageAfterScan -and -not $_.DisableUrlRewrite })
$assigned = @($good | Where-Object { $_.IsBuiltInProtection -or ($rules | Where-Object { $_.SafeLinksPolicy -eq $_.Name }) })
if ($good.Count -gt 0 -and ($rules.Count -gt 0 -or ($pol | ? { $_.RecommendedPolicyType -in 'Standard','Strict' }))) { Pass "Compliant Safe Links policy present and assigned: $(($good.Name) -join ', ')" }
elseif ($good.Count -gt 0) { Partial "A compliant Safe Links policy exists ($(($good.Name) -join ', ')) but no enabled Safe Links rule assigns it to users; only Built-In Protection applies." }
else { Fail "No Safe Links policy meets all CIS settings. Policies: $(($pol | % { "$($_.Name) [Office=$($_.EnableSafeLinksForOffice) ClickThrough=$($_.AllowClickThrough)]" }) -join '; ')" }
''', "MP", "phish")

rule("2.1.2", ["exo.malwareFilterPolicy"], r'''
$p = Ev 'exo.malwareFilterPolicy'
$off = @($p | Where-Object { -not $_.EnableFileFilter })
if ($off.Count -eq 0) { Pass "EnableFileFilter = True on all $($p.Count) anti-malware policies." } else { Fail "EnableFileFilter = False on: $(($off.Name) -join ', ')" }
''', "MP", "phish")

rule("2.1.3", ["exo.malwareFilterPolicy"], r'''
$p = Ev 'exo.malwareFilterPolicy'
$bad = @($p | Where-Object { -not ($_.EnableInternalSenderAdminNotifications -and $_.InternalSenderAdminAddress) })
if ($bad.Count -eq 0) { Pass "Internal sender admin notifications enabled with an address on all $($p.Count) anti-malware policies." } else { Fail "EnableInternalSenderAdminNotifications / InternalSenderAdminAddress not set on: $(($bad.Name) -join ', ')" }
''', "MP", "phish")

rule("2.1.4", ["exo.safeAttachmentPolicy","exo.safeAttachmentRule"], r'''
if (-not $Ctx.HasMDO1) { return NA "Safe Attachments requires Defender for Office 365 Plan 1 (not licensed)." }
$pol = Ev 'exo.safeAttachmentPolicy'; $rules = @(Ev 'exo.safeAttachmentRule' | Where-Object { $_.State -eq 'Enabled' })
$good = @($pol | Where-Object { $_.Enable -and $_.Action -in 'Block','DynamicDelivery' })
if ($good.Count -gt 0 -and $rules.Count -gt 0) { Pass "Safe Attachments enabled (Action $($good[0].Action)) and assigned by $($rules.Count) enabled rule(s): $(($good.Name) -join ', ')" }
elseif ($good.Count -gt 0) { Partial "Only Built-In Protection / unassigned policies are enabled ($(($good.Name) -join ', ')); no enabled Safe Attachments rule targets users." }
else { Fail "No Safe Attachments policy is enabled with Block or Dynamic Delivery. Policies: $(($pol | % { "$($_.Name) [Enable=$($_.Enable) Action=$($_.Action)]" }) -join '; ')" }
''', "MP", "phish")

rule("2.1.5", ["exo.atpPolicyForO365"], r'''
if (-not $Ctx.HasMDO1) { return NA "Requires Defender for Office 365 Plan 1 (not licensed)." }
$a = One 'exo.atpPolicyForO365'
if ($a.EnableATPForSPOTeamsODB -and $a.EnableSafeDocs -and -not $a.AllowSafeDocsOpen) { Pass "EnableATPForSPOTeamsODB = True; EnableSafeDocs = True; AllowSafeDocsOpen = False." }
elseif ($a.EnableATPForSPOTeamsODB) { Partial "EnableATPForSPOTeamsODB = True but EnableSafeDocs = $($a.EnableSafeDocs) / AllowSafeDocsOpen = $($a.AllowSafeDocsOpen) (Safe Documents needs E5 / MDO P2)." }
else { Fail "atpPolicyForO365: EnableATPForSPOTeamsODB = $($a.EnableATPForSPOTeamsODB)." }
''', "MP", "phish")

rule("2.1.6", ["exo.hostedOutboundSpam"], r'''
$p = Ev 'exo.hostedOutboundSpam'
$bad = @($p | Where-Object { -not ($_.NotifyOutboundSpam -and $_.NotifyOutboundSpamRecipients -and $_.BccSuspiciousOutboundMail -and $_.BccSuspiciousOutboundAdditionalRecipients) })
if ($bad.Count -eq 0) { Pass "All $($p.Count) outbound spam policies notify admins and BCC suspicious outbound mail." } else { Fail "Outbound spam notification/BCC incomplete on: $(($bad | % { "$($_.Name) [Notify=$($_.NotifyOutboundSpam) Bcc=$($_.BccSuspiciousOutboundMail)]" }) -join '; ')" }
''', "MP", "phish")

rule("2.1.7", ["exo.antiPhishPolicy"], r'''
if (-not $Ctx.HasMDO1) { return NA "Impersonation and mailbox-intelligence protection require Defender for Office 365 Plan 1 (not licensed)." }
$p = Ev 'exo.antiPhishPolicy'
$good = @($p | Where-Object { $_.Enabled -and $_.PhishThresholdLevel -ge 2 -and $_.EnableTargetedUserProtection -and $_.EnableOrganizationDomainsProtection -and $_.EnableMailboxIntelligence -and $_.EnableMailboxIntelligenceProtection -and $_.EnableSpoofIntelligence -and $_.TargetedUserProtectionAction -eq 'Quarantine' -and $_.TargetedDomainProtectionAction -eq 'Quarantine' -and $_.MailboxIntelligenceProtectionAction -eq 'Quarantine' -and $_.EnableFirstContactSafetyTips -and $_.EnableSimilarUsersSafetyTips -and $_.EnableSimilarDomainsSafetyTips -and $_.EnableUnusualCharactersSafetyTips -and $_.HonorDmarcPolicy })
if ($good.Count -gt 0) { Pass "Anti-phishing policy meets CIS settings: $(($good.Name) -join ', ')" }
else { Fail "No anti-phishing policy meets all CIS settings. $(($p | % { "$($_.Name) [Threshold=$($_.PhishThresholdLevel) TargetedUser=$($_.EnableTargetedUserProtection) MailboxIntel=$($_.EnableMailboxIntelligenceProtection) OrgDomains=$($_.EnableOrganizationDomainsProtection)]" }) -join '; ')" }
''', "MP", "phish")

rule("2.1.8", ["dns.records","exo.acceptedDomains"], r'''
$d = @(Ev 'dns.records' | Where-Object { $_.MailRouting })
if ($d.Count -eq 0) { return Manual "Check SPF for each accepted domain: nslookup -type=TXT <domain> (expect v=spf1 ... include:spf.protection.outlook.com -all)." }
$bad = @($d | Where-Object { -not ($_.SPF -match 'v=spf1' -and $_.SPF -match 'spf\.protection\.outlook\.com' -and $_.SPF -match '-all') })
if ($bad.Count -eq 0) { Pass "SPF present with include:spf.protection.outlook.com and hard fail (-all) on all $($d.Count) mail-routing domains." }
else { Fail "SPF missing, not including Exchange Online, or softfail (~all) on: $(($bad | % { "$($_.Domain) [$($_.SPF)]" }) -join '; ')" }
''', "SC", "email")

rule("2.1.9", ["exo.dkimSigningConfig","exo.acceptedDomains","dns.records"], r'''
$k = Ev 'exo.dkimSigningConfig'
$dom = @(Ev 'exo.acceptedDomains' | Where-Object { $_.DomainName -notlike '*.onmicrosoft.com' -and "$($_.DomainType)" -eq 'Authoritative' })
$on = @($k | ? { $_.Enabled } | % { $_.Domain })
$missing = @($dom | Where-Object { $_.DomainName -notin $on } | % { $_.DomainName })
if ($missing.Count -eq 0) { return Pass "DKIM signing enabled for all $($dom.Count) authoritative custom domains: $($on -join ', ')" }
$dns = Ev 'dns.records'
$routing = @($missing | ? { $d = $_; ($dns | ? { $_.Domain -eq $d -and $_.MailRouting }) })
if ($routing.Count -gt 0) { Fail "DKIM not enabled on mail-routing domain(s): $($routing -join ', '). Enabled on: $($on -join ', ')" }
elseif ($dns.Count -gt 0) { Partial "DKIM enabled on $($on -join ', '); not enabled on $($missing -join ', ') (no MX record - likely a relay/vanity domain, confirm it never sends mail)." }
else { Partial "DKIM enabled on $($on -join ', '); not enabled on $($missing -join ', '). Run the DNS workload to confirm whether these domains route mail." }
''', "SC", "email")

rule("2.1.10", ["dns.records"], r'''
$d = @(Ev 'dns.records' | Where-Object { $_.MailRouting })
if ($d.Count -eq 0) { return Manual "Check DMARC for each accepted domain: nslookup -type=TXT _dmarc.<domain> (expect v=DMARC1; p=reject or quarantine; rua=...; ruf=...)." }
$bad = @($d | Where-Object { -not ($_.DMARC -match 'v=DMARC1' -and $_.DMARC -match 'p=(reject|quarantine)' -and $_.DMARC -match 'rua=' ) })
if ($bad.Count -eq 0) { Pass "DMARC with p=quarantine/reject and rua reporting on all $($d.Count) mail-routing domains." }
else { Fail "DMARC missing, p=none, or no rua on: $(($bad | % { "$($_.Domain) [$($_.DMARC)]" }) -join '; ')" }
''', "SC", "email")

rule("2.1.11", ["exo.malwareFilterPolicy"], r'''
$L2 = 'ace','apk','app','appx','ani','arj','bat','cab','cmd','com','deb','dex','dll','docm','elf','exe','hta','img','iso','jar','jnlp','kext','lha','lib','library','lnk','lzh','macho','msc','msi','msix','msp','mst','pif','ppa','ppam','reg','rev','scf','scr','sct','sys','uif','vb','vbe','vbs','vxd','wsc','wsf','wsh','xll','xz','z','7z','ar','arj','bz','bz2','cpio','gz','jar','lz','lzma','r00','rar','rpm','tar','tgz','z','zip','xlam','xla','xlsb','xltm','potm','pptm','sldm','pps','ppsm','docb','dot','dotm','wll','wsh','ws','vbp','vbscript','vhd','vhdx','vmdk','vmx','wim','cer','crt','der','p12','pfx','p7b','ocx','prf','prg','ps1','ps1xml','ps2','ps2xml','psc1','psc2','psd1','psm1','py','pyc','pyo','pyw','pyz','pyzw','rb','sh','shb','shs','sldm','url','website','xbap','xnk','zipx','jse','js','ksh','local','local'
$L2 = $L2 | Select -Unique
$p = Ev 'exo.malwareFilterPolicy' | Where-Object { $_.EnableFileFilter }
if (-not $p) { return Fail "No anti-malware policy has the common attachment filter enabled." }
$best = $p | Sort-Object { @($_.FileTypes).Count } -Descending | Select -First 1
$have = @($best.FileTypes | % { $_.ToLower() })
$cover = @($L2 | Where-Object { $_ -in $have }).Count
$pct = [math]::Round(100 * $cover / $L2.Count)
if ($have.Count -ge 120 -and $pct -ge 90) { Pass "'$($best.Name)' blocks $($have.Count) extensions covering $pct% of the CIS L2 list." }
elseif ($have.Count -ge 120) { Partial "'$($best.Name)' blocks $($have.Count) extensions but only $pct% of the CIS L2 list." }
else { Fail "'$($best.Name)' blocks $($have.Count) extensions ($pct% of the CIS L2 list); CIS L2 expects at least 120 and 90% coverage." }
''', "MP", "phish")

rule("2.1.12", ["exo.hostedConnectionFilter"], r'''
$p = Ev 'exo.hostedConnectionFilter'; $bad = @($p | Where-Object { @($_.IPAllowList).Count -gt 0 })
if ($bad.Count -eq 0) { Pass "IPAllowList is empty on all $($p.Count) connection filter policies." } else { Fail "IP allow list in use on: $(($bad | % { "$($_.Name) [$(@($_.IPAllowList).Count) entries]" }) -join '; ')" }
''', "MP", "phish")

rule("2.1.13", ["exo.hostedConnectionFilter"], r'''
$p = Ev 'exo.hostedConnectionFilter'; $bad = @($p | Where-Object { $_.EnableSafeList })
if ($bad.Count -eq 0) { Pass "EnableSafeList = False on all $($p.Count) connection filter policies." } else { Fail "EnableSafeList = True on: $(($bad.Name) -join ', ')" }
''', "MP", "phish")

rule("2.1.14", ["exo.hostedContentFilter"], r'''
$p = Ev 'exo.hostedContentFilter'; $bad = @($p | Where-Object { @($_.AllowedSenderDomains).Count -gt 0 })
if ($bad.Count -eq 0) { Pass "AllowedSenderDomains is empty on all $($p.Count) inbound anti-spam policies." } else { Fail "Allowed sender domains configured on: $(($bad | % { "$($_.Name) [$(@($_.AllowedSenderDomains) -join ',')]" }) -join '; ')" }
''', "MP", "phish")

rule("2.1.15", ["exo.hostedOutboundSpam"], r'''
$p = Ev 'exo.hostedOutboundSpam'
$bad = @($p | Where-Object { -not ($_.RecipientLimitExternalPerHour -gt 0 -and $_.RecipientLimitExternalPerHour -le 500 -and $_.RecipientLimitInternalPerHour -gt 0 -and $_.RecipientLimitInternalPerHour -le 1000 -and $_.RecipientLimitPerDay -gt 0 -and $_.RecipientLimitPerDay -le 1000 -and $_.ActionWhenThresholdReached -eq 'BlockUser') })
if ($bad.Count -eq 0) { Pass "Outbound limits set (ext/hr <=500, int/hr <=1000, /day <=1000, BlockUser) on all $($p.Count) policies." }
else { Fail "Outbound limits not at CIS values on: $(($bad | % { "$($_.Name) [ext=$($_.RecipientLimitExternalPerHour) int=$($_.RecipientLimitInternalPerHour) day=$($_.RecipientLimitPerDay) action=$($_.ActionWhenThresholdReached)]" }) -join '; ')" }
''', "MP", "phish")

rule("2.2.1", ["scc.protectionAlerts","graph.directoryRoles"], r'''
$a = Ev 'scc.protectionAlerts'
$bg = @($Ctx.BreakGlass)
if ($bg.Count -eq 0) { return Fail "No break-glass accounts are identified (see 1.1.2), so there is nothing being monitored. Create them, then add an alert policy on their sign-in and audit activity." }
$hit = @($a | Where-Object { -not $_.Disabled -and (($_.Name + ' ' + $_.Filter) -match ($bg -join '|')) })
if ($hit.Count -gt 0) { Pass "Alert policy references the break-glass accounts: $(($hit.Name) -join ', ')" }
else { Review "$($a.Count) alert policies exist but none names the break-glass accounts ($($bg -join ', ')). Confirm a Sentinel/Defender rule or alert policy covers their sign-ins." }
''', "UAC", "log", "Defender portal > Policies & rules > Alert policy; or Purview > Audit")

rule("2.4.1", ["exo.antiPhishPolicy","exo.userTags"], r'''
if (-not $Ctx.HasMDO1) { return NA "Priority account protection requires Defender for Office 365 Plan 1 (not licensed)." }
$p = Ev 'exo.antiPhishPolicy'; $tag = Ev 'exo.userTags'
$pri = @($tag | Where-Object { $_.Name -eq 'Priority account' -or $_.Type -eq 'Priority account' })
$targeted = @($p | Where-Object { $_.EnableTargetedUserProtection -and @($_.TargetedUsersToProtect).Count -gt 0 })
if ($pri.Count -gt 0 -and $targeted.Count -gt 0) { Pass "Priority account tag populated and targeted-user protection lists $(@($targeted[0].TargetedUsersToProtect).Count) users." }
elseif ($targeted.Count -gt 0 -or $pri.Count -gt 0) { Partial "Partially configured: priority tag entries = $($pri.Count); policies with targeted users = $($targeted.Count). Confirm Priority account protection is On in Defender > Settings > Email & collaboration." }
else { Fail "No priority accounts are tagged and no anti-phishing policy lists targeted users to protect." }
''', "UAC", "phish", "Defender portal > Settings > Email & collaboration > Priority account protection / User tags")

rule("2.4.2", ["exo.eopProtectionPolicyRule","exo.atpProtectionPolicyRule"], r'''
$eop = @(Ev 'exo.eopProtectionPolicyRule' | Where-Object { $_.State -eq 'Enabled' })
$atp = @(Ev 'exo.atpProtectionPolicyRule' | Where-Object { $_.State -eq 'Enabled' })
$strictE = @($eop | ? { $_.Name -like 'Strict*' }); $strictA = @($atp | ? { $_.Name -like 'Strict*' })
if ($eop.Count -eq 0 -and $atp.Count -eq 0) { return Fail "No preset security policy (Standard or Strict) is enabled - Defender runs on Built-In Protection only." }
if ($strictE.Count -gt 0 -and ($strictA.Count -gt 0 -or -not $Ctx.HasMDO1)) { Pass "Strict preset enabled (EOP: $($strictE.Name -join ','); MDO: $($strictA.Name -join ','))." }
else { Partial "Preset enabled but not Strict for priority accounts: EOP = $(($eop.Name) -join ','); MDO = $(($atp.Name) -join ','). CIS 2.4.2 expects Strict applied to priority accounts (Standard for everyone else)." }
''', "MP", "phish")

rule("2.4.3", [], r'''
if (-not $Ctx.HasMDCA) { return NA "Defender for Cloud Apps requires E5 / MDCA add-on (not licensed)." }
Manual "Defender portal > Settings > Cloud apps: confirm app connectors (Office 365, Entra) are connected and Cloud Discovery is receiving data."
''', "-", "saas", "Defender portal > Settings > Cloud apps > Connected apps")

rule("2.4.4", ["exo.teamsProtectionPolicy"], r'''
if (-not $Ctx.HasMDO1) { return NA "Teams ZAP requires Defender for Office 365 (not licensed)." }
$t = One 'exo.teamsProtectionPolicy'
if (-not $t) { return Fail "No Teams protection policy returned (Get-TeamsProtectionPolicy)." }
if ($t.ZapEnabled) { Pass "teamsProtectionPolicy: ZapEnabled = True." } else { Fail "teamsProtectionPolicy: ZapEnabled = False." }
''', "MP", "phish")

rule("2.4.5", [], r'''
if (-not $Ctx.HasMDO2) { return NA "Automated Investigation and Response requires Defender for Office 365 Plan 2 / E5 (not licensed)." }
Manual "Defender portal > Actions & submissions > Action center: confirm investigations are running and pending actions are being approved."
''', "MP", "phish", "Defender portal > Actions & submissions > Action center")

# ---- 3  Purview -------------------------------------------------------------
rule("3.1.1", ["exo.adminAuditLogConfig","scc.auditConfig"], r'''
$a = One 'exo.adminAuditLogConfig'; $s = One 'scc.auditConfig'
$v1 = $a.UnifiedAuditLogIngestionEnabled; $v2 = $s.UnifiedAuditLogIngestionEnabled
if ($v1 -eq $true -and ($null -eq $v2 -or $v2 -eq $true)) { Pass "UnifiedAuditLogIngestionEnabled = True." }
elseif ($v1 -eq $true -or $v2 -eq $true) { Partial "Exchange reports UnifiedAuditLogIngestionEnabled = $v1; Security & Compliance reports $v2. Confirm in Purview > Audit." }
else { Fail "UnifiedAuditLogIngestionEnabled = $v1." }
''', "-", "log")

rule("3.2.1", ["scc.dlpCompliancePolicy"], r'''
$p = @(Ev 'scc.dlpCompliancePolicy' | Where-Object { $_.Enabled -and $_.Mode -eq 'Enable' })
$ex = @($p | ? { ($_.ExchangeLocation -join ',') -match 'All|@' }); $sp = @($p | ? { ($_.SharePointLocation -join ',') -match 'All|http' })
if ($ex.Count -gt 0 -and $sp.Count -gt 0) { Pass "$($p.Count) enforced DLP policies cover Exchange ($($ex.Name -join ',')) and SharePoint ($($sp.Name -join ','))." }
elseif ($p.Count -gt 0) { Partial "$($p.Count) enforced DLP policies but coverage is incomplete (Exchange: $($ex.Count), SharePoint: $($sp.Count))." }
else { Fail "No enforced DLP policy exists (Get-DlpCompliancePolicy returned $(@(Ev 'scc.dlpCompliancePolicy').Count) policies, none in Enable mode)." }
''', "-", "data")

rule("3.2.2", ["scc.dlpComplianceRule"], r'''
if (-not $Ctx.HasE5Compliance) { return NA "Teams DLP requires Microsoft 365 E5 / E5 Compliance (not licensed)." }
$r = @(Ev 'scc.dlpComplianceRule' | Where-Object { $_.Name -like 'Default Teams DLP policy rule*' })
if ($r.Count -gt 0 -and -not $r[0].Disabled) { Pass "Default Teams DLP policy rule present and enabled." } elseif ($r.Count -gt 0) { Fail "Default Teams DLP policy rule is disabled." } else { Fail "Default Teams DLP policy rule not found." }
''', "-", "data")

rule("3.2.3", ["scc.dlpCompliancePolicy"], r'''
if (-not $Ctx.HasE5Compliance) { return NA "DLP for Microsoft 365 Copilot requires E5 / E5 Compliance (not licensed)." }
$p = @(Ev 'scc.dlpCompliancePolicy' | Where-Object { $_.Enabled -and (($_.Workload -join ',') -match 'Copilot|Microsoft365Copilot' -or ($_ | ConvertTo-Json -Depth 3) -match 'Copilot') })
if ($p.Count -gt 0) { Pass "DLP policy scoped to Microsoft 365 Copilot: $($p.Name -join ', ')" } else { Fail "No DLP policy includes the Microsoft 365 Copilot location." }
''', "-", "data")

rule("3.3.1", ["scc.sensitivityLabels","scc.labelPolicies"], r'''
$l = @(Ev 'scc.sensitivityLabels' | Where-Object { -not $_.Disabled }); $pol = @(Ev 'scc.labelPolicies' | Where-Object { $_.Enabled })
if ($l.Count -gt 0 -and $pol.Count -gt 0) { Pass "$($l.Count) sensitivity labels published by $($pol.Count) label policy/policies ($($pol.Name -join ', '))." }
elseif ($l.Count -gt 0) { Partial "$($l.Count) labels exist but no enabled label policy publishes them." }
else { Fail "No sensitivity labels exist (Get-Label returned nothing)." }
''', "-", "data")

# ---- 4  Intune --------------------------------------------------------------
rule("4.1", ["graph.deviceManagementSettings"], r'''
if (-not $Ctx.HasIntune) { return NA "Intune is not licensed in this tenant." }
$s = One 'graph.deviceManagementSettings'
$v = if ($s.settings) { $s.settings.secureByDefault } else { $s.secureByDefault }
if ($v -eq $true) { Pass "deviceManagement/settings secureByDefault = true (devices with no compliance policy are Not compliant)." }
elseif ($null -eq $v) { Fail "deviceManagement settings returned null - Intune has never been configured; devices with no policy default to Compliant." }
else { Fail "secureByDefault = $v - devices with no compliance policy are marked Compliant." }
''', "SC", "device")

rule("4.2", ["graph.deviceEnrollmentConfigurations"], r'''
if (-not $Ctx.HasIntune) { return NA "Intune is not licensed in this tenant." }
$c = @(Ev 'graph.deviceEnrollmentConfigurations' | Where-Object { $_.'@odata.type' -match 'platformRestrictions?Configuration' -and $_.priority -eq 0 })
if ($c.Count -eq 0) { $c = @(Ev 'graph.deviceEnrollmentConfigurations' | Where-Object { $_.'@odata.type' -match 'platformRestrictions?Configuration' }) }
if ($c.Count -eq 0) { return Fail "No device platform restriction configuration returned." }
$d = $c[0]; $open = @()
foreach ($plat in 'androidRestriction','androidForWorkRestriction','iosRestriction','macOSRestriction','windowsRestriction','windowsHomeSkuRestriction') { $r = $d.$plat; if ($r -and -not $r.platformBlocked -and -not $r.personalDeviceEnrollmentBlocked) { $open += $plat } }
if ($d.platformRestriction -and -not $d.platformRestriction.platformBlocked -and -not $d.platformRestriction.personalDeviceEnrollmentBlocked) { $open += $d.platformType }
if ($open.Count -eq 0) { Pass "Default platform restrictions block personally owned enrolment on every platform." } else { Fail "Personally owned enrolment is allowed for: $($open -join ', ') (default priority policy '$($d.displayName)')." }
''', "SC", "device")

# ---- 5  Entra ---------------------------------------------------------------
rule("5.1.2.1", ["graph.perUserMfaStates","graph.conditionalAccessPolicies","graph.securityDefaults"], r'''
$s = Ev 'graph.perUserMfaStates'
if ($s.Count -eq 0) { return Manual "Entra admin centre > Users > Per-user MFA: every user should show Disabled (use Conditional Access or Security Defaults instead)." }
$on = @($s | Where-Object { $_.perUserMfaState -in 'enabled','enforced' })
$ca = @(Get-CA | ? { (CA-AllUsers $_) -and (CA-Grant $_ 'mfa') }); $sd = (One 'graph.securityDefaults').isEnabled
if ($on.Count -eq 0) { Pass "perUserMfaState = disabled for all $($s.Count) users checked." }
elseif ($ca.Count -eq 0 -and -not $sd) { Fail "Legacy per-user MFA is the ONLY MFA mechanism: $($on.Count) of $($s.Count) users enabled/enforced, no Conditional Access MFA policy and Security Defaults off. Do not disable per-user MFA until CA or Security Defaults enforces MFA." }
else { Fail "$($on.Count) of $($s.Count) users still have legacy per-user MFA enabled/enforced alongside CA/Security Defaults: $(($on.userPrincipalName | Select -First 10) -join ', ')" }
''', "UAC", "mfa")

rule("5.1.2.2", ["graph.authorizationPolicy"], r'''
$v = (One 'graph.authorizationPolicy').defaultUserRolePermissions.allowedToCreateApps
if ($v -eq $false) { Pass "authorizationPolicy defaultUserRolePermissions.allowedToCreateApps = false." } else { Fail "allowedToCreateApps = $v - any user can register applications." }
''', "UAC", "saas")
rule("5.1.2.3", ["graph.authorizationPolicy"], r'''
$v = (One 'graph.authorizationPolicy').defaultUserRolePermissions.allowedToCreateTenants
if ($v -eq $false) { Pass "allowedToCreateTenants = false." } else { Fail "allowedToCreateTenants = $v - any user can create new tenants." }
''', "UAC", "saas")
rule("5.1.2.4", [], None, "UAC", "admin", "Entra admin centre > Users > User settings > 'Restrict access to Microsoft Entra admin center' = Yes")
rule("5.1.2.5", [], None, "UAC", "zt", "Entra admin centre > Company branding > Default sign-in > Layout: 'Show option to remain signed in' = No")
rule("5.1.2.6", [], None, "UAC", "saas", "Entra admin centre > Users > User settings > LinkedIn account connections = No")
rule("5.1.3.1", ["graph.authorizationPolicy"], r'''
$v = (One 'graph.authorizationPolicy').defaultUserRolePermissions.allowedToCreateSecurityGroups
if ($v -eq $false) { Pass "allowedToCreateSecurityGroups = false." } else { Fail "allowedToCreateSecurityGroups = $v." }
''', "UAC", "saas")
rule("5.1.3.2", [], None, "UAC", "saas", "Entra admin centre > Groups > General > 'Restrict user ability to access groups features in My Groups' = Yes")
rule("5.1.3.3", [], None, "UAC", "saas", "Entra admin centre > Groups > General > 'Owners can manage group membership requests in My Groups' = Yes")
rule("5.1.3.4", ["graph.groupSettings"], r'''
$gs = Ev 'graph.groupSettings' | Where-Object { $_.displayName -eq 'Group.Unified' } | Select -First 1
if (-not $gs) { return Fail "No 'Group.Unified' directory setting exists - tenant default applies and every user can create Microsoft 365 groups." }
$v = ($gs.values | ? { $_.name -eq 'EnableGroupCreation' }).value
$grp = ($gs.values | ? { $_.name -eq 'GroupCreationAllowedGroupId' }).value
if ($v -eq 'false' -or $v -eq 'False') { Pass "Group.Unified EnableGroupCreation = False (allowed group: $grp)." } else { Fail "Group.Unified EnableGroupCreation = $v." }
''', "UAC", "saas")

rule("5.1.4.1", ["graph.deviceRegistrationPolicy"], r'''
$p = One 'graph.deviceRegistrationPolicy'; $v = $p.azureADJoin.appliesTo
if ($v -in 'selected','none') { Pass "deviceRegistrationPolicy azureADJoin.appliesTo = $v." } else { Fail "azureADJoin.appliesTo = $v - all users may join devices to Entra ID." }
''', "SC", "device")
rule("5.1.4.2", ["graph.deviceRegistrationPolicy"], r'''
$v = (One 'graph.deviceRegistrationPolicy').userDeviceQuota
if ($v -le 50) { Pass "userDeviceQuota = $v." } else { Fail "userDeviceQuota = $v (CIS maximum 50)." }
''', "SC", "device")
rule("5.1.4.3", ["graph.deviceRegistrationPolicy"], r'''
$v = (One 'graph.deviceRegistrationPolicy').azureADJoin.localAdmins.enableGlobalAdmins
if ($v -eq $false) { Pass "azureADJoin.localAdmins.enableGlobalAdmins = false." } else { Fail "enableGlobalAdmins = $v - Global Administrators become local admins on every joined device." }
''', "UAC", "device")
rule("5.1.4.4", ["graph.deviceRegistrationPolicy"], r'''
$r = (One 'graph.deviceRegistrationPolicy').azureADJoin.localAdmins.registeringUsers
$t = "$($r.'@odata.type')"
if ($t -match 'noDeviceRegistrationMembership') { Pass "registeringUsers = $t (registering user is not a local admin)." } else { Fail "registeringUsers = $t - the registering user becomes local administrator." }
''', "UAC", "device")
rule("5.1.4.5", ["graph.deviceRegistrationPolicy"], r'''
$v = (One 'graph.deviceRegistrationPolicy').localAdminPassword.isEnabled
if ($v) { Pass "localAdminPassword.isEnabled = true (Windows LAPS)." } else { Fail "localAdminPassword.isEnabled = $v - Windows LAPS is off in Entra." }
''', "UAC", "device")
rule("5.1.4.6", ["graph.authorizationPolicy"], r'''
$v = (One 'graph.authorizationPolicy').defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice
if ($v -eq $false) { Pass "allowedToReadBitlockerKeysForOwnedDevice = false." } else { Fail "allowedToReadBitlockerKeysForOwnedDevice = $v." }
''', "UAC", "device")

rule("5.1.5.1", ["graph.authorizationPolicy"], r'''
$g = @((One 'graph.authorizationPolicy').defaultUserRolePermissions.permissionGrantPoliciesAssigned)
if ($g.Count -eq 0) { Pass "permissionGrantPoliciesAssigned is empty - users cannot consent to applications." }
elseif (($g -join ',') -match 'microsoft-user-default-low') { Partial "Users may consent to verified publishers' low-impact permissions ($($g -join ', ')). CIS Level 2 expects 'Do not allow user consent'." }
else { Fail "permissionGrantPoliciesAssigned = $($g -join ', ') - users can consent to applications." }
''', "UAC", "saas")
rule("5.1.5.2", ["graph.adminConsentRequestPolicy"], r'''
$p = One 'graph.adminConsentRequestPolicy'
if ($p.isEnabled -and @($p.reviewers).Count -gt 0) { Pass "adminConsentRequestPolicy isEnabled = true with $(@($p.reviewers).Count) reviewer(s)." } elseif ($p.isEnabled) { Partial "Workflow enabled but no reviewers configured." } else { Fail "adminConsentRequestPolicy isEnabled = $($p.isEnabled)." }
''', "UAC", "saas")
rule("5.1.5.3", ["graph.defaultAppManagementPolicy"], r'''
$p = One 'graph.defaultAppManagementPolicy'
$r = @($p.applicationRestrictions.passwordCredentials | ? { $_.restrictionType -eq 'passwordAddition' -and $_.state -ne 'disabled' })
if ($p.isEnabled -and $r.Count -gt 0) { Pass "Default app management policy blocks password addition (enabled, restrictionType passwordAddition)." } else { Fail "defaultAppManagementPolicy isEnabled = $($p.isEnabled); no active passwordAddition restriction." }
''', "UAC", "admin")
rule("5.1.5.4", ["graph.defaultAppManagementPolicy","graph.applications"], r'''
$p = One 'graph.defaultAppManagementPolicy'
$r = @($p.applicationRestrictions.passwordCredentials | ? { $_.restrictionType -eq 'passwordLifetime' -and $_.state -ne 'disabled' })
$ok = $p.isEnabled -and $r.Count -gt 0 -and ([System.Xml.XmlConvert]::ToTimeSpan($r[0].maxLifetime).TotalDays -le 180)
$apps = Ev 'graph.applications'; $long = @(); foreach ($a in $apps) { foreach ($c in @($a.passwordCredentials)) { if ($c.startDateTime -and $c.endDateTime -and (([datetime]$c.endDateTime - [datetime]$c.startDateTime).TotalDays -gt 180)) { $long += $a.displayName } } }
$long = $long | Select -Unique
if ($ok) { Pass "passwordLifetime restriction <= 180 days enforced ($($r[0].maxLifetime)). $($long.Count) legacy app(s) still hold longer secrets issued earlier." }
else { Fail "No passwordLifetime restriction <= 180 days (policy enabled = $($p.isEnabled)). $($long.Count) app registrations hold secrets issued for > 180 days: $(($long | Select -First 10) -join ', ')" }
''', "UAC", "admin")
rule("5.1.5.5", ["graph.defaultAppManagementPolicy"], r'''
$p = One 'graph.defaultAppManagementPolicy'
$r = @($p.applicationRestrictions.passwordCredentials | ? { $_.restrictionType -eq 'customPasswordAddition' -and $_.state -ne 'disabled' })
if ($p.isEnabled -and $r.Count -gt 0) { Pass "customPasswordAddition restriction active - new secrets are system-generated." } else { Fail "No customPasswordAddition restriction in the default app management policy (enabled = $($p.isEnabled))." }
''', "UAC", "admin")
rule("5.1.5.6", ["graph.defaultAppManagementPolicy"], r'''
$p = One 'graph.defaultAppManagementPolicy'
$r = @($p.applicationRestrictions.keyCredentials | ? { $_.restrictionType -eq 'asymmetricKeyLifetime' -and $_.state -ne 'disabled' })
if ($p.isEnabled -and $r.Count -gt 0 -and ([System.Xml.XmlConvert]::ToTimeSpan($r[0].maxLifetime).TotalDays -le 180)) { Pass "asymmetricKeyLifetime restriction <= 180 days ($($r[0].maxLifetime))." } else { Fail "No asymmetricKeyLifetime restriction <= 180 days (enabled = $($p.isEnabled))." }
''', "UAC", "admin")

rule("5.1.6.1", ["graph.b2bManagementPolicy","graph.crossTenantAccessDefault"], r'''
$pol = Ev 'graph.b2bManagementPolicy' | ? { $_.type -eq 'B2BManagementPolicy' } | Select -First 1
$allow = $null
if ($pol) { try { $def = ($pol.definition | % { $_ | ConvertFrom-Json }); $allow = $def.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy.AllowedDomains; $block = $def.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy.BlockedDomains } catch {} }
$allow = @($allow | ? { $_ }); $block = @($block | ? { $_ })
if (-not $pol) { return Review "B2B management policy (legacy/policies) not returned - check Entra > External Identities > External collaboration settings > Collaboration restrictions." }
if ($allow.Count -gt 0) { Pass "B2B collaboration restricted to an allow list of $($allow.Count) domain(s): $(($allow | Select -First 8) -join ', ')" }
elseif ($block.Count -gt 0) { Partial "A deny list of $($block.Count) domain(s) is used; CIS prefers an allow list." }
else { Fail "No B2B collaboration domain allow list is configured - any domain can be invited." }
''', "UAC", "saas")
rule("5.1.6.2", ["graph.authorizationPolicy"], r'''
$v = (One 'graph.authorizationPolicy').guestUserRoleId
switch ($v) { '2af84b1e-32c8-42b7-82bc-daa82404023b' { Pass "guestUserRoleId = restricted (own objects only, most restrictive)." }
 '10dae51f-b6af-4016-8d66-8c2a99b929b3' { Pass "guestUserRoleId = limited access to properties and memberships (CIS-acceptable; 'restricted' is the stronger option)." }
 default { Fail "guestUserRoleId = $v (same access as members)." } }
''', "UAC", "saas")
rule("5.1.6.3", ["graph.authorizationPolicy"], r'''
$v = (One 'graph.authorizationPolicy').allowInvitesFrom
if ($v -in 'adminsAndGuestInviters','none') { Pass "allowInvitesFrom = $v." } else { Fail "allowInvitesFrom = $v - members (and possibly guests) can invite guests." }
''', "UAC", "saas")
rule("5.1.8.1", ["graph.organization"], r'''
$o = One 'graph.organization'
if (-not $o.onPremisesSyncEnabled) { return NA "Cloud-only tenant - onPremisesSyncEnabled is not true, so password hash sync does not apply." }
if ($o.onPremisesLastPasswordSyncDateTime) { Pass "Hybrid tenant; onPremisesLastPasswordSyncDateTime = $($o.onPremisesLastPasswordSyncDateTime)." } else { Fail "Hybrid tenant but no password sync timestamp - password hash synchronisation appears to be off." }
''', "UAC", "pwd")

# Conditional Access family -------------------------------------------------
rule("5.2.2.1", ["graph.conditionalAccessPolicies","graph.securityDefaults"], r'''
$p = @(Get-CA | ? { (CA-AdminRoles $_) -and (CA-AllApps $_) -and ((CA-Grant $_ 'mfa') -or $_.grantControls.authenticationStrength) })
$sd = (One 'graph.securityDefaults').isEnabled
if ($p.Count -gt 0) { Pass "Enabled CA policy requires MFA for administrator roles: $(CA-Names $p)" }
elseif ($sd) { Partial "No CA policy, but Security Defaults are enabled and enforce MFA for administrators." }
else { Fail "No enabled Conditional Access policy requires MFA for administrative roles, and Security Defaults are off. $(CA-Summary)" }
''', "UAC", "mfa")
rule("5.2.2.2", ["graph.conditionalAccessPolicies","graph.securityDefaults"], r'''
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (CA-AllApps $_) -and ((CA-Grant $_ 'mfa') -or $_.grantControls.authenticationStrength) })
$sd = (One 'graph.securityDefaults').isEnabled
if ($p.Count -gt 0) { Pass "Enabled CA policy requires MFA for all users on all resources: $(CA-Names $p)" }
elseif ($sd) { Partial "No CA policy, but Security Defaults enforce MFA registration/challenge for all users." }
else { Fail "No enabled CA policy requires MFA for all users and Security Defaults are off. $(CA-Summary)" }
''', "UAC", "mfa")
rule("5.2.2.3", ["graph.conditionalAccessPolicies","graph.securityDefaults"], r'''
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (CA-Grant $_ 'block') -and (@($_.conditions.clientAppTypes) -contains 'exchangeActiveSync') -and (@($_.conditions.clientAppTypes) -contains 'other') })
$sd = (One 'graph.securityDefaults').isEnabled
if ($p.Count -gt 0) { Pass "Legacy authentication blocked by CA: $(CA-Names $p)" } elseif ($sd) { Partial "Security Defaults block legacy authentication; no explicit CA policy." } else { Fail "No enabled CA policy blocks legacy authentication clients (Exchange ActiveSync + Other clients)." }
''', "UAC", "mfa")
rule("5.2.2.4", ["graph.conditionalAccessPolicies"], r'''
$p = @(Get-CA | ? { (CA-AdminRoles $_) -and (CA-AllApps $_) -and $_.sessionControls.signInFrequency.isEnabled -and $_.sessionControls.persistentBrowser.isEnabled -and $_.sessionControls.persistentBrowser.mode -eq 'never' })
if ($p.Count -gt 0) { Pass "Admin session controls (sign-in frequency + never-persistent browser) enforced: $(CA-Names $p)" }
else { $half = @(Get-CA | ? { (CA-AdminRoles $_) -and ($_.sessionControls.signInFrequency.isEnabled -or $_.sessionControls.persistentBrowser.isEnabled) }); if ($half) { Partial "Admin policy has only one of the two session controls: $(CA-Names $half)" } else { Fail "No enabled CA policy applies sign-in frequency and non-persistent browser sessions to administrator roles." } }
''', "UAC", "admin")
rule("5.2.2.5", ["graph.conditionalAccessPolicies"], r'''
$p = @(Get-CA | ? { (CA-AdminRoles $_) -and $_.grantControls.authenticationStrength.id -eq '00000000-0000-0000-0000-000000000004' })
$custom = @(Get-CA | ? { (CA-AdminRoles $_) -and $_.grantControls.authenticationStrength -and $_.grantControls.authenticationStrength.id -ne '00000000-0000-0000-0000-000000000004' })
if ($p.Count -gt 0) { Pass "Phishing-resistant MFA strength required for admin roles: $(CA-Names $p)" } elseif ($custom) { Review "Admin roles use a custom authentication strength ($(CA-Names $custom)) - confirm it only allows phishing-resistant methods." } else { Fail "No enabled CA policy requires the phishing-resistant MFA authentication strength for administrator roles." }
''', "UAC", "mfa")
rule("5.2.2.6", ["graph.conditionalAccessPolicies"], r'''
if (-not $Ctx.HasP2) { return NA "Requires Entra ID P2 (Identity Protection) - not licensed." }
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (@($_.conditions.userRiskLevels) -contains 'high') -and (CA-Grant $_ 'mfa') -and (CA-Grant $_ 'passwordChange') })
if ($p.Count -gt 0) { Pass "User-risk policy (high -> MFA + password change): $(CA-Names $p)" } else { Fail "No enabled CA policy acts on high user risk with MFA and password change." }
''', "UAC", "zt")
rule("5.2.2.7", ["graph.conditionalAccessPolicies"], r'''
if (-not $Ctx.HasP2) { return NA "Requires Entra ID P2 (Identity Protection) - not licensed." }
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (@($_.conditions.signInRiskLevels) -contains 'high') -and (@($_.conditions.signInRiskLevels) -contains 'medium') -and (CA-Grant $_ 'mfa') })
if ($p.Count -gt 0) { Pass "Sign-in-risk policy (medium/high -> MFA): $(CA-Names $p)" } else { Fail "No enabled CA policy requires MFA on medium and high sign-in risk." }
''', "UAC", "zt")
rule("5.2.2.8", ["graph.conditionalAccessPolicies"], r'''
if (-not $Ctx.HasP2) { return NA "Requires Entra ID P2 (Identity Protection) - not licensed." }
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (@($_.conditions.signInRiskLevels) -contains 'high') -and (CA-Grant $_ 'block') })
if ($p.Count -gt 0) { Pass "Sign-in-risk block policy: $(CA-Names $p)" } else { Fail "No enabled CA policy blocks high (and medium) sign-in risk." }
''', "UAC", "zt")
rule("5.2.2.9", ["graph.conditionalAccessPolicies"], r'''
if (-not $Ctx.HasIntune) { return NA "Requires Intune (device compliance) - not licensed." }
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (CA-AllApps $_) -and ((CA-Grant $_ 'compliantDevice') -or (CA-Grant $_ 'domainJoinedDevice')) })
if ($p.Count -gt 0) { Pass "Compliant/hybrid-joined device required for all users: $(CA-Names $p)" } else { Fail "No enabled CA policy requires a managed (compliant or hybrid-joined) device for all users on all resources." }
''', "SC", "zt")
rule("5.2.2.10", ["graph.conditionalAccessPolicies"], r'''
if (-not $Ctx.HasIntune) { return NA "Requires Intune (device compliance) - not licensed." }
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (@($_.conditions.applications.includeUserActions) -contains 'urn:user:registersecurityinfo') -and (CA-Grant $_ 'compliantDevice') })
if ($p.Count -gt 0) { Pass "Security-info registration requires a compliant device: $(CA-Names $p)" } else { Fail "No enabled CA policy requires a compliant device for the 'Register security information' user action." }
''', "UAC", "zt")
rule("5.2.2.11", ["graph.conditionalAccessPolicies"], r'''
if (-not $Ctx.HasIntune) { return NA "Requires Intune - not licensed." }
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (@($_.conditions.applications.includeApplications) -contains 'd4ebce55-015a-49b5-a083-c84d1797ae8c') -and $_.sessionControls.signInFrequency.frequencyInterval -eq 'everyTime' -and ((CA-Grant $_ 'mfa') -or $_.grantControls.authenticationStrength) })
if ($p.Count -gt 0) { Pass "Intune Enrollment app requires MFA every time: $(CA-Names $p)" } else { Fail "No enabled CA policy targets Microsoft Intune Enrollment (d4ebce55...) with sign-in frequency 'every time' and MFA." }
''', "SC", "device")
rule("5.2.2.12", ["graph.conditionalAccessPolicies"], r'''
$p = @(Get-CA | ? { (CA-AllUsers $_) -and ("$($_.conditions.authenticationFlows.transferMethods)" -match 'deviceCodeFlow') -and (CA-Grant $_ 'block') })
if ($p.Count -gt 0) { Pass "Device code flow blocked: $(CA-Names $p)" } else { Fail "No enabled CA policy blocks the device code authentication flow." }
''', "UAC", "mfa")
rule("5.2.2.13", ["graph.conditionalAccessPolicies"], r'''
$p = @(Get-CA | ? { (CA-AllUsers $_) -and (CA-AllApps $_) -and $_.sessionControls.signInFrequency.isEnabled -and $_.sessionControls.signInFrequency.frequencyInterval -eq 'timeBased' -and ((($_.sessionControls.signInFrequency.type -eq 'days') -and $_.sessionControls.signInFrequency.value -le 7) -or (($_.sessionControls.signInFrequency.type -eq 'hours') -and $_.sessionControls.signInFrequency.value -le 168)) })
if ($p.Count -gt 0) { Pass "Periodic re-authentication <= 7 days for all users: $(CA-Names $p)" } else { Fail "No enabled CA policy sets a sign-in frequency of 7 days or less for all users on all resources." }
''', "UAC", "zt")
rule("5.2.2.14", ["graph.namedLocations"], r'''
$n = @(Ev 'graph.namedLocations' | ? { $_.'@odata.type' -match 'ipNamedLocation' -and $_.isTrusted })
if ($n.Count -gt 0) { Pass "$($n.Count) trusted IP named location(s): $(($n.displayName) -join ', ')" } else { Fail "No trusted IP named locations are defined ($(@(Ev 'graph.namedLocations').Count) named locations in total)." }
''', "FW", "zt")
rule("5.2.2.15", ["graph.namedLocations","graph.conditionalAccessPolicies"], r'''
$geo = @(Ev 'graph.namedLocations' | ? { $_.'@odata.type' -match 'countryNamedLocation' })
$p = @(Get-CA | ? { (CA-Grant $_ 'block') -and (@($_.conditions.locations.includeLocations).Count -gt 0) })
if ($p.Count -gt 0 -and $geo.Count -gt 0) { Pass "Geographic block policy in force: $(CA-Names $p) using $(($geo.displayName) -join ', ')" }
elseif ($geo.Count -gt 0) { Partial "Country named location(s) exist ($(($geo.displayName) -join ', ')) but no enabled CA block policy uses a location condition." }
else { Fail "No country named locations and no location-based block policy." }
''', "FW", "zt")
rule("5.2.2.16", ["graph.conditionalAccessPolicies"], r'''
$p = @(Get-CA | ? { $_.sessionControls.secureSignInSession.isEnabled })
if ($p.Count -gt 0) { Pass "Token Protection session control enabled: $(CA-Names $p)" } else { Fail "No enabled CA policy applies Token Protection (secureSignInSession)." }
''', "UAC", "zt")
rule("5.2.2.17", ["graph.conditionalAccessPolicies"], r'''
$p = @(Get-CA | ? { (CA-AllUsers $_) -and ("$($_.conditions.authenticationFlows.transferMethods)" -match 'authenticationTransfer') -and (CA-Grant $_ 'block') })
if ($p.Count -gt 0) { Pass "Authentication transfer blocked: $(CA-Names $p)" } else { Fail "No enabled CA policy blocks the authentication transfer flow." }
''', "UAC", "mfa")

# Authentication methods ---------------------------------------------------
rule("5.2.3.1", ["graph.authenticationMethodsPolicy"], r'''
$m = Get-AuthMethod 'MicrosoftAuthenticator'
if (-not $m) { return Fail "Microsoft Authenticator configuration not found in the Authentication methods policy." }
if ($m.state -ne 'enabled') { return Fail "Microsoft Authenticator method state = $($m.state)." }
$app = $m.featureSettings.displayAppInformationRequiredState.state; $loc = $m.featureSettings.displayLocationInformationRequiredState.state
if ($app -eq 'enabled' -and $loc -eq 'enabled') { Pass "Authenticator enabled; displayAppInformationRequiredState = enabled; displayLocationInformationRequiredState = enabled." } else { Fail "Authenticator context settings: app information = $app, location = $loc (both must be enabled for all users)." }
''', "UAC", "mfa")
rule("5.2.3.2", ["graph.groupSettings"], r'''
$gs = Ev 'graph.groupSettings' | ? { $_.displayName -eq 'Password Rule Settings' } | Select -First 1
if (-not $gs) { return Fail "No 'Password Rule Settings' directory object - no custom banned password list." }
$v = @{}; $gs.values | % { $v[$_.name] = $_.value }
$n = @(($v['BannedPasswordList'] -split "`t|\r?\n") | ? { $_ }).Count
if ($v['EnableBannedPasswordCheck'] -match 'true' -and $n -gt 0) { Pass "Custom banned password check enabled with $n entries." } else { Fail "EnableBannedPasswordCheck = $($v['EnableBannedPasswordCheck']); list entries = $n." }
''', "UAC", "pwd")
rule("5.2.3.3", ["graph.groupSettings","graph.organization"], r'''
if (-not (One 'graph.organization').onPremisesSyncEnabled) { return NA "Cloud-only tenant." }
$gs = Ev 'graph.groupSettings' | ? { $_.displayName -eq 'Password Rule Settings' } | Select -First 1
$v = @{}; if ($gs) { $gs.values | % { $v[$_.name] = $_.value } }
if ($v['EnableBannedPasswordCheckOnPremises'] -match 'true' -and $v['BannedPasswordCheckOnPremisesMode'] -eq 'Enforce') { Pass "On-premises password protection enforced." } else { Fail "EnableBannedPasswordCheckOnPremises = $($v['EnableBannedPasswordCheckOnPremises']); mode = $($v['BannedPasswordCheckOnPremisesMode'])." }
''', "UAC", "pwd")
rule("5.2.3.4", ["graph.mfaRegistrationDetails"], r'''
$r = @(Ev 'graph.mfaRegistrationDetails' | ? { $_.userType -eq 'member' })
if ($r.Count -eq 0) { return Review "userRegistrationDetails returned no member users (needs Reports.Read.All / AuditLog.Read.All)." }
$not = @($r | ? { -not $_.isMfaCapable })
if ($not.Count -eq 0) { Pass "All $($r.Count) member users are MFA capable." } else { Fail "$($not.Count) of $($r.Count) member users are not MFA capable: $(($not.userPrincipalName | Select -First 12) -join ', ')" }
''', "UAC", "mfa")
rule("5.2.3.5", ["graph.authenticationMethodsPolicy"], r'''
$sms = (Get-AuthMethod 'Sms').state; $voice = (Get-AuthMethod 'Voice').state
if ($sms -eq 'disabled' -and $voice -eq 'disabled') { Pass "Sms = disabled; Voice = disabled." } elseif ($sms -eq 'disabled' -or $voice -eq 'disabled') { Partial "Sms = $sms; Voice = $voice (both should be disabled)." } else { Fail "Sms = $sms; Voice = $voice." }
''', "UAC", "mfa")
rule("5.2.3.6", ["graph.authenticationMethodsPolicy"], r'''
$s = (One 'graph.authenticationMethodsPolicy').systemCredentialPreferences
if (-not $s) { return Review "systemCredentialPreferences not returned (needs the beta authenticationMethodsPolicy endpoint) - check Entra > Authentication methods > Settings > System-preferred MFA." }
$all = @($s.includeTargets | ? { $_.id -eq 'all_users' }).Count -gt 0
if ($s.state -eq 'enabled' -and $all) { Pass "systemCredentialPreferences state = enabled, includeTargets = all_users." }
elseif ($s.state -eq 'default') { Partial "systemCredentialPreferences state = default (Microsoft-managed; currently behaves as enabled). CIS asks for an explicit 'enabled' with all users." }
else { Fail "systemCredentialPreferences state = $($s.state); all_users targeted = $all." }
''', "UAC", "mfa")
rule("5.2.3.7", ["graph.authenticationMethodsPolicy"], r'''
$e = (Get-AuthMethod 'Email').state
if ($e -eq 'disabled') { Pass "Email OTP = disabled." } else { Fail "Email OTP = $e." }
''', "UAC", "mfa")
rule("5.2.3.8", ["graph.groupSettings"], r'''
$gs = Ev 'graph.groupSettings' | ? { $_.displayName -eq 'Password Rule Settings' } | Select -First 1
$t = if ($gs) { ($gs.values | ? { $_.name -eq 'LockoutThreshold' }).value } else { $null }
if (-not $t) { Pass "No custom lockout threshold - Microsoft default of 10 applies." } elseif ([int]$t -le 10) { Pass "LockoutThreshold = $t." } else { Fail "LockoutThreshold = $t (CIS maximum 10)." }
''', "UAC", "pwd")
rule("5.2.3.9", ["graph.groupSettings"], r'''
$gs = Ev 'graph.groupSettings' | ? { $_.displayName -eq 'Password Rule Settings' } | Select -First 1
$d = if ($gs) { ($gs.values | ? { $_.name -eq 'LockoutDurationInSeconds' }).value } else { $null }
if (-not $d) { Pass "No custom lockout duration - Microsoft default of 60 seconds applies." } elseif ([int]$d -ge 60) { Pass "LockoutDurationInSeconds = $d." } else { Fail "LockoutDurationInSeconds = $d (CIS minimum 60)." }
''', "UAC", "pwd")
rule("5.2.3.10", ["graph.authenticationMethodsPolicy"], r'''
$m = Get-AuthMethod 'MicrosoftAuthenticator'; $v = $m.featureSettings.companionAppAllowedState.state
if (-not $v) { return Review "companionAppAllowedState not returned (beta endpoint) - check Entra > Authentication methods > Microsoft Authenticator > Configure > 'Microsoft Authenticator on companion applications'." }
if ($v -eq 'disabled') { Pass "companionAppAllowedState = disabled (Authenticator Lite off)." } elseif ($v -eq 'default') { Partial "companionAppAllowedState = default (Microsoft-managed - Authenticator Lite may be enabled). CIS expects an explicit 'disabled'." } else { Fail "companionAppAllowedState = $v." }
''', "UAC", "mfa")
rule("5.2.4.1", ["graph.authorizationPolicy"], r'''
$v = (One 'graph.authorizationPolicy').allowedToUseSSPR
if ($v) { Pass "authorizationPolicy allowedToUseSSPR = true." } else { Fail "allowedToUseSSPR = $v - self-service password reset is not enabled." }
''', "UAC", "pwd", "Entra admin centre > Password reset > Properties")
rule("5.2.4.2", [], None, "UAC", "pwd", "Entra admin centre > Password reset > Authentication methods > 'Number of methods required to reset' = 2")
rule("5.2.4.3", ["graph.authenticationMethodsPolicy"], r'''
$c = (One 'graph.authenticationMethodsPolicy').registrationEnforcement.authenticationMethodsRegistrationCampaign
if ($c.state -eq 'enabled') { Review "Registration campaign enabled (snoozeDuration $($c.snoozeDurationInDays) days). Also confirm Entra > Password reset > Registration: 'Require users to register when signing in' = Yes and re-confirm <= 180 days." }
else { Manual "Entra admin centre > Password reset > Registration: 'Require users to register when signing in' = Yes; 'Number of days before users are asked to re-confirm' <= 180. (Registration campaign state = $($c.state))" }
''', "UAC", "pwd", "Entra admin centre > Password reset > Registration")
rule("5.2.4.4", [], None, "UAC", "pwd", "Entra admin centre > Password reset > Notifications > 'Notify users on password resets' = Yes")
rule("5.2.4.5", [], None, "UAC", "pwd", "Entra admin centre > Password reset > Notifications > 'Notify all admins when other admins reset their password' = Yes")

rule("5.3.1", ["graph.roleAssignmentSchedules","graph.roleEligibilitySchedules","graph.directoryRoles"], r'''
if (-not $Ctx.HasP2) { return NA "Privileged Identity Management requires Entra ID P2 (not licensed). Standing assignments: $(@(Get-AdminUsers).Count) role-holding accounts." }
$perm = @(Ev 'graph.roleAssignmentSchedules' | ? { $_.assignmentType -eq 'Assigned' -and ($_.scheduleInfo.expiration.type -eq 'noExpiration' -or -not $_.scheduleInfo.expiration.endDateTime) -and $_.roleDefinitionId -in $Ctx.PrivilegedRoleIds })
$users = Ev 'graph.users'; $names = @(); foreach ($a in $perm) { $u = $users | ? { $_.id -eq $a.principalId } | Select -First 1; if ($u -and $u.userPrincipalName -notin $Ctx.BreakGlass) { $names += $u.userPrincipalName } }
$names = $names | Select -Unique
if ($names.Count -eq 0) { Pass "No permanent active privileged role assignments outside break-glass; $(@(Ev 'graph.roleEligibilitySchedules').Count) PIM-eligible assignments." } else { Fail "$($names.Count) accounts hold permanent active privileged roles: $(($names | Select -First 10) -join ', ')" }
''', "UAC", "admin")
rule("5.3.2", ["graph.accessReviewDefinitions"], r'''
if (-not $Ctx.HasP2) { return NA "Access reviews require Entra ID P2 / ID Governance (not licensed)." }
$r = @(Ev 'graph.accessReviewDefinitions' | ? { $_.status -ne 'Completed' -and ("$($_.scope | ConvertTo-Json -Depth 4)" -match 'Guest|guest') })
if ($r.Count -gt 0) { Pass "$($r.Count) active access review(s) scoped to guests: $(($r.displayName) -join ', ')" } else { Fail "No active access review targets guest users." }
''', "UAC", "admin")
rule("5.3.3", ["graph.accessReviewDefinitions"], r'''
if (-not $Ctx.HasP2) { return NA "Access reviews require Entra ID P2 (not licensed)." }
$r = @(Ev 'graph.accessReviewDefinitions' | ? { $_.status -ne 'Completed' -and ("$($_.scope | ConvertTo-Json -Depth 4)" -match 'roleManagement|directoryRole|RoleDefinition') })
if ($r.Count -gt 0) { Pass "$($r.Count) active access review(s) of privileged roles: $(($r.displayName) -join ', ')" } else { Fail "No active access review targets privileged role assignments." }
''', "UAC", "admin")
rule("5.3.4", ["graph.roleManagementPolicyAssignments"], r'''
if (-not $Ctx.HasP2) { return NA "PIM approval requires Entra ID P2 (not licensed)." }
$ok = Test-PimApproval '62e90394-69f5-4237-9190-012177145e10'
if ($ok -eq $true) { Pass "PIM policy for Global Administrator requires approval on activation." } elseif ($null -eq $ok) { Review "PIM policy for Global Administrator not returned." } else { Fail "PIM policy for Global Administrator does not require approval (isApprovalRequired = false)." }
''', "UAC", "admin")
rule("5.3.5", ["graph.roleManagementPolicyAssignments"], r'''
if (-not $Ctx.HasP2) { return NA "PIM approval requires Entra ID P2 (not licensed)." }
$ok = Test-PimApproval 'e8611ab8-c189-46e8-94e1-60213ab1f814'
if ($ok -eq $true) { Pass "PIM policy for Privileged Role Administrator requires approval." } elseif ($null -eq $ok) { Review "PIM policy for Privileged Role Administrator not returned." } else { Fail "PIM policy for Privileged Role Administrator does not require approval." }
''', "UAC", "admin")

# ---- 6  Exchange ------------------------------------------------------------
rule("6.1.1", ["exo.organizationConfig"], r'''
$o = One 'exo.organizationConfig'
if ($o.AuditDisabled -eq $false) { Pass "organizationConfig: AuditDisabled = False." } else { Fail "organizationConfig: AuditDisabled = $($o.AuditDisabled)." }
''', "-", "log")
rule("6.1.2", ["exo.mailboxes"], r'''
$m = @(Ev 'exo.mailboxes' | ? { $_.RecipientTypeDetails -in 'UserMailbox','SharedMailbox' })
$off = @($m | ? { -not $_.AuditEnabled })
if ($off.Count -eq 0) { Pass "AuditEnabled = True on all $($m.Count) user and shared mailboxes." } else { Fail "$($off.Count) of $($m.Count) mailboxes have AuditEnabled = False: $(($off.PrimarySmtpAddress | Select -First 10) -join ', ')" }
''', "-", "log")
rule("6.1.3", ["exo.mailboxAuditBypass"], r'''
$b = @(Ev 'exo.mailboxAuditBypass' | ? { $_.AuditBypassEnabled })
if ($b.Count -eq 0) { Pass "No mailbox audit bypass associations ($(@(Ev 'exo.mailboxAuditBypass').Count) checked)." } else { Fail "$($b.Count) accounts bypass mailbox auditing: $(($b.Identity | Select -First 10) -join ', ')" }
''', "-", "log")
rule("6.2.1", ["exo.remoteDomain","exo.hostedOutboundSpam","exo.transportRules","exo.mailboxes"], r'''
$rd = @(Ev 'exo.remoteDomain' | ? { $_.AutoForwardEnabled })
$os = @(Ev 'exo.hostedOutboundSpam' | ? { $_.AutoForwardingMode -ne 'Off' })
$tr = @(Ev 'exo.transportRules' | ? { $_.State -eq 'Enabled' -and ($_.RedirectMessageTo -or $_.BlindCopyTo) })
$fw = @(Ev 'exo.mailboxes' | ? { $_.ForwardingSmtpAddress })
if ($rd.Count -eq 0 -and $os.Count -eq 0) { $txt = "Remote domains AutoForwardEnabled = False; outbound spam AutoForwardingMode = Off."; if ($tr.Count -or $fw.Count) { Partial "$txt But $($tr.Count) transport rule(s) redirect/BCC and $($fw.Count) mailbox(es) have ForwardingSmtpAddress set." } else { Pass $txt } }
else { Fail "Auto-forwarding permitted: remote domains with AutoForwardEnabled = $(($rd.DomainName) -join ','); outbound spam AutoForwardingMode = $(($os | % { "$($_.Name)=$($_.AutoForwardingMode)" }) -join ','); mailboxes forwarding externally = $($fw.Count)." }
''', "SC", "email")
rule("6.2.2", ["exo.transportRules"], r'''
$r = @(Ev 'exo.transportRules' | ? { $_.State -eq 'Enabled' -and $_.SetSCL -eq -1 -and $_.SenderDomainIs })
if ($r.Count -eq 0) { Pass "No enabled transport rule sets SCL -1 for sender domains ($(@(Ev 'exo.transportRules').Count) rules checked)." } else { Fail "Transport rules whitelist sender domains (SCL -1): $(($r | % { "$($_.Name) [$($_.SenderDomainIs -join ',')]" }) -join '; ')" }
''', "MP", "phish")
rule("6.2.3", ["exo.externalInOutlook"], r'''
$e = One 'exo.externalInOutlook'
if ($e.Enabled) { Pass "externalInOutlook Enabled = True (allow list: $(@($e.AllowList).Count) entries)." } else { Fail "externalInOutlook Enabled = $($e.Enabled)." }
''', "MP", "phish")
rule("6.3.1", ["exo.roleAssignmentPolicy"], r'''
$p = @(Ev 'exo.roleAssignmentPolicy')
$bad = @($p | ? { ($_.AssignedRoles -join ',') -match 'My Custom Apps|My Marketplace Apps|My ReadWriteMailbox Apps' })
if ($bad.Count -eq 0) { Pass "No role assignment policy grants the add-in roles." } else { Fail "Add-in installation roles granted by: $(($bad | % { "$($_.Name) [$((@($_.AssignedRoles) | ? { $_ -match 'Apps' }) -join ', ')]" }) -join '; ')" }
''', "SC", "saas")
rule("6.3.2", ["exo.owaMailboxPolicy"], r'''
$d = @(Ev 'exo.owaMailboxPolicy' | ? { $_.IsDefault }) ; if (-not $d) { $d = @(Ev 'exo.owaMailboxPolicy' | Select -First 1) }
$p = $d[0]
if ($p.PersonalAccountsEnabled -eq $false -and $p.PersonalAccountCalendarsEnabled -eq $false) { Pass "'$($p.Name)': PersonalAccountsEnabled = False; PersonalAccountCalendarsEnabled = False." } else { Fail "'$($p.Name)': PersonalAccountsEnabled = $($p.PersonalAccountsEnabled); PersonalAccountCalendarsEnabled = $($p.PersonalAccountCalendarsEnabled)." }
''', "SC", "saas")
rule("6.5.1", ["exo.organizationConfig"], r'''
if ((One 'exo.organizationConfig').OAuth2ClientProfileEnabled) { Pass "OAuth2ClientProfileEnabled = True." } else { Fail "OAuth2ClientProfileEnabled = False." }
''', "UAC", "mfa")
rule("6.5.2", ["exo.organizationConfig"], r'''
$o = One 'exo.organizationConfig'
if ($o.MailTipsAllTipsEnabled -and $o.MailTipsExternalRecipientsTipsEnabled -and $o.MailTipsGroupMetricsEnabled -and $o.MailTipsLargeAudienceThreshold -le 25) { Pass "MailTips all enabled; LargeAudienceThreshold = $($o.MailTipsLargeAudienceThreshold)." } else { Fail "MailTipsAllTipsEnabled = $($o.MailTipsAllTipsEnabled); External = $($o.MailTipsExternalRecipientsTipsEnabled); GroupMetrics = $($o.MailTipsGroupMetricsEnabled); LargeAudienceThreshold = $($o.MailTipsLargeAudienceThreshold)." }
''', "SC", "email")
rule("6.5.3", ["exo.owaMailboxPolicy"], r'''
$d = @(Ev 'exo.owaMailboxPolicy' | ? { $_.IsDefault -or $_.Name -eq 'OwaMailboxPolicy-Default' }) ; if (-not $d) { $d = @(Ev 'exo.owaMailboxPolicy' | Select -First 1) }
if ($d[0].AdditionalStorageProvidersAvailable -eq $false) { Pass "'$($d[0].Name)': AdditionalStorageProvidersAvailable = False." } else { Fail "'$($d[0].Name)': AdditionalStorageProvidersAvailable = $($d[0].AdditionalStorageProvidersAvailable)." }
''', "SC", "saas")
rule("6.5.4", ["exo.transportConfig"], r'''
if ((One 'exo.transportConfig').SmtpClientAuthenticationDisabled) { Pass "transportConfig: SmtpClientAuthenticationDisabled = True." } else { Fail "SmtpClientAuthenticationDisabled = False - SMTP AUTH is enabled organisation-wide." }
''', "UAC", "mfa")
rule("6.5.5", ["exo.organizationConfig"], r'''
if ((One 'exo.organizationConfig').RejectDirectSend) { Pass "organizationConfig: RejectDirectSend = True." } else { Fail "RejectDirectSend = False - unauthenticated Direct Send is accepted." }
''', "SC", "email")

# ---- 7  SharePoint ----------------------------------------------------------
rule("7.2.1", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; $g = One 'graph.sharePointSettings'
$v = if ($t) { $t.LegacyAuthProtocolsEnabled } else { $g.isLegacyAuthProtocolsEnabled }
if ($v -eq $false) { Pass "LegacyAuthProtocolsEnabled = False." } elseif ($null -eq $v) { Manual "Run Get-SPOTenant | fl LegacyAuthProtocolsEnabled." } else { Fail "LegacyAuthProtocolsEnabled = True." }
''', "UAC", "mfa")
rule("7.2.2", ["spo.tenant"], r'''
$t = One 'spo.tenant'; if (-not $t) { return Manual "Get-SPOTenant | fl EnableAzureADB2BIntegration (requires SharePoint Online PowerShell)." }
if ($t.EnableAzureADB2BIntegration) { Pass "EnableAzureADB2BIntegration = True." } else { Fail "EnableAzureADB2BIntegration = False." }
''', "UAC", "saas")
rule("7.2.3", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; $g = One 'graph.sharePointSettings'
$v = if ($t) { "$($t.SharingCapability)" } else { "$($g.sharingCapability)" }
if ($v -in 'Disabled','ExistingExternalUserSharingOnly','ExternalUserSharingOnly','disabled','existingExternalUserSharingOnly','externalUserSharingOnly') { Pass "SharingCapability = $v." } else { Fail "SharingCapability = $v (anonymous 'Anyone' links permitted)." }
''', "UAC", "data")
rule("7.2.4", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; if (-not $t) { return Manual "Get-SPOTenant | fl OneDriveSharingCapability (expect Disabled for Level 2)." }
$v = "$($t.OneDriveSharingCapability)"
if ($v -eq 'Disabled') { Pass "OneDriveSharingCapability = Disabled." } elseif ($v -in 'ExistingExternalUserSharingOnly','ExternalUserSharingOnly') { Partial "OneDriveSharingCapability = $v (restricted but not Disabled, which CIS L2 expects)." } else { Fail "OneDriveSharingCapability = $v." }
''', "UAC", "data")
rule("7.2.5", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; $g = One 'graph.sharePointSettings'
$v = if ($t) { $t.PreventExternalUsersFromResharing } elseif ($null -ne $g.isResharingByExternalUsersEnabled) { -not $g.isResharingByExternalUsersEnabled } else { $null }
if ($v -eq $true) { Pass "PreventExternalUsersFromResharing = True." } elseif ($null -eq $v) { Manual "Get-SPOTenant | fl PreventExternalUsersFromResharing." } else { Fail "External users can re-share content (PreventExternalUsersFromResharing = False)." }
''', "UAC", "data")
rule("7.2.6", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; $g = One 'graph.sharePointSettings'
$mode = if ($t) { "$($t.SharingDomainRestrictionMode)" } else { "$($g.sharingDomainRestrictionMode)" }
$cap = if ($t) { "$($t.SharingCapability)" } else { "$($g.sharingCapability)" }
if ($cap -in 'Disabled','disabled') { Pass "External sharing is disabled, so domain restriction is moot." } elseif ($mode -in 'AllowList','allowList') { Pass "SharingDomainRestrictionMode = AllowList." } elseif ($mode -in 'BlockList','blockList') { Partial "SharingDomainRestrictionMode = BlockList (CIS prefers an allow list)." } else { Fail "SharingDomainRestrictionMode = $mode - no domain restriction on external sharing." }
''', "UAC", "data")
rule("7.2.7", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; $g = One 'graph.sharePointSettings'
$v = if ($t) { "$($t.DefaultSharingLinkType)" } else { "$($g.defaultSharingLinkType)" }
if ($v -in 'Direct','direct','specificPeople') { Pass "DefaultSharingLinkType = $v (specific people)." } else { Fail "DefaultSharingLinkType = $v." }
''', "UAC", "data")
rule("7.2.8", ["spo.tenant"], r'''
$t = One 'spo.tenant'; if (-not $t) { return Manual "SharePoint admin centre > Policies > Sharing > More external sharing settings > 'Allow only users in specific security groups to share externally'." }
if ("$($t.SharingCapability)" -eq 'Disabled') { return Pass "External sharing disabled - control satisfied." }
$v = @($t.WhoCanShareAllowListInTenant) + @($t.WhoCanShareAllowListInTenantByPrincipalIdentity) | ? { $_ }
if ($v.Count -gt 0) { Pass "External sharing limited to $($v.Count) security group(s)." } else { Fail "No security group restriction on who can share externally." }
''', "UAC", "data")
rule("7.2.9", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; $g = One 'graph.sharePointSettings'
$req = if ($t) { $t.ExternalUserExpirationRequired } else { $g.isSharingExpirationEnabled }
$days = if ($t) { $t.ExternalUserExpireInDays } else { $g.sharingExpirationInDays }
if ($req -and $days -le 30) { Pass "External user expiration required after $days days." } elseif ($req) { Partial "External user expiration enabled but set to $days days (CIS: 30 or fewer)." } else { Fail "ExternalUserExpirationRequired = $req - guest access never expires." }
''', "UAC", "data")
rule("7.2.10", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; $g = One 'graph.sharePointSettings'
$req = if ($t) { $t.EmailAttestationRequired } else { $g.isRequireAcceptingUserToMatchInvitedUserEnabled }
$days = if ($t) { $t.EmailAttestationReAuthDays } else { $null }
if ($t) { if ($req -and $days -le 15) { Pass "EmailAttestationRequired = True; re-authentication every $days days." } elseif ($req) { Partial "EmailAttestationRequired = True but EmailAttestationReAuthDays = $days (CIS: 15 or fewer)." } else { Fail "EmailAttestationRequired = False." } }
else { Manual "Get-SPOTenant | fl EmailAttestationRequired, EmailAttestationReAuthDays." }
''', "UAC", "data")
rule("7.2.11", ["spo.tenant","graph.sharePointSettings"], r'''
$t = One 'spo.tenant'; $g = One 'graph.sharePointSettings'
$v = if ($t) { "$($t.DefaultLinkPermission)" } else { "$($g.defaultLinkPermission)" }
if ($v -in 'View','view') { Pass "DefaultLinkPermission = View." } else { Fail "DefaultLinkPermission = $v." }
''', "UAC", "data")
rule("7.3.1", ["spo.tenant"], r'''
if (-not $Ctx.HasMDO1) { return NA "Requires Defender for Office 365 (not licensed)." }
$t = One 'spo.tenant'; if (-not $t) { return Manual "Get-SPOTenant | fl DisallowInfectedFileDownload." }
if ($t.DisallowInfectedFileDownload) { Pass "DisallowInfectedFileDownload = True." } else { Fail "DisallowInfectedFileDownload = False." }
''', "MP", "phish")

# ---- 8  Teams ---------------------------------------------------------------
rule("8.1.1", ["teams.clientConfiguration"], r'''
$c = One 'teams.clientConfiguration'; $on = @(); foreach ($p in 'AllowDropBox','AllowBox','AllowGoogleDrive','AllowShareFile','AllowEgnyte') { if ($c.$p) { $on += $p } }
if ($on.Count -eq 0) { Pass "All third-party storage providers disabled in Teams." } else { Fail "Third-party storage enabled in Teams: $($on -join ', ')" }
''', "SC", "saas")
rule("8.1.2", ["teams.clientConfiguration"], r'''
if ((One 'teams.clientConfiguration').AllowEmailIntoChannel -eq $false) { Pass "AllowEmailIntoChannel = False." } else { Fail "AllowEmailIntoChannel = True." }
''', "MP", "phish")
rule("8.2.1", ["teams.federationConfiguration"], r'''
$f = One 'teams.federationConfiguration'; $ad = "$($f.AllowedDomains)"
if ($f.AllowFederatedUsers -eq $false) { Pass "AllowFederatedUsers = False (external access off)." } elseif ($ad -notmatch 'AllowAllKnownDomains' -and $ad) { Pass "External access limited to an allow list: $ad" } else { Fail "AllowFederatedUsers = True with AllowedDomains = AllowAllKnownDomains (open federation)." }
''', "UAC", "saas")
rule("8.2.2", ["teams.federationConfiguration"], r'''
if ((One 'teams.federationConfiguration').AllowTeamsConsumer -eq $false) { Pass "AllowTeamsConsumer = False." } else { Fail "AllowTeamsConsumer = True - users can chat with personal Teams accounts." }
''', "UAC", "saas")
rule("8.2.3", ["teams.federationConfiguration"], r'''
if ((One 'teams.federationConfiguration').AllowTeamsConsumerInbound -eq $false) { Pass "AllowTeamsConsumerInbound = False." } else { Fail "AllowTeamsConsumerInbound = True - unmanaged users can initiate contact." }
''', "UAC", "saas")
rule("8.2.4", ["teams.federationConfiguration"], r'''
$v = "$((One 'teams.federationConfiguration').ExternalAccessWithTrialTenants)"
if ($v -eq 'Blocked') { Pass "ExternalAccessWithTrialTenants = Blocked." } else { Fail "ExternalAccessWithTrialTenants = $v." }
''', "UAC", "saas")
rule("8.4.1", ["teams.appPermissionPolicy"], r'''
$g = @(Ev 'teams.appPermissionPolicy' | ? { $_.Identity -match 'Global' }) | Select -First 1
Manual "Teams admin centre > Teams apps > Manage apps > Actions > Org-wide app settings: Third-party apps 'Let users install and use available apps by default' = Off; Custom apps = Off; custom apps in preview = Off. (Legacy Global app permission policy: default=$($g.DefaultCatalogAppsType) global=$($g.GlobalCatalogAppsType) private=$($g.PrivateCatalogAppsType))"
''', "SC", "saas", "Teams admin centre > Teams apps > Manage apps > Org-wide app settings")
def teams_mp(prop, want, passtxt=None, l2=False):
    return r'''
$g = Get-TeamsGlobalMeetingPolicy
$v = "$($g.%s)"
if ($v -eq '%s') { Pass "meetingPolicy Global: %s = $v." } else { Fail "meetingPolicy Global: %s = $v (expected %s)." }
''' % (prop, want, prop, prop, want)
rule("8.5.1", ["teams.meetingPolicy"], teams_mp("AllowAnonymousUsersToJoinMeeting","False"), "UAC", "saas")
rule("8.5.2", ["teams.meetingPolicy"], teams_mp("AllowAnonymousUsersToStartMeeting","False"), "UAC", "saas")
rule("8.5.3", ["teams.meetingPolicy"], teams_mp("AutoAdmittedUsers","EveryoneInCompanyExcludingGuests"), "UAC", "saas")
rule("8.5.4", ["teams.meetingPolicy"], teams_mp("AllowPSTNUsersToBypassLobby","False"), "UAC", "saas")
rule("8.5.5", ["teams.meetingPolicy"], teams_mp("MeetingChatEnabledType","EnabledExceptAnonymous"), "UAC", "saas")
rule("8.5.6", ["teams.meetingPolicy"], teams_mp("DesignatedPresenterRoleMode","OrganizerOnlyUserOverride"), "UAC", "saas")
rule("8.5.7", ["teams.meetingPolicy"], teams_mp("AllowExternalParticipantGiveRequestControl","False"), "UAC", "saas")
rule("8.5.8", ["teams.meetingPolicy"], teams_mp("AllowExternalNonTrustedMeetingChat","False"), "UAC", "saas")
rule("8.5.9", ["teams.meetingPolicy"], teams_mp("AllowCloudRecording","False"), "-", "data")
rule("8.6.1", ["teams.messagingPolicy","exo.reportSubmissionPolicy"], r'''
$m = @(Ev 'teams.messagingPolicy' | ? { $_.Identity -match 'Global' }) | Select -First 1
$r = One 'exo.reportSubmissionPolicy'
$teamsOn = $m.AllowSecurityEndUserReporting -eq $true
$defOn = $r.EnableReportToMicrosoft -or ($r.ReportJunkToCustomizedAddress -and $r.ReportPhishToCustomizedAddress)
if ($teamsOn -and $defOn) { Pass "Teams AllowSecurityEndUserReporting = True; Defender user-reported settings enabled (ReportToMicrosoft = $($r.EnableReportToMicrosoft); custom address = $($r.ReportPhishAddresses -join ','))." }
elseif ($teamsOn -or $defOn) { Partial "Teams reporting = $teamsOn; Defender user-reported settings = $defOn - both are required." }
else { Fail "Users cannot report malicious messages: Teams AllowSecurityEndUserReporting = $($m.AllowSecurityEndUserReporting); Defender reporting disabled." }
''', "MP", "phish")

# ---- 9  Fabric --------------------------------------------------------------
def fabric(setting, want_enabled=False, allow_groups=True):
    return r'''
if (-not $Ctx.HasFabric) { return NA "No Power BI / Fabric licence or capacity in the tenant; the Fabric admin portal is not provisioned." }
$s = Get-FabricSetting '%s'
if (-not $s) { return Manual "Fabric admin portal > Tenant settings: locate '%s' (collector could not read tenant settings - needs Fabric Administrator)." }
$grp = @($s.enabledSecurityGroups).Count -gt 0
if ($s.enabled -eq %s) { Pass "%s enabled = $($s.enabled)." }
elseif (%s -and $s.enabled -and $grp) { Pass "%s enabled for specific security groups only ($(@($s.enabledSecurityGroups).Count))." }
else { Fail "%s enabled = $($s.enabled) for the whole organisation." }
''' % (setting, setting, '$true' if want_enabled else '$false', setting, '$true' if allow_groups else '$false', setting, setting)
rule("9.1.1", ["fabric.tenantSettings"], fabric("AllowGuestUserToAccessSharedContent"), "UAC", "saas")
rule("9.1.2", ["fabric.tenantSettings"], fabric("ExternalSharingV2"), "UAC", "saas")
rule("9.1.3", ["fabric.tenantSettings"], fabric("ElevatedGuestsTenant"), "UAC", "saas")
rule("9.1.4", ["fabric.tenantSettings"], fabric("PublishToWeb"), "UAC", "data")
rule("9.1.5", ["fabric.tenantSettings"], fabric("RScriptVisual", allow_groups=False), "SC", "saas")
rule("9.1.6", ["fabric.tenantSettings"], fabric("EimInformationProtectionEdit", want_enabled=True), "-", "data")
rule("9.1.7", ["fabric.tenantSettings"], fabric("ShareLinkToEntireOrg"), "UAC", "data")
rule("9.1.8", ["fabric.tenantSettings"], fabric("EnableDatasetInPlaceSharing"), "UAC", "data")
rule("9.1.9", ["fabric.tenantSettings"], fabric("BlockResourceKeyAuthentication", want_enabled=True, allow_groups=False), "UAC", "saas")
rule("9.1.10", ["fabric.tenantSettings"], fabric("ServicePrincipalAccessPermissionAPIs"), "UAC", "saas")
rule("9.1.11", ["fabric.tenantSettings"], fabric("AllowServicePrincipalsCreateAndUseProfiles"), "UAC", "saas")
rule("9.1.12", ["fabric.tenantSettings"], fabric("ServicePrincipalAccessGlobalAPIs"), "UAC", "saas")

# ---------------------------------------------------------------------------
missing = [x["Id"] for x in SRC if x["Id"] not in R]
assert not missing, f"rules missing for: {missing}"
assert all(k in SHORT for k in R), "short titles missing"

def refs(s):
    return [u for u in re.split(r":(?=https?)", s or "") if u.startswith("http")]

controls = []
for x in SRC:
    a = x["Attributes"][0]; r = R[x["Id"]]
    prof = a["Profile"]  # e.g. "E3 Level 1"
    level = "L2" if "Level 2" in prof else "L1"
    lic = "E5" if prof.startswith("E5") else "E3"
    ncsc_t, ncsc_u = NCSC[r["ncsc"]]
    controls.append({
        "id": x["Id"], "title": SHORT[x["Id"]], "level": level, "licenceProfile": lic,
        "section": a["Section"], "subSection": a["SubSection"],
        "assessment": a["AssessmentStatus"],
        "description": a["Description"], "rationale": a["RationaleStatement"],
        "impact": a["ImpactStatement"], "audit": a["AuditProcedure"],
        "remediation": a["RemediationProcedure"], "defaultValue": a["DefaultValue"],
        "references": refs(a["References"]),
        "ceArea": CE_AREAS[r["ce"]], "ncscTitle": ncsc_t, "ncscUrl": ncsc_u,
        "evidenceKeys": r["keys"], "portal": r["portal"],
        "test": (r["test"].strip() if r["test"] else None),
    })

os.makedirs("out/2-Scripts/controls", exist_ok=True)
json.dump({"benchmark": "CIS Microsoft 365 Foundations Benchmark v7.0.0", "controlCount": len(controls),
           "generated": "2026-10-21", "controls": controls},
          open("out/2-Scripts/controls/cis-m365-v7-controls.json", "w"), indent=1)
print("controls:", len(controls), "automated tests:", sum(1 for c in controls if c["test"]),
      "manual:", sum(1 for c in controls if not c["test"]))
