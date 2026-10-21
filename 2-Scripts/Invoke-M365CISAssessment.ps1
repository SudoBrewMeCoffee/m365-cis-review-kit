<#
.SYNOPSIS
    Scores collected evidence against all 160 CIS Microsoft 365 Foundations Benchmark v7.0.0 controls
    and writes the findings register (Excel), a report draft (HTML, opens in Word) and a results JSON.

.DESCRIPTION
    Reads every *.json produced by Get-M365CISEvidence.ps1 in -EvidencePath (they are merged, so a
    workload re-run with -Only is picked up automatically), builds the licence context, evaluates each
    control's test from controls\cis-m365-v7-controls.json and produces:

      <Client>-CIS-M365-v7-Findings-Register.xlsx   5 sheets: Summary, Register, Findings, Licensing & scope, Evidence gaps
      <Client>-M365-Security-Review-DRAFT.html       the report draft in the standard structure - open in Word, Save As .docx
      <Client>-assessment-results.json               machine-readable results (for re-runs and trend)

    Makes NO network calls and NO changes. The evidence folder is the only input.

    Status values: Pass | Fail | Partial | N/A | Manual | Review | Not assessed
      Manual   = portal-only control: read it by hand and overwrite the status in the Register sheet
      Review   = the test found something that needs a human judgement (text explains what)
      Not assessed = the evidence the test needed was not collected (collector error / permission)

.PARAMETER EvidencePath
    Folder containing the evidence JSON file(s), or a single JSON file.
.PARAMETER ClientName
    Client name for file names and report title. Default: taken from the evidence meta.
.PARAMETER BreakGlassAccounts
    UPNs of the agreed emergency-access accounts. Used by 1.1.2, 1.1.4, 2.2.1 and 5.3.1.
.PARAMETER PreparedBy
    Name and organisation printed on the report cover, e.g. "Jane Smith, Example Consulting".
.PARAMETER PreparedFor
    Recipient printed on the cover, e.g. "Jane Smith, Contoso Ltd".
.PARAMETER OutputPath
    Folder for the outputs. Default: .\Output
.PARAMETER PreviousResults
    Optional path to an earlier <Client>-assessment-results.json to show status-vs-previous in the register.

.EXAMPLE
    .\Invoke-M365CISAssessment.ps1 -EvidencePath .\Evidence -ClientName Contoso -PreparedBy "Jane Smith, Example Consulting" -PreparedFor "IT Director, Contoso" -BreakGlassAccounts bg1@contoso.onmicrosoft.com,bg2@contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $EvidencePath,
    [string] $ClientName,
    [string[]] $BreakGlassAccounts = @(),
    [string] $PreparedBy = 'Reviewer',
    [string] $PreparedFor = '',
    [string] $OutputPath = (Join-Path (Get-Location).Path 'Output'),
    [string] $PreviousResults
)
$ErrorActionPreference = 'Stop'
$KitVersion = '1.0'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# ------------------------------------------------------------------ load evidence
# JSON is parsed as hashtables (Exchange/Teams objects can contain keys that differ only by case, which the
# PSObject parser rejects) and then converted to PSCustomObjects so the pipeline cmdlets behave normally.
# On a case collision the first key wins and the duplicate is dropped.
function ConvertTo-ObjectTree($v) {
    if ($v -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $v.Keys) { if (-not $o.Contains("$k")) { $o["$k"] = ConvertTo-ObjectTree $v[$k] } }
        return [pscustomobject]$o
    }
    if ($v -is [System.Collections.IList] -and $v -isnot [string]) { $a = [System.Collections.ArrayList]::new(); foreach ($i in $v) { [void]$a.Add((ConvertTo-ObjectTree $i)) } ; return ,$a.ToArray() }
    return $v
}
$files = if (Test-Path $EvidencePath -PathType Container) { Get-ChildItem $EvidencePath -Filter *.json | Sort-Object LastWriteTime } else { Get-Item $EvidencePath }
if (-not $files) { throw "No evidence JSON found at $EvidencePath" }
$E = @{}; $errors = @(); $meta = $null
foreach ($f in $files) {
    Write-Host "Loading $($f.Name)" -ForegroundColor DarkGray
    $j = Get-Content $f.FullName -Raw -Encoding utf8 | ConvertFrom-Json -Depth 30 -AsHashtable
    foreach ($k in @($j.Keys)) {
        $v = ConvertTo-ObjectTree $j[$k]
        if ($k -eq 'meta') { if (-not $meta) { $meta = $v } else { $meta.workloads = @(@($meta.workloads) + @($v.workloads) | Select-Object -Unique) } ; continue }
        if ($k -eq 'errors') { $errors += @($v); continue }
        $E[$k] = $(if ($null -eq $v) { @() } else { $v })
    }
}
if (-not $ClientName) { $ClientName = if ($meta.clientName) { $meta.clientName } else { 'Tenant' } }
$collectedDate = if ($meta.collectedUtc) { ([datetime]$meta.collectedUtc).ToString('d MMMM yyyy') } else { (Get-Date).ToString('d MMMM yyyy') }
$today = (Get-Date).ToString('d MMMM yyyy')

# ------------------------------------------------------------------ helpers available to tests
function Ev([string]$k) { if ($E.ContainsKey($k)) { return @($E[$k]) } ; return @() }
function Has([string]$k) { return $E.ContainsKey($k) }
function One([string]$k) { $a = Ev $k; if ($a.Count -gt 0) { return $a[0] } ; return $null }
function Res($s, $t) { [pscustomobject]@{ Status = $s; Evidence = "$t" } }
function Pass($t)    { Res 'Pass' $t }
function Fail($t)    { Res 'Fail' $t }
function Partial($t) { Res 'Partial' $t }
function NA($t)      { Res 'N/A' $t }
function Manual($t)  { Res 'Manual' $t }
function Review($t)  { Res 'Review' $t }

# licence context ----------------------------------------------------------
$plans = @()
foreach ($s in (Ev 'graph.subscribedSkus')) { if ($s.capabilityStatus -in 'Enabled','Warning' -and $s.prepaidUnits.enabled -gt 0) { $plans += @($s.servicePlans | ? { $_.provisioningStatus -ne 'Disabled' } | % { $_.servicePlanName }) } }
$plans = $plans | Select-Object -Unique
$skus = @(Ev 'graph.subscribedSkus' | ? { $_.prepaidUnits.enabled -gt 0 } | % { "$($_.skuPartNumber) ($($_.consumedUnits)/$($_.prepaidUnits.enabled))" })
$org = One 'graph.organization'
$Ctx = [pscustomobject]@{
    HasP1 = [bool]($plans -match '^AAD_PREMIUM$|^AAD_PREMIUM_P2$').Count
    HasP2 = [bool]($plans -match '^AAD_PREMIUM_P2$').Count
    HasMDO1 = [bool]($plans -match '^ATP_ENTERPRISE|^THREAT_INTELLIGENCE').Count
    HasMDO2 = [bool]($plans -match '^THREAT_INTELLIGENCE').Count
    HasIntune = [bool]($plans -match '^INTUNE_A|^INTUNE_P|^INTUNE_EDU').Count
    HasMDCA = [bool]($plans -match '^ADALLOM_S_STANDALONE|^ADALLOM_S_O365|^ADALLOM_STANDALONE').Count
    HasLockbox = [bool]($plans -match 'LOCKBOX').Count
    HasE5Compliance = [bool]($plans -match '^MIP_S_CLP2|^M365_ADVANCED_AUDITING|^INFORMATION_BARRIERS|^COMMUNICATIONS_DLP').Count
    HasFabric = ([bool]($plans -match '^BI_AZURE|^PBI_|^POWER_BI|^FABRIC').Count) -or (Has 'fabric.tenantSettings')
    Hybrid = [bool]$org.onPremisesSyncEnabled
    BreakGlass = @($BreakGlassAccounts | % { $_.ToLower() })
    PrivilegedRoleIds = @('62e90394-69f5-4237-9190-012177145e10','e8611ab8-c189-46e8-94e1-60213ab1f814','194ae4cb-b126-40b2-bd5b-6091b380977d','b1be1c3e-b65d-4f19-8427-f6fa0d97feb9','7be44c8a-adaf-4e2a-84d6-ab2649e08a13','3a2c62db-5318-420d-8d74-23affee5d9d5','29232cdf-9323-42fd-ade2-1d097af3e4de','f28a1f50-f6e7-4571-818b-6a12f2af6b6c','158c047a-c907-4556-b7ef-446551a6b5f7','9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3','fe930be7-5e62-47db-91af-98c3a49a38b1','729827e3-9c14-49f7-bb1b-9608f156bbb8','966707d0-3269-4727-9be2-8c3a10f19b9d','c4e39bd9-1100-46d3-8c65-fb160da0071f','7698a772-787b-4ac8-901f-60d6b08affd2')
    Plans = $plans; Skus = $skus
}
if (-not (Has 'graph.subscribedSkus')) { Write-Host "subscribedSkus not collected - licence-dependent controls will be assessed as if licensed. Check N/A decisions by hand." -ForegroundColor Yellow; foreach ($p in 'HasP1','HasP2','HasMDO1','HasMDO2','HasIntune','HasE5Compliance') { $Ctx.$p = $true } }

# role helpers ---------------------------------------------------------------
function Get-RoleMembers([string]$templateId) {
    $users = Ev 'graph.users'; $out = @()
    foreach ($r in (Ev 'graph.directoryRoles' | ? { $_.roleTemplateId -eq $templateId })) { foreach ($m in @($r.membersResolved)) { if ("$($m.'@odata.type')" -match 'user') { $u = $users | ? { $_.id -eq $m.id } | Select -First 1; $out += $(if ($u) { $u } else { $m }) } } }
    foreach ($e in (Ev 'graph.roleEligibilitySchedules' | ? { $_.roleDefinitionId -eq $templateId })) { $u = $users | ? { $_.id -eq $e.principalId } | Select -First 1; if ($u) { $out += $u } }
    $out | Sort-Object userPrincipalName -Unique
}
function Get-GAUsers { Get-RoleMembers '62e90394-69f5-4237-9190-012177145e10' }
function Get-AdminUsers { $o = @(); foreach ($id in $Ctx.PrivilegedRoleIds) { $o += Get-RoleMembers $id } ; $o | Sort-Object userPrincipalName -Unique }
function Get-AuthMethod([string]$id) { (One 'graph.authenticationMethodsPolicy').authenticationMethodConfigurations | ? { $_.id -eq $id } | Select -First 1 }
function Test-PimApproval([string]$roleId) {
    $a = Ev 'graph.roleManagementPolicyAssignments' | ? { $_.roleDefinitionId -eq $roleId } | Select -First 1
    if (-not $a) { return $null }
    $rule = @($a.policy.rules | ? { $_.id -eq 'Approval_EndUser_Assignment' }) | Select -First 1
    if (-not $rule) { return $null }
    return [bool]$rule.setting.isApprovalRequired
}
function Get-TeamsGlobalMeetingPolicy { $g = Ev 'teams.meetingPolicy' | ? { $_.Identity -match '^(Tag:)?Global$' } | Select -First 1; if (-not $g) { $g = One 'teams.meetingPolicy' } ; $g }
function Get-FabricSetting([string]$name) { Ev 'fabric.tenantSettings' | ? { $_.settingName -eq $name } | Select -First 1 }
# conditional access helpers --------------------------------------------------
function Get-CA { Ev 'graph.conditionalAccessPolicies' | ? { $_.state -eq 'enabled' } }
function CA-AllUsers($p) { @($p.conditions.users.includeUsers) -contains 'All' }
function CA-AdminRoles($p) { @($p.conditions.users.includeRoles).Count -ge 1 -or (CA-AllUsers $p) }
function CA-AllApps($p) { @($p.conditions.applications.includeApplications) -contains 'All' }
function CA-Grant($p, [string]$c) { @($p.grantControls.builtInControls) -contains $c }
function CA-Names($list) { (@($list) | % { "'$($_.displayName)'" }) -join ', ' }
function CA-Summary { $all = Ev 'graph.conditionalAccessPolicies'; "CA policies: $($all.Count) total, $(@($all | ? state -eq 'enabled').Count) enabled, $(@($all | ? state -eq 'enabledForReportingButNotEnforced').Count) report-only." }

# ------------------------------------------------------------------ evaluate
$catalogue = Get-Content (Join-Path $here 'controls\cis-m365-v7-controls.json') -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
$prev = @{}
if ($PreviousResults -and (Test-Path $PreviousResults)) { (Get-Content $PreviousResults -Raw | ConvertFrom-Json -AsHashtable).results | % { $prev[$_.id] = $_.status } }

$results = @()
Write-Host "`nAssessing $($catalogue.controls.Count) controls against evidence collected $collectedDate ..." -ForegroundColor Cyan
foreach ($c in $catalogue.controls) {
    $status = 'Not assessed'; $text = ''
    if (-not $c.test) {
        $status = 'Manual'; $text = "Portal-only control. Check: $($c.portal)"
    } else {
        $missing = @($c.evidenceKeys | ? { -not (Has $_) })
        $allMissing = (@($c.evidenceKeys).Count -gt 0 -and $missing.Count -eq @($c.evidenceKeys).Count)
        try {
            $sb = [scriptblock]::Create($c.test)
            $r = & $sb
            if ($r -is [array]) { $r = $r[-1] }
            $status = $r.Status; $text = $r.Evidence
            if ($allMissing -and $status -notin 'N/A','Manual','Review') { $status = 'Not assessed'; $text = "Evidence not collected: $($missing -join ', '). $(if ($c.portal) { 'Check by hand: ' + $c.portal } else { 'Re-run the collector for this workload.' })" }
            elseif ($missing.Count -gt 0 -and $status -notin 'N/A','Manual') { $text += " [Note: $($missing -join ', ') not collected.]" }
        } catch { $status = 'Not assessed'; $text = "Test error: $($_.Exception.Message)" }
    }
    $results += [pscustomobject]@{
        id = $c.id; title = $c.title; level = $c.level; licenceProfile = $c.licenceProfile; section = $c.section; subSection = $c.subSection
        assessment = $c.assessment; status = $status; evidence = $text
        previous = $(if ($prev.ContainsKey($c.id)) { $prev[$c.id] } else { '' })
        ceArea = $c.ceArea; ncscTitle = $c.ncscTitle; ncscUrl = $c.ncscUrl
        references = @($c.references); remediation = $c.remediation; rationale = $c.rationale; portal = $c.portal
    }
    $colour = switch ($status) { 'Pass' {'Green'} 'Fail' {'Red'} 'Partial' {'Yellow'} 'N/A' {'DarkGray'} default {'Magenta'} }
    Write-Host ("  {0,-9} {1,-13} {2}" -f $c.id, $status, $c.title) -ForegroundColor $colour
}

# ------------------------------------------------------------------ summarise
$counts = @{}; foreach ($s in 'Pass','Fail','Partial','N/A','Manual','Review','Not assessed') { $counts[$s] = @($results | ? status -eq $s).Count }
$assessable = $counts.Pass + $counts.Fail + $counts.Partial
$passRate = if ($assessable) { [math]::Round(100 * $counts.Pass / $assessable) } else { 0 }
$sections = $results | Group-Object section | Sort-Object { [int]($_.Name -split ' ')[0] }
function Rate($grp) { $p = @($grp | ? status -eq 'Pass').Count; $a = @($grp | ? status -in 'Pass','Fail','Partial').Count; if ($a) { "$([math]::Round(100*$p/$a))%" } else { '—' } }

# draft findings: group Fail/Partial by sub-section --------------------------------
$sevMap = @{
    '1.1' = 'High'; '1.2' = 'Medium'; '1.3' = 'Low'; '2.1' = 'High'; '2.2' = 'Medium'; '2.4' = 'High'; '3.1' = 'Medium'; '3.2' = 'Medium'; '3.3' = 'Medium'; '4' = 'High'
    '5.1.2' = 'High'; '5.1.3' = 'Medium'; '5.1.4' = 'High'; '5.1.5' = 'High'; '5.1.6' = 'Medium'; '5.1.8' = 'High'; '5.2.2' = 'High'; '5.2.3' = 'High'; '5.2.4' = 'Medium'; '5.3' = 'High'
    '6.1' = 'Medium'; '6.2' = 'Medium'; '6.3' = 'Medium'; '6.5' = 'Medium'; '7.2' = 'High'; '7.3' = 'Medium'; '8.1' = 'Medium'; '8.2' = 'Medium'; '8.4' = 'Medium'; '8.5' = 'Medium'; '8.6' = 'Low'; '9.1' = 'Low'
}
$findings = @(); $n = 0
$groups = $results | ? { $_.status -in 'Fail','Partial' } | Group-Object { if ($_.subSection) { $_.subSection } else { $_.section } } | Sort-Object { ($_.Group[0].id -replace '(\d+)','0000$1' -replace '0*(\d{4})','$1') }
foreach ($g in $groups) {
    $n++
    $sev = 'Medium'; $prefix = ($g.Name -split ' ')[0]; foreach ($k in ($sevMap.Keys | Sort-Object Length)) { if ($prefix -eq $k -or $prefix -like "$k.*") { $sev = $sevMap[$k] } }
    if (@($g.Group | ? level -eq 'L1').Count -eq 0) { $sev = if ($sev -eq 'High') { 'Medium' } else { 'Low' } }
    $ids = $g.Group.id
    # escalate the classic criticals
    if ($ids -contains '5.2.2.2' -and ($results | ? id -eq '5.2.2.1').status -eq 'Fail') { $sev = 'Critical' }
    if ($ids -contains '1.1.2' -and ($ids -contains '1.1.4' -or $ids -contains '1.1.3')) { $sev = 'Critical' }
    $refs = @($g.Group | % { $_.references } | Select -Unique | Select -First 6)
    $findings += [pscustomobject]@{
        id = ('F-{0:00}' -f $n); severity = $sev; area = $g.Name
        finding = "$(@($g.Group).Count) control(s) in '$($g.Name)' not met: $(($g.Group | % { $_.title }) -join '; ')"
        controls = ($ids -join ', ')
        observed = (($g.Group | % { "• $($_.id): $($_.evidence)" }) -join "`n")
        risk = (($g.Group | Select -First 2 | % { $_.rationale }) -join "`n")
        recommendation = (($g.Group | % { "→ $($_.id): $(($_.remediation -replace '\s+',' ').Substring(0, [math]::Min(400, ($_.remediation -replace '\s+',' ').Length)))" }) -join "`n")
        owner = 'TBC'; time = 'TBC'; learn = ($refs -join "`n")
        ce = (($g.Group.ceArea | Select -Unique) -join '; '); ncsc = (($g.Group | % { "$($_.ncscTitle) — $($_.ncscUrl)" } | Select -Unique) -join "`n")
    }
}
# licensing & scope register from N/A results + context ----------------------------
$lic = @(); $i = 0
foreach ($r in ($results | ? status -eq 'N/A')) { $i++; $lic += [pscustomobject]@{ ref = ('L-{0:00}' -f $i); capability = "$($r.id) $($r.title)"; licence = $(if ($r.licenceProfile -eq 'E5') { 'E5-class (see evidence)' } else { 'see evidence' }); position = $r.evidence; related = '' } }
$i++; $lic += [pscustomobject]@{ ref = ('L-{0:00}' -f $i); capability = 'Licences observed in tenant'; licence = '—'; position = ($Ctx.Skus -join '; '); related = '' }
$i++; $lic += [pscustomobject]@{ ref = ('L-{0:00}' -f $i); capability = 'Capability flags used for N/A decisions'; licence = '—'; position = "Entra P1=$($Ctx.HasP1) P2=$($Ctx.HasP2) MDO P1=$($Ctx.HasMDO1) MDO P2=$($Ctx.HasMDO2) Intune=$($Ctx.HasIntune) MDCA=$($Ctx.HasMDCA) Lockbox=$($Ctx.HasLockbox) E5 Compliance=$($Ctx.HasE5Compliance) Fabric=$($Ctx.HasFabric) Hybrid=$($Ctx.Hybrid)"; related = '' }
# evidence gaps ------------------------------------------------------------------
$gaps = @($results | ? { $_.status -in 'Manual','Review','Not assessed' } | % { [pscustomobject]@{ id = $_.id; title = $_.title; level = $_.level; section = $_.section; status = $_.status; how = $(if ($_.portal) { $_.portal } else { 'See CIS audit procedure in the catalogue workbook' }); why = $_.evidence } })

# ------------------------------------------------------------------ write outputs
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$base = Join-Path $OutputPath $ClientName
$score = [math]::Max(1, [math]::Min(10, [math]::Round($passRate / 10)))
if (@($findings | ? severity -eq 'Critical').Count -gt 0) { $score = [math]::Min($score, 4) }

# results JSON
[pscustomobject]@{ kitVersion = $KitVersion; client = $ClientName; collectedUtc = $meta.collectedUtc; assessedUtc = (Get-Date).ToUniversalTime().ToString('o'); tenantId = $meta.tenantId
    counts = $counts; passRate = $passRate; indicativeScore = $score; context = $Ctx; results = $results; draftFindings = $findings; collectorErrors = $errors } |
    ConvertTo-Json -Depth 12 | Out-File "$base-assessment-results.json" -Encoding utf8

# Excel register
$regRows = $results | % { [pscustomobject]@{ 'CIS ID' = $_.id; 'Title' = $_.title; 'Level' = $_.level; 'Section' = $_.section; 'Sub-section' = $_.subSection; 'Licence profile' = $_.licenceProfile; 'Assessment type' = $_.assessment
    'Status' = $_.status; "Evidence (collected $collectedDate)" = $_.evidence; 'Previous status' = $_.previous; 'Remediation (CIS)' = ($_.remediation -replace '\s+',' '); 'Report finding' = (($findings | ? { ($_.controls -split ', ') -contains $_.id }).id -join ', ')
    'Cyber Essentials area' = $_.ceArea; 'NCSC guidance' = "$($_.ncscTitle) — $($_.ncscUrl)"; 'Microsoft Learn reference' = ($_.references -join "`n") } }
# fix Report finding (the inner $_ shadowed)
for ($k = 0; $k -lt $regRows.Count; $k++) { $id = $regRows[$k].'CIS ID'; $regRows[$k].'Report finding' = (@($findings | ? { ($_.controls -split ', ') -contains $id }).id -join ', ') }
$sumRows = @([pscustomobject]@{ Status = 'Pass'; Count = $counts.Pass; 'Share of assessed' = "$passRate%" }) + @('Fail','Partial') | % { if ($_ -is [string]) { [pscustomobject]@{ Status = $_; Count = $counts[$_]; 'Share of assessed' = $(if ($assessable) { "$([math]::Round(100*$counts[$_]/$assessable))%" } else { '' }) } } else { $_ } }
$sumRows += @('N/A','Manual','Review','Not assessed') | % { [pscustomobject]@{ Status = $_; Count = $counts[$_]; 'Share of assessed' = '' } }
$secRows = $sections | % { [pscustomobject]@{ Section = $_.Name; Controls = $_.Count; Pass = @($_.Group | ? status -eq 'Pass').Count; Fail = @($_.Group | ? status -eq 'Fail').Count; Partial = @($_.Group | ? status -eq 'Partial').Count; 'N/A' = @($_.Group | ? status -eq 'N/A').Count; 'Manual/Review' = @($_.Group | ? status -in 'Manual','Review').Count; 'Not assessed' = @($_.Group | ? status -eq 'Not assessed').Count; 'Pass rate (assessable)' = (Rate $_.Group) } }
$findRows = $findings | % { [pscustomobject]@{ ID = $_.id; Severity = $_.severity; Area = $_.area; Finding = $_.finding; 'CIS controls' = $_.controls; 'Previous refs' = ''; 'Status vs previous' = ''; Observed = $_.observed; Risk = $_.risk; Recommendation = $_.recommendation; Owner = $_.owner; 'Approximate time' = $_.time; 'Microsoft Learn' = $_.learn; 'Cyber Essentials' = $_.ce; 'NCSC' = $_.ncsc } }
$licRows = $lic | % { [pscustomobject]@{ Ref = $_.ref; 'Control / capability' = $_.capability; 'Licence required' = $_.licence; 'Position in this tenant' = $_.position; 'Related finding(s)' = $_.related } }
$gapRows = $gaps | % { [pscustomobject]@{ 'CIS ID' = $_.id; Title = $_.title; Level = $_.level; Section = $_.section; Status = $_.status; 'How to verify' = $_.how; 'Why it could not be scored automatically' = $_.why } }

$xlsx = "$base-CIS-M365-v7-Findings-Register.xlsx"
if (Get-Module -ListAvailable ImportExcel) {
    Import-Module ImportExcel
    Remove-Item $xlsx -ErrorAction SilentlyContinue
    $title = "$ClientName — CIS Microsoft 365 Foundations Benchmark v7.0.0 assessment"
    $sub = "Evidence: read-only collection $collectedDate ($($meta.workloads -join ', ')). Assessed $today by $PreparedBy with M365 CIS v7 Review Kit $KitVersion. Indicative posture score $score/10 (reviewer to confirm)."
    $x = $sumRows | Export-Excel -Path $xlsx -WorksheetName 'Summary' -StartRow 4 -AutoSize -BoldTopRow -PassThru
    $ws = $x.Workbook.Worksheets['Summary']; $ws.Cells['A1'].Value = $title; $ws.Cells['A1'].Style.Font.Bold = $true; $ws.Cells['A1'].Style.Font.Size = 14; $ws.Cells['A2'].Value = $sub
    Close-ExcelPackage $x
    $secRows  | Export-Excel -Path $xlsx -WorksheetName 'Summary' -StartRow 14 -AutoSize -BoldTopRow
    $regRows  | Export-Excel -Path $xlsx -WorksheetName 'Register' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter -ConditionalText @(
        (New-ConditionalText -Text 'Pass' -ConditionalTextColor DarkGreen -BackgroundColor LightGreen),
        (New-ConditionalText -Text 'Fail' -ConditionalTextColor DarkRed -BackgroundColor MistyRose),
        (New-ConditionalText -Text 'Partial' -ConditionalTextColor DarkGoldenrod -BackgroundColor LightYellow))
    $findRows | Export-Excel -Path $xlsx -WorksheetName 'Findings' -AutoSize -BoldTopRow -FreezeTopRow -AutoFilter
    $licRows  | Export-Excel -Path $xlsx -WorksheetName 'Licensing & scope' -AutoSize -BoldTopRow
    $gapRows  | Export-Excel -Path $xlsx -WorksheetName 'Evidence gaps' -AutoSize -BoldTopRow -AutoFilter
    Write-Host "`nRegister written: $xlsx" -ForegroundColor Green
} else {
    Write-Host "ImportExcel module not installed - writing CSVs instead (run Install-Prerequisites.ps1 for Excel output)." -ForegroundColor Yellow
    $regRows | Export-Csv "$base-Register.csv" -NoTypeInformation -Encoding utf8
    $findRows | Export-Csv "$base-Findings.csv" -NoTypeInformation -Encoding utf8
    $licRows | Export-Csv "$base-Licensing.csv" -NoTypeInformation -Encoding utf8
    $gapRows | Export-Csv "$base-EvidenceGaps.csv" -NoTypeInformation -Encoding utf8
}

# ------------------------------------------------------------------ HTML report draft
function Esc([string]$s) { [System.Net.WebUtility]::HtmlEncode("$s") -replace "`n",'<br/>' }
function Tbl($rows, $cols) {
    $sb = [System.Text.StringBuilder]::new(); [void]$sb.Append('<table><tr>'); foreach ($c in $cols) { [void]$sb.Append("<th>$(Esc $c)</th>") }; [void]$sb.Append('</tr>')
    foreach ($r in $rows) { [void]$sb.Append('<tr>'); foreach ($c in $cols) { $v = $r.$c; [void]$sb.Append("<td class='s-$(("$v" -replace '[^A-Za-z]','').ToLower())'>$(Esc $v)</td>") }; [void]$sb.Append('</tr>') }
    [void]$sb.Append('</table>'); $sb.ToString()
}
$sevCount = @{}; foreach ($s in 'Critical','High','Medium','Low') { $sevCount[$s] = @($findings | ? severity -eq $s).Count }
$passes = @($results | ? status -eq 'Pass' | Sort-Object { $_.level }, id)
$users = Ev 'graph.users'; $devices = Ev 'graph.devices'
$ga = @(Get-GAUsers)
$tenantRows = @(
    [pscustomobject]@{ Item = 'Tenant'; Value = "$(($org.verifiedDomains | ? isInitial).name) (default domain $(($org.verifiedDomains | ? isDefault).name))" },
    [pscustomobject]@{ Item = 'Tenant ID'; Value = $meta.tenantId },
    [pscustomobject]@{ Item = 'Accepted domains'; Value = ((Ev 'exo.acceptedDomains').DomainName -join ', ') },
    [pscustomobject]@{ Item = 'Licensing observed'; Value = ($Ctx.Skus -join '; ') },
    [pscustomobject]@{ Item = 'Users'; Value = "$($users.Count) user objects — $(@($users | ? accountEnabled).Count) enabled, $(@($users | ? userType -eq 'Guest').Count) guests; $($ga.Count) Global Administrators" },
    [pscustomobject]@{ Item = 'Devices'; Value = "$($devices.Count) registered devices — $(@($devices | ? isManaged).Count) managed, $(@($devices | ? isCompliant).Count) compliant" },
    [pscustomobject]@{ Item = 'Collection method'; Value = "Read-only delegated sign-in as $($meta.collectedBy) using Microsoft's first-party PowerShell clients ($($meta.workloads -join ', ')) on $collectedDate. No app registration, secret or consent created. No setting changed." },
    [pscustomobject]@{ Item = 'Benchmark'; Value = 'CIS Microsoft 365 Foundations Benchmark v7.0.0 (160 recommendations, Level 1 and Level 2)' },
    [pscustomobject]@{ Item = 'Findings (draft)'; Value = "$($findings.Count) auto-grouped ($($sevCount.Critical) Critical, $($sevCount.High) High, $($sevCount.Medium) Medium, $($sevCount.Low) Low) — reviewer to consolidate and confirm severities" }
)
$css = @"
<style>
body{font-family:Calibri,Segoe UI,Arial,sans-serif;font-size:10.5pt;color:#1a1a1a;max-width:1100px;margin:30px auto;line-height:1.35}
h1{font-size:18pt;color:#1f3864;border-bottom:2px solid #1f3864;padding-bottom:4px;margin-top:36px}
h2{font-size:13pt;color:#2e5597;margin-top:24px} .cover h1{border:none;font-size:26pt;margin-top:120px}
table{border-collapse:collapse;width:100%;margin:8px 0 14px 0;font-size:9.5pt} th{background:#1f3864;color:#fff;text-align:left;padding:5px 6px} td{border:1px solid #c9c9c9;padding:4px 6px;vertical-align:top}
.box{border:1px solid #2e5597;background:#eef3fb;padding:10px 14px;margin:12px 0} .rev{color:#b00020;font-weight:bold}
.s-pass{background:#e2f0d9} .s-fail{background:#fbe5e5} .s-partial{background:#fff2cc} .s-na{background:#ededed} .s-critical{background:#c00000;color:#fff;font-weight:bold} .s-high{background:#f4b183} .s-medium{background:#ffe699} .s-low{background:#dbe5f1}
.score{font-size:40pt;font-weight:bold;color:#1f3864} .legend{font-size:9pt;color:#444} .f td:first-child{width:160px;background:#f3f6fb;font-weight:bold}
</style>
"@
$sb = [System.Text.StringBuilder]::new()
[void]$sb.Append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>$(Esc $ClientName) — Microsoft 365 Security Review (CIS v7.0.0)</title>$css</head><body>")
[void]$sb.Append("<div class='cover'><h1>$(Esc $ClientName)</h1><p style='font-size:16pt'>Microsoft 365 Tenant — Security Review</p><p>Assessment against the CIS Microsoft 365 Foundations Benchmark v7.0.0</p><p>Prepared by<br/><b>$(Esc $PreparedBy)</b></p><p>$today</p><p>Version 0.1 DRAFT — for $(Esc $PreparedFor)</p><p>Classification: Confidential — contains tenant identifiers, account names and configuration detail</p></div>")
[void]$sb.Append("<h1>Revision history</h1>" + (Tbl @([pscustomobject]@{ Version='0.1'; Date=(Get-Date).ToString('yyyy-MM-dd'); Author=$PreparedBy; Notes="Draft generated by M365 CIS v7 Review Kit $KitVersion from evidence collected $collectedDate. Reviewer to complete the sections marked REVIEWER." }) @('Version','Date','Author','Notes')))
[void]$sb.Append("<div class='box'><b>Read this first.</b> <span class='rev'>REVIEWER:</span> state whether this is a first assessment or a re-run, the evidence date, and the one or two things that matter most. Keep it to five lines.</div>")
[void]$sb.Append("<h1>Contents</h1><p>1. Executive summary · 2. Posture scorecard · 3. CIS v7.0.0 compliance summary · 4. Severity model and methodology · 5. What's working well · 6. Tenant context · 7. Findings at a glance · 8. Detailed findings · 9. Licensing and scope register · 10. Remediation roadmap · 11. Methodology, scope and evidence gaps · Appendix A Full control register · Appendix B Glossary · Appendix C UK Cyber Essentials alignment · Appendix D Microsoft Secure Score mapping · Appendix E NCSC guidance references</p><p class='legend'>In Word: References > Table of Contents to replace this line with a live contents table.</p>")
[void]$sb.Append("<h1>1. Executive summary</h1><p>This review assesses the $(Esc $ClientName) Microsoft 365 tenant against the CIS Microsoft 365 Foundations Benchmark v7.0.0 — 160 recommendations across Level 1 and Level 2 profiles. Evidence was collected read-only on $collectedDate through Microsoft Graph, Exchange Online, Purview, Teams, SharePoint Online and public DNS. No setting was changed.</p><p>Of the 160 recommendations, $assessable were scored automatically: $($counts.Pass) pass, $($counts.Fail) fail, $($counts.Partial) are partially met and $($counts.'N/A') do not apply (licence not held or service not provisioned). $($counts.Manual + $counts.Review) need a portal check or a human judgement and $($counts.'Not assessed') could not be read (Section 11). The pass rate on assessable controls is <b>$passRate%</b>.</p><p><span class='rev'>REVIEWER:</span> write 4–7 bullets naming the findings that matter most, in plain English, each ending with its finding ID. Then one sentence on sequencing (what must happen before what).</p>")
[void]$sb.Append("<h1>2. Posture scorecard</h1><table><tr><td style='width:160px;text-align:center'><span class='score'>$score / 10</span><br/>Indicative posture</td><td><span class='rev'>REVIEWER:</span> one paragraph characterising the tenant. The score is computed from the pass rate (and capped at 4 where a Critical draft finding exists); adjust it with judgement and say why.</td></tr></table>")
[void]$sb.Append("<h1>3. CIS v7.0.0 compliance summary</h1><p>Status per control is in the workbook's Register sheet and reproduced in Appendix A. 'Assessable' excludes N/A, manual and unread controls.</p>" + (Tbl ($secRows + [pscustomobject]@{ Section='Total'; Controls=$results.Count; Pass=$counts.Pass; Fail=$counts.Fail; Partial=$counts.Partial; 'N/A'=$counts.'N/A'; 'Manual/Review'=($counts.Manual+$counts.Review); 'Not assessed'=$counts.'Not assessed'; 'Pass rate (assessable)'="$passRate%" }) @('Section','Controls','Pass','Fail','Partial','N/A','Manual/Review','Not assessed','Pass rate (assessable)')))
$lv = foreach ($L in 'L1','L2') { $g = $results | ? level -eq $L; [pscustomobject]@{ 'Profile level' = $(if ($L -eq 'L1') { 'Level 1 (baseline)' } else { 'Level 2 (defence-in-depth)' }); Pass = @($g | ? status -eq 'Pass').Count; Fail = @($g | ? status -eq 'Fail').Count; Partial = @($g | ? status -eq 'Partial').Count; 'Pass rate' = (Rate $g) } }
[void]$sb.Append((Tbl $lv @('Profile level','Pass','Fail','Partial','Pass rate')) + "<p class='legend'>Legend: Pass — evidenced compliant · Fail — evidenced non-compliant · Partial — met with a specific documented gap · N/A — licence not held, or the service is not provisioned · Manual — portal-only setting, to be read by hand · Review — needs a human judgement · Not assessed — evidence could not be read.</p>")
[void]$sb.Append("<h1>4. Severity model and methodology</h1><p>CIS profiles (Level 1 / Level 2) say how important a control is in general; the severities below say how important each gap is in this tenant, given the other controls observed alongside it. Severity is deliberately contextual: an open setting matters more where there is no identity perimeter behind it.</p>" + (Tbl @(
    [pscustomobject]@{ Severity='Critical'; Definition='Direct path to tenant compromise or large-scale data exposure with no compensating control.'; 'Typical pattern'='Global Administrator reachable with a password alone; no MFA enforcement; no break-glass and standing GA on daily-use mailboxes.' },
    [pscustomobject]@{ Severity='High'; Definition='Materially weakens defence-in-depth; one breached layer reaches sensitive data or privilege.'; 'Typical pattern'='Default-permissive identity settings; unmanaged app credentials; anonymous sharing links; Defender on Built-In Protection only.' },
    [pscustomobject]@{ Severity='Medium'; Definition='Specific weakness that can be chained, or fails a Level 1 baseline without immediate exposure.'; 'Typical pattern'='Mail-flow exfiltration paths; open Teams federation; permissive meeting defaults; missing DLP.' },
    [pscustomobject]@{ Severity='Low'; Definition='Hygiene, Level 2 hardening or non-load-bearing settings. Next review cycle.'; 'Typical pattern'='Reporting routed to a personal mailbox; licensing-constrained items; Fabric defaults in an unused service.' }) @('Severity','Definition','Typical pattern')) +
    "<p>Each control was tested against the CIS v7.0.0 audit procedure using the live value read from Microsoft Graph, the relevant PowerShell cmdlet, public DNS or the admin portal (Appendix A names the evidence for every assessed control). Where a setting could not be read it is marked Not assessed rather than inferred, and where a capability is not licensed or not provisioned it is marked N/A rather than Fail, so the pass rate is not distorted by things the tenant could not do. Recommendations are written in operational form so they can be lifted into change tickets, and every finding carries Microsoft Learn references and the relevant NCSC guidance.</p>")
[void]$sb.Append("<h1>5. What's working well</h1><p>$($counts.Pass) controls pass. These are working and should be preserved through remediation rather than disturbed by it.</p><ul>" + (($passes | Select -First 25 | % { "<li><b>$($_.id)</b> $(Esc $_.title) — <span class='legend'>$(Esc $_.evidence)</span></li>" }) -join '') + "</ul>")
[void]$sb.Append("<h1>6. Tenant context</h1>" + (Tbl $tenantRows @('Item','Value')) + "<div class='box'><b>Scope note.</b> This review covers the $(Esc $ClientName) tenant only. <span class='rev'>REVIEWER:</span> name anything explicitly out of scope.</div>")
[void]$sb.Append("<h1>7. Findings at a glance</h1><table><tr><td class='s-critical' style='text-align:center;font-size:18pt'>$($sevCount.Critical)<br/>Critical</td><td class='s-high' style='text-align:center;font-size:18pt'>$($sevCount.High)<br/>High</td><td class='s-medium' style='text-align:center;font-size:18pt'>$($sevCount.Medium)<br/>Medium</td><td class='s-low' style='text-align:center;font-size:18pt'>$($sevCount.Low)<br/>Low</td></tr></table><p class='legend'><span class='rev'>REVIEWER:</span> the findings below are auto-grouped by benchmark sub-section. Merge, split and rename them so each reads as one problem the customer would recognise, then confirm severities. Typical finished reports have 12–20 findings.</p>" + (Tbl ($findings | % { [pscustomobject]@{ ID=$_.id; Severity=$_.severity; Area=$_.area; Finding=$_.finding; 'CIS controls'=$_.controls } }) @('ID','Severity','Area','Finding','CIS controls')))
[void]$sb.Append("<h1>8. Detailed findings</h1>")
foreach ($f in $findings) {
    [void]$sb.Append("<table class='f'><tr><th colspan='2'>$($f.id)&nbsp; [$($f.severity)]&nbsp; $(Esc $f.finding)</th></tr><tr><td>Area</td><td>$(Esc $f.area)</td></tr><tr><td>CIS v7 controls</td><td>$(Esc $f.controls)</td></tr><tr><td>Baseline</td><td><span class='rev'>REVIEWER:</span> New — first assessment / Open since &lt;date&gt; / Improved</td></tr><tr><td>Observed</td><td>$(Esc $f.observed)</td></tr><tr><td>Risk</td><td>$(Esc $f.risk)<br/><span class='rev'>REVIEWER:</span> rewrite as 2–3 sentences specific to this tenant.</td></tr><tr><td>Recommendation</td><td>$(Esc $f.recommendation)</td></tr><tr><td>Microsoft Learn</td><td>" + (($f.learn -split "`n" | ? { $_ } | % { "📘 <a href='$_'>$_</a>" }) -join '<br/>') + "</td></tr><tr><td>NCSC / Cyber Essentials</td><td>$(Esc $f.ce)<br/>$(Esc $f.ncsc)</td></tr><tr><td>Approximate time</td><td>$(Esc $f.time)</td></tr></table>")
}
[void]$sb.Append("<h1>9. Licensing and scope register</h1><p>Which recommendations the tenant's current subscriptions prevent it from meeting, which are not provisioned, and which are available today at no cost.</p>" + (Tbl $licRows @('Ref','Control / capability','Licence required','Position in this tenant','Related finding(s)')))
[void]$sb.Append("<h1>10. Remediation roadmap</h1><p>Times are approximate, for a familiar Entra/Exchange administrator working from PowerShell; they exclude change approval and user communications. Owners are to be confirmed.</p>")
foreach ($lane in @(@('Day 0 — make it safe to change','Critical'),@('Day 1 — close the Critical findings','Critical'),@('Week 1 — close the High findings','High'),@('Month 1 — harden and classify','Medium'),@('Quarter 1 — Level 2 and licensing decisions','Low'))) {
    $rows = @($findings | ? severity -eq $lane[1] | % { [pscustomobject]@{ ID=$_.id; 'Approx. time'='TBC'; Owner='TBC'; Task=(($_.recommendation -split "`n")[0]) } })
    [void]$sb.Append("<h2>$($lane[0])</h2>" + $(if ($rows) { Tbl $rows @('ID','Approx. time','Owner','Task') } else { "<p class='legend'>No findings at this severity. <span class='rev'>REVIEWER:</span> move prerequisite tasks (break-glass accounts, admin MFA registration) into Day 0 if an MFA change is planned.</p>" }))
}
[void]$sb.Append("<h1>11. Methodology, scope and evidence gaps</h1><h2>Method</h2><p>The 160 v7.0.0 recommendations were loaded from the benchmark's machine-readable control definitions (ID, profile, audit and remediation procedure, references). Each was tested against a live value read on $collectedDate. Evidence was collected read-only through a delegated interactive sign-in as $(Esc $meta.collectedBy) using Microsoft's first-party PowerShell clients, so no application registration, client secret or admin consent was created in the client tenant. Workloads collected: $(Esc ($meta.workloads -join ', ')). No setting was changed at any point.</p>")
[void]$sb.Append("<h2>Not assessed, manual or needing review ($($gaps.Count) controls)</h2>" + (Tbl $gapRows @('CIS ID','Title','Level','Status','How to verify','Why it could not be scored automatically')))
if ($errors) { [void]$sb.Append("<h2>Collector errors</h2>" + (Tbl ($errors | % { [pscustomobject]@{ Dataset=$_.key; Error=$_.error } }) @('Dataset','Error'))) }
[void]$sb.Append("<h2>Not applicable rather than failed</h2><p>$($counts.'N/A') controls are recorded as N/A (Section 9 lists each with its licence). Marking these N/A rather than Fail keeps the pass rate honest.</p><h2>Out of scope</h2><p>Real-time signal (sign-in risk events, alert history, Secure Score trend), Defender for Endpoint / Identity / Cloud Apps tuning, endpoint configuration baselines, and the content of mailboxes and SharePoint sites.</p>")
[void]$sb.Append("<h1>Appendix A — Full control register (CIS v7.0.0)</h1><p>One row per recommendation. 'Evidence' names the live value read. The workbook carries the same table with remediation text and Microsoft Learn hyperlinks.</p>" + (Tbl ($results | % { [pscustomobject]@{ ID=$_.id; Recommendation=$_.title; L=$_.level; Status=$_.status; Evidence=$_.evidence; Finding=(@($findings | ? { ($_.controls -split ', ') -contains $_.id }).id -join ', ') } }) @('ID','Recommendation','L','Status','Evidence','Finding')))
[void]$sb.Append("<h1>Appendix B — Glossary</h1>" + (Tbl @(
 [pscustomobject]@{Term='CIS / L1 / L2';Definition='Center for Internet Security benchmark; Level 1 = baseline every tenant should meet; Level 2 = defence-in-depth, may affect usability.'},
 [pscustomobject]@{Term='Security Defaults';Definition='A free, tenant-wide Microsoft preset that forces MFA registration, requires MFA for admins and blocks legacy authentication.'},
 [pscustomobject]@{Term='Conditional Access (CA)';Definition='Policy engine that evaluates signals (user, device, location, risk) and grants, limits or blocks access. Requires Entra ID P1.'},
 [pscustomobject]@{Term='Entra ID P1 / P2';Definition='Licence tiers. P1 brings Conditional Access; P2 adds Privileged Identity Management, Identity Protection and access reviews.'},
 [pscustomobject]@{Term='Per-user MFA';Definition='The legacy, account-by-account MFA toggle that predates Conditional Access.'},
 [pscustomobject]@{Term='Break-glass';Definition='Emergency-access account excluded from Conditional Access, unlicensed, cloud-only, with monitored sign-ins.'},
 [pscustomobject]@{Term='PIM / JIT';Definition='Privileged Identity Management — just-in-time, time-bound activation of admin roles with approval and audit.'},
 [pscustomobject]@{Term='Preset security policy';Definition='Microsoft-maintained Standard and Strict bundles of Defender for Office 365 and EOP settings.'},
 [pscustomobject]@{Term='Built-In Protection';Definition='The lowest-priority Defender for Office policy tier, applied when nothing else is assigned.'},
 [pscustomobject]@{Term='Direct Send';Definition='Unauthenticated SMTP delivery straight to the tenant''s MX record from any host on the internet.'},
 [pscustomobject]@{Term='Anonymous / ''Anyone'' link';Definition='A SharePoint or OneDrive sharing link that requires no sign-in.'},
 [pscustomobject]@{Term='App management policy';Definition='Tenant-wide Entra policy restricting how application credentials (secrets, certificates) may be created and how long they live.'},
 [pscustomobject]@{Term='DLP / sensitivity label';Definition='Purview data loss prevention policies detect and act on sensitive content; labels classify and protect it.'},
 [pscustomobject]@{Term='DMARC / SPF / DKIM';Definition='Email authentication: policy for unaligned mail / authorised sending hosts / cryptographic signing of outbound mail.'},
 [pscustomobject]@{Term='MDO / EOP';Definition='Microsoft Defender for Office 365 / Exchange Online Protection.'},
 [pscustomobject]@{Term='LAPS';Definition='Windows Local Administrator Password Solution — rotates and escrows local admin passwords in Entra ID.'}) @('Term','Definition')))
$ceRows = $results | ? { $_.status -in 'Fail','Partial' } | Group-Object ceArea | % { [pscustomobject]@{ 'Cyber Essentials control area' = $_.Name; 'Open controls' = $_.Count; 'CIS IDs' = (($_.Group.id) -join ', ') } }
[void]$sb.Append("<h1>Appendix C — UK Cyber Essentials alignment</h1><p>Mapping of open controls to the five Cyber Essentials control areas (NCSC). Cyber Essentials Plus additionally requires a hands-on assessment of endpoint configuration, which is outside this tenant review. <span class='rev'>REVIEWER:</span> state whether, on this evidence, the tenant would pass a Cyber Essentials assessment and which area is the binding constraint.</p>" + (Tbl $ceRows @('Cyber Essentials control area','Open controls','CIS IDs')))
$ss = @(Ev 'graph.secureScoreControlProfiles' | ? { $_.controlStateUpdates -and ($_.controlStateUpdates[-1].state -ne 'Default' -or $true) } | Select -First 0)
[void]$sb.Append("<h1>Appendix D — Microsoft Secure Score mapping</h1><p>Each finding maps to one or more Secure Score improvement actions. Point values vary by licence and change over time, so they are not estimated here — read the live values in the Defender portal and use the Register sheet's control IDs to attribute the uplift. $(if (Has 'graph.secureScores') { $s = One 'graph.secureScores'; "Secure Score at collection: $($s.currentScore) / $($s.maxScore) on $(([datetime]$s.createdDateTime).ToString('d MMM yyyy'))." })</p>")
$ncRows = $results | ? { $_.status -in 'Fail','Partial' } | Group-Object ncscTitle | % { [pscustomobject]@{ 'NCSC guidance' = $_.Name; URL = $_.Group[0].ncscUrl; 'Open CIS controls' = (($_.Group.id) -join ', ') } }
[void]$sb.Append("<h1>Appendix E — NCSC guidance references</h1><p>UK National Cyber Security Centre guidance relevant to the open findings. Use these alongside the Microsoft Learn references when explaining why a change matters.</p>" + (Tbl $ncRows @('NCSC guidance','URL','Open CIS controls')))
[void]$sb.Append("<p class='legend'>Generated by M365 CIS v7 Review Kit $KitVersion on $today. Control definitions: CIS Microsoft 365 Foundations Benchmark v7.0.0. $(Esc $PreparedBy) · Confidential.</p></body></html>")
$html = "$base-M365-Security-Review-DRAFT.html"
$sb.ToString() | Out-File $html -Encoding utf8

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host ("Pass {0}  Fail {1}  Partial {2}  N/A {3}  Manual {4}  Review {5}  Not assessed {6}   Pass rate (assessable) {7}%   Indicative score {8}/10" -f $counts.Pass,$counts.Fail,$counts.Partial,$counts.'N/A',$counts.Manual,$counts.Review,$counts.'Not assessed',$passRate,$score) -ForegroundColor Green
Write-Host "Draft findings: $($findings.Count) (Critical $($sevCount.Critical), High $($sevCount.High), Medium $($sevCount.Medium), Low $($sevCount.Low))"
Write-Host "`nOutputs in $OutputPath :"
Write-Host "  $(Split-Path $html -Leaf)   <- open in Word, Save As .docx, complete the REVIEWER prompts"
Write-Host "  $(if (Test-Path $xlsx) { Split-Path $xlsx -Leaf } else { "$ClientName-Register.csv / -Findings.csv / -Licensing.csv / -EvidenceGaps.csv (install ImportExcel for the .xlsx)" })"
Write-Host "  $ClientName-assessment-results.json"
Write-Host "`nNext: work through the Evidence gaps sheet (Manual / Review items), then finalise findings and severities. See the Runbook, section 6." -ForegroundColor Cyan
