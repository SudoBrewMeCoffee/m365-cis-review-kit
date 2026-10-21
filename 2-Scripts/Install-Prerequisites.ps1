<#
.SYNOPSIS
    One-time setup for the M365 CIS v7 Review Kit on a Windows machine.
.DESCRIPTION
    Checks PowerShell 7, installs the PowerShell modules the collector and assessment need (current user,
    from the PowerShell Gallery) and confirms DNS lookups work. Safe to re-run. Needs internet access to
    the PowerShell Gallery. Nothing here touches any tenant.
#>
$ErrorActionPreference = 'Continue'
Write-Host "M365 CIS v7 Review Kit - prerequisites" -ForegroundColor Cyan
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "You are running Windows PowerShell $($PSVersionTable.PSVersion). The kit needs PowerShell 7." -ForegroundColor Red
    Write-Host "Install it with:   winget install Microsoft.PowerShell     then open 'PowerShell 7' from the Start menu and run this script again." -ForegroundColor Yellow
    return
}
Write-Host "PowerShell $($PSVersionTable.PSVersion) OK" -ForegroundColor Green
if ((Get-ExecutionPolicy -Scope CurrentUser) -in 'Restricted','Undefined' -and (Get-ExecutionPolicy) -eq 'Restricted') {
    Write-Host "Setting execution policy to RemoteSigned for the current user so the kit scripts can run." -ForegroundColor Yellow
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
}
try { Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue } catch {}
$modules = @(
    @{ Name = 'Microsoft.Graph.Authentication';          Why = 'Entra ID, Intune and admin-centre settings via Microsoft Graph' },
    @{ Name = 'ExchangeOnlineManagement';                Why = 'Exchange Online, Defender for Office 365 and Purview (Security & Compliance)' },
    @{ Name = 'MicrosoftTeams';                          Why = 'Teams policies' },
    @{ Name = 'Microsoft.Online.SharePoint.PowerShell';  Why = 'SharePoint Online tenant settings (section 7)' },
    @{ Name = 'MicrosoftPowerBIMgmt';                    Why = 'Fabric / Power BI tenant settings (section 9)' },
    @{ Name = 'ImportExcel';                             Why = 'Writes the findings register as .xlsx (no Excel install needed)' }
)
foreach ($m in $modules) {
    if (Get-Module -ListAvailable -Name $m.Name) { Write-Host ("  {0,-42} already installed" -f $m.Name) -ForegroundColor Green; continue }
    Write-Host ("  {0,-42} installing ... ({1})" -f $m.Name, $m.Why) -ForegroundColor Cyan
    try { Install-Module $m.Name -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -ErrorAction Stop; Write-Host ("  {0,-42} installed" -f $m.Name) -ForegroundColor Green }
    catch { Write-Host ("  {0,-42} FAILED: {1}" -f $m.Name, $_.Exception.Message) -ForegroundColor Red }
}
if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) { Write-Host "DNS lookups: Resolve-DnsName available" -ForegroundColor Green } else { Write-Host "Resolve-DnsName not found - the collector will fall back to nslookup." -ForegroundColor Yellow }
Write-Host "`nDone. Next: .\Get-M365CISEvidence.ps1 -UserPrincipalName <admin@client.com> -ClientName <Client>" -ForegroundColor Cyan
