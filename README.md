# M365 CIS v7 Review Kit

A self-contained kit for running a Microsoft 365 tenant security review against the **CIS Microsoft 365 Foundations Benchmark v7.0.0** (160 controls), with Microsoft Learn, NCSC and UK Cyber Essentials references. Works against any tenant, read-only throughout, runs on Windows with PowerShell 7. One reviewer, about half a day of hands-on time, produces a Word report and an Excel findings register.

## Layout

| Path | What |
|---|---|
| `2-Scripts/Install-Prerequisites.ps1` | one-time module install |
| `2-Scripts/Get-M365CISEvidence.ps1` | read-only evidence collector: Graph, Exchange/Defender, Purview, Teams, SharePoint, Fabric, public DNS |
| `2-Scripts/Invoke-M365CISAssessment.ps1` | scores all 160 controls; writes the findings register (.xlsx), a report draft (.html → Word) and a results JSON |
| `2-Scripts/controls/cis-m365-v7-controls.json` | control catalogue: CIS text, references, NCSC/CE mapping, evidence keys, portal paths, one PowerShell test per control (152 automated, 8 portal-only) |
| `build_catalogue.py` | regenerates the catalogue from `cis7.json` (CIS v7.0.0 machine-readable definitions, from the Prowler project) — **this is where the test rules live** |
| `build_runbook.js`, `build_report_template.js`, `build_templates.py` | generate the runbook (.docx), report template (.docx), register template and reference catalogue (.xlsx) |
| `dist/` | built kit (runbook, templates, reference) — produced by `build.sh` |

## Build the kit

```bash
curl -sL -o cis7.json https://raw.githubusercontent.com/prowler-cloud/prowler/master/prowler/compliance/m365/cis_7.0_m365.json
python3 build_catalogue.py          # -> out/2-Scripts/controls/cis-m365-v7-controls.json
npm install docx && node build_runbook.js && node build_report_template.js
pip3 install openpyxl && python3 build_templates.py
```

`build.sh` runs all of the above and zips `dist/M365-CIS-v7-Review-Kit-<version>.zip`.

## Run a review

```powershell
cd 2-Scripts
.\Install-Prerequisites.ps1
.\Get-M365CISEvidence.ps1 -UserPrincipalName admin@client.com -ClientName Client
.\Invoke-M365CISAssessment.ps1 -EvidencePath .\Evidence -ClientName Client -PreparedBy "Name, Org" -PreparedFor "Recipient, Client" -BreakGlassAccounts bg1@client.onmicrosoft.com,bg2@client.onmicrosoft.com
```

Then open `Output\Client-M365-Security-Review-DRAFT.html` in Word, Save As .docx, complete the REVIEWER prompts, and edit the register workbook. Full procedure: `dist/1-Runbook/`.

## Handling

`Evidence/` and `Output/` are git-ignored: evidence files contain account names and configuration detail and are confidential to the client. Never commit them.

## Sources

Control definitions and Microsoft Learn references: CIS Microsoft 365 Foundations Benchmark v7.0.0 (19 May 2026), machine-readable data via the open-source [Prowler](https://github.com/prowler-cloud/prowler) project. NCSC mapping: NCSC Cyber Essentials requirements and published guidance collections.
