M365 CIS v7 REVIEW KIT  -  version 1.0  (21 October 2026)
=========================================================
A self-contained kit for running a Microsoft 365 tenant security review against the
CIS Microsoft 365 Foundations Benchmark v7.0.0 (160 controls), with Microsoft Learn,
NCSC and UK Cyber Essentials references. Works against ANY tenant. Read-only throughout.
Runs on Windows with PowerShell 7. One reviewer, about half a day of hands-on time.

START HERE:  1-Runbook\M365 CIS v7 Review Kit - Runbook.docx

FOLDERS
  1-Runbook\            The runbook: setup, client access request, collection, scoring,
                        portal checks, consolidating findings, producing the report, QA, delivery.
  2-Scripts\            Install-Prerequisites.ps1      one-time module install
                        Get-M365CISEvidence.ps1        read-only evidence collector (Graph, Exchange,
                                                       Purview, Teams, SharePoint, Fabric, DNS)
                        Invoke-M365CISAssessment.ps1   scores all 160 controls; writes the findings
                                                       register (.xlsx), the report draft (.html -> Word)
                                                       and a results JSON
                        controls\cis-m365-v7-controls.json  the control catalogue the scripts read
                                                       (CIS text, references, NCSC/CE mapping, tests)
  3-Templates\          Report template (.docx) and findings register template (.xlsx) in the
                        standard structure
  4-Reference\          CIS-M365-v7-Control-Catalogue.xlsx  all 160 controls with audit and remediation
                                                       procedures, Microsoft Learn, NCSC and CE references
                        Severity-and-scoring-model.md
  5-Worked-examples\    Add finished reviews from your
                        document library so new reviewers can see what "done" looks like.

QUICK START (PowerShell 7, in 2-Scripts)
  .\Install-Prerequisites.ps1
  .\Get-M365CISEvidence.ps1 -UserPrincipalName admin@client.com -ClientName Client
  .\Invoke-M365CISAssessment.ps1 -EvidencePath .\Evidence -ClientName Client -PreparedBy "Name, Org" -PreparedFor "Recipient, Client" -BreakGlassAccounts bg1@client.onmicrosoft.com,bg2@client.onmicrosoft.com
  Then: open Output\Client-M365-Security-Review-DRAFT.html in Word, Save As .docx, complete the
  REVIEWER prompts, and edit Output\Client-CIS-M365-v7-Findings-Register.xlsx. Runbook sections 5-7.

HANDLING
  Evidence files contain account names and configuration detail. Confidential to the client.
  Store only on an encrypted machine and the your document library; never email.

SOURCES
  Control definitions and Microsoft Learn references: CIS Microsoft 365 Foundations Benchmark v7.0.0
  (19 May 2026), machine-readable data via the open-source Prowler project. Audit logic, evidence
  collection and report structure: two client reviews delivered in September 2026.
  NCSC mapping: NCSC Cyber Essentials requirements and published guidance collections.
