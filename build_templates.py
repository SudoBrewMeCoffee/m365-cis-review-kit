#!/usr/bin/env python3
"""Builds: 3-Templates/Findings-Register-Template.xlsx, 4-Reference/CIS-M365-v7-Control-Catalogue.xlsx, 4-Reference/Severity-and-scoring-model.md"""
import json, os
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.table import Table, TableStyleInfo

NAVY = "1F3864"
hdr_font = Font(bold=True, color="FFFFFF", name="Calibri", size=10)
hdr_fill = PatternFill("solid", fgColor=NAVY)
thin = Side(style="thin", color="C9C9C9")
border = Border(left=thin, right=thin, top=thin, bottom=thin)
wrap = Alignment(wrap_text=True, vertical="top")

def sheet(wb, name, headers, rows, widths, title=None, subtitle=None, freeze=True):
    ws = wb.create_sheet(name)
    r0 = 1
    if title:
        ws["A1"] = title; ws["A1"].font = Font(bold=True, size=14, color=NAVY)
        ws["A2"] = subtitle or ""; ws["A2"].font = Font(italic=True, size=9, color="555555")
        r0 = 4
    for c, h in enumerate(headers, 1):
        cell = ws.cell(row=r0, column=c, value=h); cell.font = hdr_font; cell.fill = hdr_fill; cell.alignment = wrap; cell.border = border
    for i, row in enumerate(rows, r0 + 1):
        for c, v in enumerate(row, 1):
            cell = ws.cell(row=i, column=c, value=v); cell.alignment = wrap; cell.border = border; cell.font = Font(name="Calibri", size=10)
    for c, w in enumerate(widths, 1): ws.column_dimensions[get_column_letter(c)].width = w
    if freeze: ws.freeze_panes = ws.cell(row=r0 + 1, column=1)
    ws.auto_filter.ref = f"A{r0}:{get_column_letter(len(headers))}{max(r0 + 1, r0 + len(rows))}"
    return ws

# ------------------------------------------------------------------ register template
wb = Workbook(); wb.remove(wb.active)
sheet(wb, "Summary", ["Status", "Count", "Share of assessed"],
      [["Pass", None, None], ["Fail", None, None], ["Partial", None, None], ["N/A", None, None], ["Manual", None, None], ["Review", None, None], ["Not assessed", None, None]],
      [18, 10, 18], "<Client> — CIS Microsoft 365 Foundations Benchmark v7.0.0 assessment",
      "Evidence: read-only collection <date> (<workloads>). Prepared by <name>, <organisation>, <date>. Posture score <n>/10.", freeze=False)
ws = wb["Summary"]
ws["A14"] = "Section"; ws["B14"] = "Controls"; ws["C14"] = "Pass"; ws["D14"] = "Fail"; ws["E14"] = "Partial"; ws["F14"] = "N/A"; ws["G14"] = "Manual/Review"; ws["H14"] = "Not assessed"; ws["I14"] = "Pass rate (assessable)"
for c in range(1, 10): ws.cell(row=14, column=c).font = hdr_font; ws.cell(row=14, column=c).fill = hdr_fill
for i, s in enumerate(["1 Microsoft 365 admin center", "2 Microsoft Defender", "3 Microsoft Purview", "4 Microsoft Intune admin center", "5 Microsoft Entra admin center", "6 Exchange admin center", "7 SharePoint admin center", "8 Microsoft Teams admin center", "9 Microsoft Fabric", "Total"], 15):
    ws.cell(row=i, column=1, value=s)
ws.cell(row=15, column=2, value=15); ws.cell(row=16, column=2, value=21); ws.cell(row=17, column=2, value=5); ws.cell(row=18, column=2, value=2); ws.cell(row=19, column=2, value=63); ws.cell(row=20, column=2, value=13); ws.cell(row=21, column=2, value=12); ws.cell(row=22, column=2, value=17); ws.cell(row=23, column=2, value=12); ws.cell(row=24, column=2, value=160)
sheet(wb, "Register", ["CIS ID", "Title", "Level", "Section", "Sub-section", "Licence profile", "Assessment type", "Status", "Evidence (collected <date>)", "Previous status", "Remediation (CIS)", "Report finding", "Cyber Essentials area", "NCSC guidance", "Microsoft Learn reference"],
      [], [9, 44, 7, 26, 22, 9, 12, 12, 60, 12, 60, 12, 20, 40, 50])
sheet(wb, "Findings", ["ID", "Severity", "Area", "Finding", "CIS controls", "Previous refs", "Status vs previous", "Observed", "Risk", "Recommendation", "Owner", "Approximate time", "Microsoft Learn", "Cyber Essentials", "NCSC"],
      [["F-01", "Critical / High / Medium / Low", "", "One sentence the client recognises", "5.2.2.1, 5.2.2.2", "—", "New — first assessment", "• property = value …", "2–3 sentences specific to this tenant", "→ command or click-path …", "TBC", "1 hr", "Title — https://learn.microsoft.com/…", "User access control", "NCSC: … — https://www.ncsc.gov.uk/…"]],
      [7, 12, 22, 50, 20, 12, 18, 60, 50, 60, 8, 12, 50, 20, 40])
sheet(wb, "Licensing & scope", ["Ref", "Control / capability", "Licence required", "Position in this tenant", "Related finding(s)"],
      [["L-01", "Conditional Access (all policies, CIS 5.2.2.x)", "Entra ID P1", "", ""], ["L-02", "Privileged Identity Management (5.3.1, 5.3.4, 5.3.5)", "Entra ID P2", "", ""], ["L-03", "Access reviews (5.3.2, 5.3.3)", "Entra ID P2 / ID Governance", "", ""],
       ["L-04", "Intune device compliance and enrolment restrictions (4.1, 4.2)", "Intune / Business Premium", "", ""], ["L-05", "Defender for Office 365 presets, Safe Links, Safe Attachments, priority accounts (2.1.1, 2.1.4, 2.1.5, 2.1.7, 2.4.1, 2.4.2, 2.4.4, 7.3.1)", "Defender for Office P1", "", ""],
       ["L-06", "Defender for Cloud Apps (2.4.3)", "E5 / MDCA add-on", "", ""], ["L-07", "Automated Investigation and Response (2.4.5)", "Defender for Office P2 / E5", "", ""], ["L-08", "Customer Lockbox (1.3.6)", "E5 / add-on", "", ""],
       ["L-09", "Teams DLP default rule; DLP scoped to Copilot (3.2.2, 3.2.3)", "E5 / E5 Compliance", "", ""], ["L-10", "Identity Protection risk policies (5.2.2.6–8)", "Entra ID P2", "", ""], ["L-11", "Security Defaults (MFA for all users, block legacy auth)", "Free — all SKUs", "", ""], ["L-12", "Power BI / Fabric tenant settings (9.1.1–9.1.12)", "Power BI / Fabric capacity", "", ""]],
      [7, 60, 26, 40, 18])
sheet(wb, "Evidence gaps", ["CIS ID", "Title", "Level", "Section", "Status", "How to verify", "Why it could not be scored automatically"], [], [9, 44, 7, 26, 12, 60, 50])
os.makedirs("out/3-Templates", exist_ok=True)
wb.save("out/3-Templates/Findings-Register-Template.xlsx")

# ------------------------------------------------------------------ control catalogue (reference)
d = json.load(open("out/2-Scripts/controls/cis-m365-v7-controls.json"))
rows = []
for c in d["controls"]:
    rows.append([c["id"], c["title"], c["level"], c["licenceProfile"], c["section"], c["subSection"], c["assessment"],
                 "Automated by kit" if c["test"] else "Portal check", ", ".join(c["evidenceKeys"]) or "—", c["portal"] or "—",
                 c["description"], c["rationale"], c["impact"], c["audit"], c["remediation"], c["defaultValue"],
                 "\n".join(c["references"]), c["ceArea"], f'{c["ncscTitle"]} — {c["ncscUrl"]}'])
wb = Workbook(); wb.remove(wb.active)
sheet(wb, "Catalogue", ["CIS ID", "Title", "Level", "Licence profile", "Section", "Sub-section", "CIS assessment", "Kit scoring", "Evidence datasets read", "Portal path", "Description (CIS)", "Rationale (CIS)", "Impact (CIS)", "Audit procedure (CIS)", "Remediation (CIS)", "Default value (CIS)", "Microsoft Learn references", "Cyber Essentials area", "NCSC guidance"],
      rows, [9, 44, 7, 9, 26, 22, 11, 14, 36, 40, 60, 60, 50, 70, 70, 20, 60, 20, 50],
      "CIS Microsoft 365 Foundations Benchmark v7.0.0 — control catalogue (160 controls)",
      "Control text from the CIS benchmark (machine-readable definitions, 19 May 2026). Kit scoring, evidence datasets, portal paths, NCSC and Cyber Essentials mapping added by T4 Digital Futures, 21 Oct 2026. Microsoft Learn links verified at build; Microsoft moves pages, so re-check before quoting.")
ws = wb["Catalogue"]
for r in range(5, 5 + len(rows)): ws.row_dimensions[r].height = 60
# NCSC / CE reference sheet
ncsc = [["User access control", "MFA, admin accounts, Conditional Access, passwords, guest access, PIM, sharing permissions", "NCSC: Multi-factor authentication for online services", "https://www.ncsc.gov.uk/guidance/multi-factor-authentication-online-services"],
        ["User access control", "Passwords, lockout, banned lists, SSPR", "NCSC: Password administration for system owners", "https://www.ncsc.gov.uk/collection/passwords"],
        ["User access control", "Privileged roles, break-glass, admin workstations", "NCSC: Secure system administration", "https://www.ncsc.gov.uk/collection/secure-system-administration"],
        ["Secure configuration", "SPF, DKIM, DMARC, Direct Send, MailTips", "NCSC: Email security and anti-spoofing", "https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing"],
        ["Malware protection", "Defender for Office policies, attachment filtering, user reporting, Forms phishing", "NCSC: Phishing attacks — defending your organisation", "https://www.ncsc.gov.uk/guidance/phishing"],
        ["Secure configuration", "Intune compliance, enrolment, LAPS, BitLocker, device join", "NCSC: Device Security Guidance", "https://www.ncsc.gov.uk/collection/device-security-guidance"],
        ["—", "Unified audit log, mailbox auditing, alerting", "NCSC: Introduction to logging for security purposes", "https://www.ncsc.gov.uk/guidance/introduction-logging-security-purposes"],
        ["—", "Conditional Access signals, token protection, risk policies, named locations", "NCSC: Zero trust architecture design principles", "https://www.ncsc.gov.uk/collection/zero-trust-architecture"],
        ["Secure configuration", "Tenant org settings, Teams, Sway, Forms, add-ins, third-party storage", "NCSC: Using SaaS securely", "https://www.ncsc.gov.uk/collection/saas-security"],
        ["—", "DLP, sensitivity labels, sharing links, Fabric data sharing", "NCSC: Protecting bulk personal data", "https://www.ncsc.gov.uk/collection/protecting-bulk-personal-data"],
        ["—", "Customer Lockbox, Defender for Cloud Apps, service governance", "NCSC: Cloud security principles", "https://www.ncsc.gov.uk/collection/cloud/the-cloud-security-principles"],
        ["All five", "Cyber Essentials scheme requirements (firewalls, secure configuration, security update management, user access control, malware protection)", "NCSC: Cyber Essentials", "https://www.ncsc.gov.uk/cyberessentials/overview"]]
sheet(wb, "NCSC & Cyber Essentials", ["Cyber Essentials area", "Applies to (benchmark topics)", "NCSC guidance", "URL"], ncsc, [24, 70, 50, 70])
# severity model
sev = [["Critical", "Direct path to tenant compromise or large-scale data exposure with no compensating control.", "Global Administrator reachable with a password alone; no MFA enforcement; no break-glass and standing GA on daily-use mailboxes.", "Day 0 / Day 1"],
       ["High", "Materially weakens defence-in-depth; one breached layer reaches sensitive data or privilege.", "Default-permissive identity settings; unmanaged app credentials; anonymous sharing links; Defender on Built-In Protection only.", "Week 1"],
       ["Medium", "Specific weakness that can be chained, or fails a Level 1 baseline without immediate exposure.", "Mail-flow exfiltration paths; open Teams federation; permissive meeting defaults; missing DLP.", "Month 1"],
       ["Low", "Hygiene, Level 2 hardening or non-load-bearing settings. Next review cycle.", "Reporting routed to a personal mailbox; licensing-constrained items; Fabric defaults in an unused service.", "Quarter 1"]]
sheet(wb, "Severity model", ["Severity", "Definition", "Typical pattern", "Roadmap lane"], sev, [12, 70, 70, 16])
os.makedirs("out/4-Reference", exist_ok=True)
wb.save("out/4-Reference/CIS-M365-v7-Control-Catalogue.xlsx")

open("out/4-Reference/Severity-and-scoring-model.md", "w").write("""# Severity and scoring model — M365 CIS v7 Review Kit

## Status values
Pass — evidenced compliant · Fail — evidenced non-compliant · Partial — met with a specific documented gap · N/A — licence not held or service not provisioned · Manual — portal-only setting read by hand · Review — needs a human judgement · Not assessed — evidence could not be read.

## Pass rate
Assessable = Pass + Fail + Partial. Pass rate = Pass / assessable. Reported overall, per benchmark section and per profile level (L1 baseline, L2 defence-in-depth). N/A is never counted as Pass or Fail, so a tenant is not penalised for capabilities it has not bought — those go in the Licensing and scope register.

## Severity (contextual)
| Severity | Definition | Typical pattern | Lane |
|---|---|---|---|
| Critical | Direct path to tenant compromise or large-scale data exposure with no compensating control | GA reachable with a password alone; no MFA enforcement; no break-glass with standing GA on daily-use mailboxes | Day 0 / Day 1 |
| High | Materially weakens defence-in-depth; one breached layer reaches sensitive data or privilege | Default-permissive identity settings; unmanaged app credentials; anonymous links; Defender on Built-In Protection only | Week 1 |
| Medium | Specific weakness that can be chained, or fails a Level 1 baseline without immediate exposure | Mail-flow exfiltration; open Teams federation; permissive meetings; no DLP | Month 1 |
| Low | Hygiene, Level 2 hardening, non-load-bearing settings | Reporting to a personal mailbox; licensing-constrained items; Fabric defaults in an unused service | Quarter 1 |

CIS profile level says how important a control is in general; severity says how important this gap is in this tenant given what else is open. The same setting can be Medium behind a working Conditional Access baseline and High in a tenant with no MFA.

## Indicative posture score (1–10)
round(pass rate / 10), floor 1, ceiling 10, capped at 4 while any Critical draft finding exists. The reviewer sets the final score and explains it in the scorecard paragraph. September 2026 reference points: 5/10 at 36% pass rate with two Criticals (licensing context); 2/10 at 20% with no MFA enforcement.

## Draft finding grouping
The assessment groups Fail/Partial controls by benchmark sub-section and assigns a provisional severity from the sub-section (identity, Defender, SharePoint sharing = High; mail flow, Teams, Purview = Medium; org settings, Fabric = Low; groups with no Level 1 control are reduced one step). Escalations to Critical: no MFA for all users AND no MFA for admins; no break-glass combined with licensed/too many GAs. These are starting points for the reviewer.
""")
print("templates and reference written")
