// Builds the Runbook (docx) for the M365 CIS v7 Review Kit
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType, ShadingType,
        AlignmentType, BorderStyle, LevelFormat, PageBreak, Header, Footer, PageNumber, TableOfContents } = require('docx');

const NAVY = '1F3864', BLUE = '2E5597', GREY = 'C9C9C9', LIGHT = 'EEF3FB', PALE = 'F3F6FB';
const W = 9360; // text width DXA (A4 with 1" margins ≈ 9638; use 9360)

const P = (text, opts = {}) => new Paragraph({ spacing: { after: 120 }, ...opts, children: Array.isArray(text) ? text : [new TextRun({ text, size: 21 })] });
const R = (text, o = {}) => new TextRun({ text, size: 21, ...o });
const B = (text) => new TextRun({ text, size: 21, bold: true });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 360, after: 160 }, children: [new TextRun({ text: t })] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 120 }, children: [new TextRun({ text: t })] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, spacing: { before: 200, after: 80 }, children: [new TextRun({ text: t })] });
const bullet = (t, level = 0) => new Paragraph({ numbering: { reference: 'bullets', level }, spacing: { after: 60 }, children: Array.isArray(t) ? t : [R(t)] });
const num = (t, ref) => new Paragraph({ numbering: { reference: ref, level: 0 }, spacing: { after: 80 }, children: Array.isArray(t) ? t : [R(t)] });
const code = (t) => new Paragraph({ spacing: { after: 100 }, shading: { type: ShadingType.CLEAR, fill: 'F2F2F2' }, indent: { left: 200 }, children: [new TextRun({ text: t, font: 'Consolas', size: 18 })] });
const note = (title, text) => new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: [W], rows: [new TableRow({ children: [new TableCell({ width: { size: W, type: WidthType.DXA }, shading: { type: ShadingType.CLEAR, fill: LIGHT }, margins: { top: 100, bottom: 100, left: 160, right: 160 },
  borders: { top: { style: BorderStyle.SINGLE, size: 6, color: BLUE }, bottom: { style: BorderStyle.SINGLE, size: 6, color: BLUE }, left: { style: BorderStyle.SINGLE, size: 6, color: BLUE }, right: { style: BorderStyle.SINGLE, size: 6, color: BLUE } },
  children: [new Paragraph({ children: [B(title + ' '), R(text)] })] })] })] });
const spacer = () => new Paragraph({ spacing: { after: 60 }, children: [] });

function table(headers, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const cell = (t, w, head, i) => new TableCell({ width: { size: w, type: WidthType.DXA }, margins: { top: 60, bottom: 60, left: 100, right: 100 },
    shading: head ? { type: ShadingType.CLEAR, fill: NAVY } : (i === 0 ? { type: ShadingType.CLEAR, fill: PALE } : undefined),
    borders: { top: { style: BorderStyle.SINGLE, size: 4, color: GREY }, bottom: { style: BorderStyle.SINGLE, size: 4, color: GREY }, left: { style: BorderStyle.SINGLE, size: 4, color: GREY }, right: { style: BorderStyle.SINGLE, size: 4, color: GREY } },
    children: (Array.isArray(t) ? t : [t]).map(line => new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: String(line), size: 19, bold: head, color: head ? 'FFFFFF' : undefined })] })) });
  return new Table({ width: { size: total, type: WidthType.DXA }, columnWidths: widths, rows: [
    new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, widths[i], true, i)) }),
    ...rows.map(r => new TableRow({ children: r.map((c, i) => cell(c, widths[i], false, i)) })) ] });
}

const children = [];
// ---------------------------------------------------------------- cover
children.push(new Paragraph({ spacing: { before: 2400 }, children: [] }));
children.push(new Paragraph({ children: [new TextRun({ text: 'M365 CIS v7 Review Kit', size: 52, bold: true, color: NAVY })] }));
children.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Runbook — how to run a Microsoft 365 tenant security review from start to finish', size: 30, color: BLUE })] }));
children.push(new Paragraph({ spacing: { before: 200 }, children: [R('Assessment against the CIS Microsoft 365 Foundations Benchmark v7.0.0, with Microsoft Learn, NCSC and Cyber Essentials references')] }));
children.push(new Paragraph({ spacing: { before: 600 }, children: [B('Kit version 1.0 · 21 October 2026')] }));
children.push(P('Prepared by Graham Hathway, T4 Digital Futures'));
children.push(P('Works against any Microsoft 365 tenant. Read-only throughout. Runs on Windows with PowerShell 7.'));
children.push(P([new TextRun({ text: 'Classification: Internal. The evidence files and reports the kit produces are Confidential to the client.', size: 21, italics: true })]));
children.push(new Paragraph({ children: [new PageBreak()] }));

// ---------------------------------------------------------------- contents
children.push(H1('Contents'));
children.push(new TableOfContents('Contents', { hyperlink: true, headingStyleRange: '1-2' }));
children.push(P([new TextRun({ text: 'If the contents table is empty, right-click it in Word and choose Update Field.', size: 18, italics: true, color: '666666' })]));
children.push(new Paragraph({ children: [new PageBreak()] }));

// ---------------------------------------------------------------- 0
children.push(H1('Read this first'));
children.push(P('This kit lets one person run a complete CIS v7.0.0 security review of a client\'s Microsoft 365 tenant in about half a day of hands-on time: collect evidence (30–60 minutes, mostly waiting), score it (2 seconds), check the handful of settings that can only be read in a portal (20–30 minutes), then turn the generated draft into the finished report and findings register (2–4 hours of judgement and writing). The output is the same two documents the September 2026 reviews delivered: a Word report and an Excel findings register.'));
children.push(P('Three things to hold on to:'));
children.push(bullet([B('It is read-only. '), R('Every command is a Get. No app registration, secret or admin consent is created in the client tenant. If a client asks, say exactly that.')]));
children.push(bullet([B('The scripts score; you judge. '), R('The assessment script produces statuses and draft findings grouped by benchmark section. Section 6 of this runbook is where the consultant earns the fee: consolidating findings into things the client recognises, setting severities, sequencing the roadmap.')]));
children.push(bullet([B('N/A is not a pass. '), R('Where the client does not hold the licence (Entra ID P2, Defender for Office 365, E5 Compliance, Fabric), the control is N/A so the pass rate stays honest, and the gap goes in the Licensing and scope register instead.')]));
children.push(spacer());
children.push(note('What is in the kit.', 'Folder 1 is this runbook. Folder 2 is the scripts and the control catalogue they read. Folder 3 holds the report and register templates. Folder 4 is reference material: the full 160-control catalogue workbook with audit procedures, remediation, Microsoft Learn, NCSC and Cyber Essentials references, plus the severity model. Folder 5 is for worked examples — add finished reviews so new reviewers can see what finished looks like.'));
children.push(spacer());
children.push(table(['Step', 'What', 'Who', 'Time'], [
  ['1', 'Set up the machine (once)', 'Reviewer', '15 min'],
  ['2', 'Agree scope, access and break-glass accounts with the client', 'Reviewer + client', '1 email, a day of lead time'],
  ['3', 'Collect evidence — Get-M365CISEvidence.ps1', 'Reviewer (client admin signs in)', '30–60 min, mostly unattended'],
  ['4', 'Score — Invoke-M365CISAssessment.ps1', 'Reviewer', '1 min'],
  ['5', 'Portal checks and Review items', 'Reviewer', '20–30 min'],
  ['6', 'Consolidate findings, severities, roadmap', 'Reviewer', '2–3 h'],
  ['7', 'Produce the report and register, QA, deliver', 'Reviewer + peer reviewer', '1–2 h'],
], [700, 4160, 2500, 2000]));

// ---------------------------------------------------------------- 1
children.push(H1('1. Set up the machine (once)'));
children.push(P('You need a Windows PC or VM with PowerShell 7 and internet access to the PowerShell Gallery. A standard consultancy laptop is fine; nothing is installed system-wide.'));
children.push(num([B('Install PowerShell 7 '), R('if it is not already there. In a normal Windows PowerShell window: '), new TextRun({ text: 'winget install Microsoft.PowerShell', font: 'Consolas', size: 19 }), R('. Then open "PowerShell 7" from the Start menu — not the blue "Windows PowerShell".')], 'steps1'));
children.push(num([B('Unzip the kit '), R('to a folder you control, e.g. C:\\Reviews\\Kit. Keep it out of OneDrive-synced folders while running (evidence files are large and confidential).')], 'steps1'));
children.push(num([B('Run the prerequisites script '), R('from the 2-Scripts folder. It installs the six PowerShell modules for the current user and checks DNS lookups work:')], 'steps1'));
children.push(code('cd C:\\Reviews\\Kit\\2-Scripts'));
children.push(code('.\\Install-Prerequisites.ps1'));
children.push(P('If Windows blocks the script ("not digitally signed"), run: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser, then unblock the files: Get-ChildItem -Recurse | Unblock-File. Both are included in the prerequisites script but can fail on locked-down builds.'));
children.push(table(['Module', 'Used for', 'Notes'], [
  ['Microsoft.Graph.Authentication', 'Entra ID, Intune, admin-centre org settings, SharePoint tenant settings (Graph)', 'Only the Authentication module is needed; the collector calls Graph REST directly.'],
  ['ExchangeOnlineManagement', 'Exchange Online, Defender for Office 365, Purview (Security & Compliance)', 'v3.x. Two sign-ins: Connect-ExchangeOnline and Connect-IPPSSession.'],
  ['MicrosoftTeams', 'Teams federation, client, meeting, messaging and app policies', ''],
  ['Microsoft.Online.SharePoint.PowerShell', 'Get-SPOTenant — the only source for 7.2.2, 7.2.8, 7.2.10, 7.3.1 and the OneDrive setting', 'Windows only. Loads through Windows PowerShell compatibility on PowerShell 7 automatically.'],
  ['MicrosoftPowerBIMgmt', 'Fabric / Power BI tenant settings (section 9)', 'Needs Fabric Administrator. Skip if the client has no Power BI — section 9 becomes N/A.'],
  ['ImportExcel', 'Writes the findings register .xlsx', 'No Excel installation needed. Without it the assessment writes CSVs instead.'],
], [2900, 3700, 2760]));

// ---------------------------------------------------------------- 2
children.push(H1('2. Before you start: scope, access and consent'));
children.push(P('Send the client one email before the review day. It should cover the five points below; the wording in the box can be pasted.'));
children.push(bullet([B('Scope. '), R('One tenant, named by its .onmicrosoft.com domain. Say which workloads are covered (Entra, Exchange, Defender for Office, Purview, Teams, SharePoint/OneDrive, Intune, Fabric, public DNS) and that endpoint configuration, mailbox content and other tenants are out of scope.')]));
children.push(bullet([B('Read-only. '), R('State that the review uses Microsoft\'s own PowerShell tools with an existing admin account, reads settings only, changes nothing and creates no application registration or consent in their tenant.')]));
children.push(bullet([B('Account. '), R('Ask for an account with Global Reader (minimum). For Purview add Compliance Administrator or the Security & Compliance "View-Only" roles; for Fabric tenant settings, Fabric Administrator. If they would rather drive the sign-ins themselves on a screen-share, that works — the collector pauses at each sign-in.')]));
children.push(bullet([B('Break-glass accounts. '), R('Ask them to name their emergency-access accounts (if any). You pass these to the assessment so they are not reported as licensing or MFA failures, and so 2.2.1 can check they are monitored.')]));
children.push(bullet([B('Confidentiality and handling. '), R('The evidence file contains account names, licences and configuration detail. It is stored only on the reviewer\'s encrypted machine and your document library, never emailed, and deleted from the laptop when the report is signed off.')]));
children.push(spacer());
children.push(note('Suggested wording.', 'We will run a read-only security review of your Microsoft 365 tenant against the CIS Microsoft 365 Foundations Benchmark v7.0.0. The review uses Microsoft\'s own PowerShell tools signed in with an administrator account you provide; it reads settings only, changes nothing, and does not create any application or grant any consent in your tenant. Please provide an account with the Global Reader role (plus Compliance Administrator for Purview and Fabric Administrator if you use Power BI), confirm the names of any emergency-access accounts, and confirm the tenant\'s default domain. You will receive a Word report with prioritised findings and remediation steps, and an Excel register of all 160 controls.'));
children.push(spacer());
children.push(P([B('Conditional Access gotcha. '), R('If the tenant blocks device-code sign-in (a CIS control, so good tenants do), every module still works — the collector uses interactive browser sign-in by default. If the tenant requires a compliant device for admins, run the kit from a device the client manages, or ask them to exclude the reviewer account for the day and record that as a finding note.')]));

// ---------------------------------------------------------------- 3
children.push(H1('3. Collect evidence'));
children.push(P('Open PowerShell 7 in the 2-Scripts folder and run the collector with the admin account and a short client name (letters, digits and hyphens — it becomes part of the file names):'));
children.push(code('.\\Get-M365CISEvidence.ps1 -UserPrincipalName admin@contoso.com -ClientName Contoso'));
children.push(P('Expect up to six sign-in prompts, all for the same account: Graph, Exchange Online, Purview, Teams, SharePoint, Fabric. Each opens a browser window; approve MFA and come back to the console. The script prints one line per dataset — "ok (n)", "empty (collected, nothing configured)" or "FAILED" with the reason — and finishes by writing one JSON file to .\\Evidence\\ and listing any failures.'));
children.push(H2('What it collects'));
children.push(table(['Workload', 'Datasets', 'Controls'], [
  ['Graph', 'organisation, licences, domains, authorisation policy, security defaults, authentication methods, Conditional Access, named locations, group settings, directory roles and PIM schedules, access reviews, users, groups, apps, service principals, MFA registration, per-user MFA state, Secure Score, SharePoint settings, Office Store / Forms / Sway settings, Intune compliance settings and enrolment restrictions, devices', '1.x, 4.x, 5.x, 7.2.x (fallback)'],
  ['Exchange Online', 'organisation and transport config, accepted domains, anti-phish, Safe Links, Safe Attachments, anti-spam (inbound, outbound, connection), anti-malware, preset policy rules, Teams protection, user-reported settings, user tags, transport rules, DKIM, OWA and sharing policies, remote domains, external-in-Outlook, role assignment policy, all mailboxes, audit bypass', '1.2.2, 1.3.x, 2.1.x, 2.4.x, 3.1.1, 6.x, 8.6.1'],
  ['Purview', 'DLP policies and rules, sensitivity labels and label policies, alert policies, retention policies, audit config', '2.2.1, 3.x'],
  ['Teams', 'federation, client configuration, meeting / messaging / app policies', '8.x'],
  ['SharePoint Online', 'Get-SPOTenant (all tenant sharing and security settings)', '7.x'],
  ['Fabric', 'Power BI admin tenant settings', '9.x'],
  ['DNS', 'MX, SPF, DMARC and DKIM selector CNAMEs for every accepted domain', '2.1.8–2.1.10'],
], [1700, 5960, 1700]));
children.push(H2('Options'));
children.push(table(['Switch', 'Use when'], [
  ['-SkipWorkload Fabric', 'The client has no Power BI / Fabric (the sign-in would fail anyway). Section 9 is then scored N/A from the licence data.'],
  ['-Only SharePoint,Fabric', 'A sign-in failed first time round and you want to add just that workload later. The output is a second JSON in the same folder; the assessment merges every JSON it finds.'],
  ['-PerUserMfaCap 2000', 'Large tenants. Per-user MFA state is one Graph call per user; the default cap is 600 users (about 2 minutes).'],
  ['-OutputPath D:\\Reviews\\Contoso\\Evidence', 'Keep each client\'s evidence in its own folder — the assessment reads every JSON in the folder you give it.'],
], [3000, 6360]));
children.push(H2('If something fails'));
children.push(table(['Symptom', 'Cause and fix'], [
  ['Connect-MgGraph: "AADSTS65001 … consent"', 'The Microsoft Graph Command Line Tools app has not been consented in this tenant. A Global Administrator must accept the consent prompt once (it only grants the signed-in user\'s own permissions). Alternatively the client can pre-consent the app in Entra > Enterprise applications.'],
  ['Graph datasets return 403', 'The account lacks Global Reader, or PIM activation has lapsed. Activate the role and re-run with -Only Graph.'],
  ['Connect-IPPSSession fails or Purview datasets are empty', 'The account needs a Purview role (Compliance Administrator, or Global Reader with the S&C View-Only role group). Re-run with -Only Purview once granted; otherwise 3.x and 2.2.1 become Manual.'],
  ['Connect-SPOService: "The remote server returned an error: (403)"', 'SharePoint Administrator or Global Reader needed; also check the admin URL printed is https://<tenant>-admin.sharepoint.com. Section 7 falls back to Graph for most controls.'],
  ['Fabric: 401 / "not provisioned"', 'Normal when the client has no Power BI. Section 9 is N/A. If they do have it, the account needs Fabric Administrator.'],
  ['Device-code or browser sign-in blocked by Conditional Access', 'See section 2. Run from a compliant device or agree a temporary exclusion for the reviewer account.'],
  ['DNS section shows no records', 'Corporate proxy blocking DNS over the VPN. Run again off-VPN, or run -Only DNS from another machine; the file merges.'],
], [3400, 5960]));

// ---------------------------------------------------------------- 4
children.push(H1('4. Score the evidence'));
children.push(code('.\\Invoke-M365CISAssessment.ps1 -EvidencePath .\\Evidence -ClientName Contoso -PreparedBy "Your Name, Your Organisation" -PreparedFor "Jane Smith, IT Director, Contoso" -BreakGlassAccounts bg1@contoso.onmicrosoft.com,bg2@contoso.onmicrosoft.com'));
children.push(P('The script makes no network calls. It loads every JSON in the evidence folder, works out which licences the tenant holds (for the N/A decisions), evaluates all 160 controls and prints one line per control. It then writes three files to .\\Output\\:'));
children.push(table(['File', 'What it is'], [
  ['<Client>-CIS-M365-v7-Findings-Register.xlsx', 'Five sheets in the standard layout: Summary, Register (160 rows with status, evidence, CIS remediation, Microsoft Learn, NCSC and Cyber Essentials columns), Findings (draft), Licensing & scope, Evidence gaps. This is the workbook you deliver, after editing.'],
  ['<Client>-M365-Security-Review-DRAFT.html', 'The full report draft in the standard structure (cover, scorecard, compliance tables, findings, licensing register, roadmap lanes, methodology, four appendices). Open it in Word and Save As .docx. Every place that needs the reviewer is marked REVIEWER in red.'],
  ['<Client>-assessment-results.json', 'Machine-readable results. Keep it with the engagement; pass it as -PreviousResults next time to get status-vs-previous in the register.'],
], [3600, 5760]));
children.push(H2('Status values'));
children.push(table(['Status', 'Meaning', 'What you do'], [
  ['Pass', 'Evidence shows the CIS-recommended state', 'Nothing. Consider listing in "What\'s working well".'],
  ['Fail', 'Evidence shows the control is not met', 'Becomes part of a finding.'],
  ['Partial', 'Met with a specific documented gap (the evidence text says which)', 'Usually a finding, sometimes a note in a related finding.'],
  ['N/A', 'Licence not held or service not provisioned', 'Goes in the Licensing and scope register, not the pass rate. Check the licence flags printed on the Summary sheet are right.'],
  ['Manual', 'Portal-only setting; nothing automatable reads it', 'Read it in the portal (section 5), overwrite the status and evidence in the Register sheet.'],
  ['Review', 'The test found something that needs a judgement (the text says what)', 'Decide, then overwrite the status.'],
  ['Not assessed', 'The dataset the test needed was not collected', 'Re-run the collector for that workload with -Only, or check by hand and overwrite.'],
], [1500, 4000, 3860]));
children.push(P([B('Indicative posture score. '), R('The script computes a 1–10 score from the pass rate on assessable controls and caps it at 4 when a Critical draft finding exists. It is a starting point only: in the September reviews the final scores (5/10 and 2/10) were set by judgement about what the gaps mean for that client. Adjust it, and say why in the scorecard paragraph.')]));

// ---------------------------------------------------------------- 5
children.push(H1('5. Portal checks and Review items'));
children.push(P('Open the Evidence gaps sheet. It lists every Manual, Review and Not assessed control with where to look. The eight portal-only controls are the same for every tenant; the Review items vary. Record the date you read each setting in the Register\'s evidence column, in the form "Entra admin centre > Users > User settings (read 21 Oct 2026): Restrict access = No" — that wording survives into the report appendix.'));
children.push(table(['CIS ID', 'Setting', 'Where', 'Compliant value'], [
  ['5.1.2.4', 'Restrict access to Microsoft Entra admin centre', 'Entra admin centre > Users > User settings', 'Yes'],
  ['5.1.2.5', '"Stay signed in?" prompt', 'Entra admin centre > Company branding > Default sign-in > Layout', 'Show option to remain signed in = No'],
  ['5.1.2.6', 'LinkedIn account connections', 'Entra admin centre > Users > User settings', 'No'],
  ['5.1.3.2', 'Restrict user ability to access groups features in My Groups', 'Entra admin centre > Groups > General', 'Yes'],
  ['5.1.3.3', 'Owners can manage group membership requests in My Groups', 'Entra admin centre > Groups > General', 'Yes'],
  ['5.2.4.2', 'Number of methods required to reset', 'Entra admin centre > Password reset > Authentication methods', '2'],
  ['5.2.4.4', 'Notify users on password resets', 'Entra admin centre > Password reset > Notifications', 'Yes'],
  ['5.2.4.5', 'Notify all admins when other admins reset their password', 'Entra admin centre > Password reset > Notifications', 'Yes'],
  ['5.2.4.3', 'Require users to register when signing in; re-confirm days', 'Entra admin centre > Password reset > Registration', 'Yes; 180 or fewer'],
  ['8.4.1', 'Org-wide app settings', 'Teams admin centre > Teams apps > Manage apps > Actions > Org-wide app settings', 'Third-party apps Off; Custom apps Off; custom apps in preview Off'],
  ['2.2.1', 'Alert on break-glass sign-in', 'Defender portal > Policies & rules > Alert policy (or Sentinel)', 'An alert exists for each break-glass UPN'],
  ['2.4.1', 'Priority account protection and tags', 'Defender portal > Settings > Email & collaboration > Priority account protection / User tags', 'On; priority users tagged'],
  ['1.1.2', 'Break-glass accounts', 'Entra admin centre > Roles & admins > Global Administrator', 'Two cloud-only, unlicensed, excluded from CA, monitored'],
], [900, 2900, 3360, 2200]));
children.push(P('Where the SharePoint module could not connect, 7.2.2, 7.2.4, 7.2.8, 7.2.10 and 7.3.1 also appear here with the Get-SPOTenant property to read; the SharePoint admin centre > Policies > Sharing page shows the same values.'));

// ---------------------------------------------------------------- 6
children.push(H1('6. Consolidate findings, set severities, build the roadmap'));
children.push(P('The draft groups failing controls by benchmark sub-section and numbers them F-01 onwards. That is a starting point, not the finished list. A finished report has 12–20 findings, each describing one problem the client would recognise, in plain English, with the CIS IDs it closes. The two September 2026 reviews are the model: 20 and 19 findings respectively.'));
children.push(H2('6.1 Consolidate'));
children.push(bullet('Merge groups that are one problem. "No Conditional Access at all" is one finding whether it fails nine controls or seventeen. Default user permissions (5.1.2.x, 5.1.3.x, 5.1.4.6, 5.1.6.3) are one finding. SharePoint sharing (7.2.x) is one finding.'));
children.push(bullet('Split groups that are different problems. 2.1 Email & collaboration usually splits into "Defender on Built-In Protection only" (policies) and "Email authentication" (SPF/DKIM/DMARC).'));
children.push(bullet('Write the Observed cell from the evidence text — keep the exact property names and values (they are what the client\'s engineer will look for). Write Risk in 2–3 sentences about this tenant, not the generic CIS rationale. Write Recommendation as commands or click-paths that could be lifted straight into a change ticket.'));
children.push(bullet('Add the finding IDs back into the Register sheet\'s "Report finding" column so Appendix A cross-references correctly.'));
children.push(H2('6.2 Severity'));
children.push(P('CIS profiles (L1/L2) say how important a control is in general; severity says how important this gap is in this tenant, given what else is open. The same open setting is Medium behind a working Conditional Access baseline and High in a tenant with no MFA. Use the model below (it is printed in section 4 of every report).'));
children.push(table(['Severity', 'Definition', 'Typical pattern'], [
  ['Critical', 'Direct path to tenant compromise or large-scale data exposure with no compensating control', 'Global Administrator reachable with a password alone; no MFA enforcement; no break-glass with standing GA on daily-use mailboxes'],
  ['High', 'Materially weakens defence-in-depth; one breached layer reaches sensitive data or privilege', 'Default-permissive identity settings; unmanaged app credentials; anonymous sharing links; Defender on Built-In Protection only'],
  ['Medium', 'Specific weakness that can be chained, or fails a Level 1 baseline without immediate exposure', 'Mail-flow exfiltration paths; open Teams federation; permissive meeting defaults; no DLP'],
  ['Low', 'Hygiene, Level 2 hardening or non-load-bearing settings; next review cycle', 'Reporting to a personal mailbox; licensing-constrained items; Fabric defaults in an unused service'],
], [1300, 4000, 4060]));
children.push(H2('6.3 Licensing and scope register'));
children.push(P('The draft lists every N/A control with its reason, plus the licences observed and the capability flags the script used. Turn it into the L-01… table the September reports use: one row per capability (Conditional Access, PIM, access reviews, Intune compliance, Defender presets, Customer Lockbox, DLP for Teams/Copilot, Fabric…), the licence it needs, the client\'s position, and the findings it relates to. Always include the row for what is available today at no cost — Security Defaults in a tenant with no P1 is the single most useful line in the table.'));
children.push(H2('6.4 Roadmap and time estimates'));
children.push(P('Lanes are Day 0 (make it safe to change — break-glass accounts, admin MFA registration), Day 1 (close Criticals), Week 1 (Highs), Month 1 (Mediums, classification), Quarter 1 (Level 2 and licensing decisions). Every task gets an approximate time for a familiar Entra/Exchange administrator, excluding change approval and communications, and an owner of TBC. Sequence deliberately: enabling Security Defaults or an MFA policy before break-glass exists locks the tenant out, and the report must say so.'));
children.push(table(['Typical task', 'Approx. time'], [
  ['Create two break-glass accounts, exclude from CA, add alert', '45 min'],
  ['Enable Security Defaults (after admin MFA registration)', '15 min'],
  ['Lock default user permissions (apps, tenants, groups, BitLocker, invitations)', '45 min'],
  ['Assign Standard preset security policy; tag priority accounts', '1 h'],
  ['SharePoint sharing baseline (link type, permission, expiry, domain list)', '1 h'],
  ['Block auto-forwarding, Direct Send, enable external tag and MailTips', '45 min'],
  ['Teams federation and meeting policy baseline', '1 h'],
  ['Conditional Access baseline (once P1 held): MFA all users, admins, legacy auth, device', '4 h'],
  ['Baseline sensitivity labels and one DLP policy', '2 h'],
], [6360, 3000]));

// ---------------------------------------------------------------- 7
children.push(H1('7. Produce the report and register'));
children.push(num('Open the HTML draft in Word (File > Open, choose the .html). Save As .docx immediately. Word keeps the headings, tables and colours.', 'steps7'));
children.push(num('Replace the Contents line with a live table: References > Table of Contents. Set the header to "<Client> — Microsoft 365 Security Review · CIS v7.0.0 · Confidential" and the footer to "your organisation · Page X of Y", as in the template in folder 3 (set your organisation name in the footer).', 'steps7'));
children.push(num('Work through every red REVIEWER prompt: Read-this-first box, executive summary bullets (4–7, each ending with a finding ID), scorecard paragraph, scope note, per-finding Baseline and Risk, roadmap owners and times, Cyber Essentials verdict. Delete the prompts as you go — search for "REVIEWER" at the end; the count must be zero.', 'steps7'));
children.push(num('Replace the auto-grouped findings in sections 7 and 8 with the consolidated set from section 6, and make sure Appendix A\'s Finding column matches.', 'steps7'));
children.push(num('Open the register workbook. Edit the Findings sheet to match the report exactly (same IDs, severities, wording). Fill the Owner and Approximate time columns. Overwrite Manual / Review statuses in the Register sheet with what you read. Check the Summary counts still reconcile with the report\'s section 3 table.', 'steps7'));
children.push(num('Set version 1.0, the date and the recipient on the cover and in the revision history.', 'steps7'));
children.push(H2('QA checklist (peer reviewer)'));
children.push(table(['Check', 'How'], [
  ['Counts reconcile', 'Section 3 total row = Register sheet Summary; Pass + Fail + Partial + N/A + manual-read + not-assessed = 160'],
  ['No REVIEWER prompts left', 'Ctrl+F "REVIEWER" in Word → 0 results'],
  ['Every finding has CIS IDs, Observed, Risk, Recommendation, Microsoft Learn, time', 'Scan section 8; blank cells are not acceptable'],
  ['Appendix A cross-references', 'Every Fail/Partial row names a finding; every finding\'s IDs appear in Appendix A'],
  ['Microsoft Learn links resolve', 'Click five at random; the catalogue links were verified at kit build (21 Oct 2026), Microsoft moves pages'],
  ['Names and tenant IDs are the client\'s', 'Search for "Contoso" and previous client names to catch pasted examples'],
  ['Sequencing stated', 'Day 0 lane exists whenever an MFA or CA change is recommended'],
  ['Classification and handling', 'Cover says Confidential; files named <Client>-M365-Security-Review-CIS-v7.docx and <Client>-CIS-M365-v7-Findings-Register.xlsx'],
], [3400, 5960]));

// ---------------------------------------------------------------- 8
children.push(H1('8. Deliver and close'));
children.push(bullet('Upload the .docx, the .xlsx and the evidence JSON to the client\'s folder in your document library. Share the two documents with the client through a restricted link; never attach the evidence file to email.'));
children.push(bullet('Keep <Client>-assessment-results.json with the engagement; it drives the status-vs-previous column at the next review.'));
children.push(bullet('Delete the evidence folder from the laptop once the report is accepted. Sign out of all six services (the collector disconnects, but browser sessions persist).'));
children.push(bullet('Offer the follow-up: a re-run in 90 days costs an hour of collection and shows the trend; the Register\'s Previous status column does the comparison.'));

// ---------------------------------------------------------------- 9
children.push(H1('9. Re-runs and trend'));
children.push(code('.\\Invoke-M365CISAssessment.ps1 -EvidencePath .\\Evidence -ClientName Contoso -PreviousResults ..\\2026-10\\Output\\Contoso-assessment-results.json'));
children.push(P('The Register sheet then carries a Previous status column. In the report, the Baseline row of each finding becomes "Open since <date>", "Improved" or "Closed", and section 1 gets a sentence on movement. Keep the same finding IDs for problems that persist so the client can track them.'));

// ---------------------------------------------------------------- 10
children.push(H1('10. Maintaining the kit'));
children.push(P('Everything the scripts know about the benchmark lives in one file: 2-Scripts\\controls\\cis-m365-v7-controls.json. Each control carries its CIS text (description, rationale, impact, audit and remediation procedures, default value), the Microsoft Learn references, the NCSC guidance and Cyber Essentials area, the evidence datasets it reads, the portal path, and the test — a short PowerShell block that returns Pass, Fail, Partial, N/A, Manual or Review with an evidence sentence.'));
children.push(bullet([B('A test is wrong for a tenant. '), R('Overwrite the status in the Register sheet for that review, and note the control ID and why in the kit change log so the test can be corrected.')]));
children.push(bullet([B('Microsoft renames a property. '), R('The control reports "Test error: …" or an empty value. Fix the test text in the JSON; the collector may also need the endpoint updated.')]));
children.push(bullet([B('New benchmark version. '), R('CIS publishes v7.1 / v8: the control definitions are rebuilt from the machine-readable benchmark data and the tests re-mapped by ID. Expect a day\'s work; most tests carry over unchanged.')]));
children.push(bullet([B('Where things came from. '), R('Control definitions and references: CIS Microsoft 365 Foundations Benchmark v7.0.0 (19 May 2026) via the open-source Prowler compliance data. Audit logic, evidence collection and report structure: two client reviews delivered in September 2026. NCSC mapping: NCSC Cyber Essentials requirements and published guidance collections.')]));

// ---------------------------------------------------------------- appendix
children.push(H1('Appendix A — Roles and permissions'));
children.push(table(['Workload', 'Minimum role for the signed-in account', 'Delegated Graph scopes requested'], [
  ['Graph (Entra, Intune, org settings)', 'Global Reader', 'Directory.Read.All, Policy.Read.All, Policy.Read.ConditionalAccess, RoleManagement.Read.Directory, Application.Read.All, Group.Read.All, User.Read.All, Organization.Read.All, Domain.Read.All, Reports.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, SecurityEvents.Read.All, SharePointTenantSettings.Read.All, DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All, DeviceManagementManagedDevices.Read.All, AccessReview.Read.All, RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.Read.Directory, RoleManagementPolicy.Read.Directory, OrgSettings-AppsAndServices.Read.All, OrgSettings-Forms.Read.All, ReportSettings.Read.All'],
  ['Exchange Online / Defender for Office', 'Global Reader (View-Only Organization Management)', 'n/a — Exchange RBAC'],
  ['Purview', 'Compliance Administrator, or Global Reader plus the Security & Compliance "View-Only" role groups', 'n/a'],
  ['Teams', 'Global Reader or Teams Administrator', 'n/a'],
  ['SharePoint Online', 'Global Reader or SharePoint Administrator', 'n/a'],
  ['Fabric / Power BI', 'Fabric Administrator', 'n/a — Power BI admin API'],
], [2400, 3000, 3960]));
children.push(P('All scopes are read-only delegated permissions. The signed-in account\'s own role is the ceiling: a delegated scope cannot read anything the account could not read in the portal.'));

children.push(H1('Appendix B — Command reference'));
children.push(code('.\\Install-Prerequisites.ps1'));
children.push(code('.\\Get-M365CISEvidence.ps1 -UserPrincipalName <upn> -ClientName <Client> [-OutputPath <folder>] [-SkipWorkload <list>] [-Only <list>] [-PerUserMfaCap <n>]'));
children.push(code('.\\Invoke-M365CISAssessment.ps1 -EvidencePath <folder or file> [-ClientName <Client>] [-BreakGlassAccounts <upn,upn>] [-PreparedBy <text>] [-PreparedFor <text>] [-OutputPath <folder>] [-PreviousResults <json>]'));
children.push(P('Get-Help .\\Get-M365CISEvidence.ps1 -Full shows the same in the console.'));

children.push(H1('Appendix C — Severity, scoring and pass-rate definitions'));
children.push(bullet('Assessable controls = Pass + Fail + Partial. Pass rate = Pass ÷ assessable. N/A, Manual, Review and Not assessed are excluded until resolved.'));
children.push(bullet('Level 1 / Level 2 pass rates are reported separately; Level 1 is the baseline every tenant should meet.'));
children.push(bullet('Indicative posture score = round(pass rate ÷ 10), floor 1, ceiling 10, capped at 4 if any Critical draft finding exists. The reviewer sets the final score.'));
children.push(bullet('Severity: contextual (Appendix 6.2). Profile level never overrides severity; a Level 2 control can be High in the right context.'));

children.push(H1('Appendix D — Glossary'));
children.push(table(['Term', 'Meaning'], [
  ['CIS / L1 / L2', 'Center for Internet Security benchmark; Level 1 baseline, Level 2 defence-in-depth'],
  ['Security Defaults', 'Free Microsoft preset: MFA registration for all, MFA for admins, legacy authentication blocked'],
  ['Conditional Access', 'Entra policy engine; requires Entra ID P1'],
  ['PIM', 'Privileged Identity Management — just-in-time admin roles; requires Entra ID P2'],
  ['Break-glass', 'Emergency-access account: cloud-only, unlicensed, excluded from CA, monitored'],
  ['Preset security policy', 'Microsoft-maintained Standard / Strict Defender for Office bundles'],
  ['Built-In Protection', 'Lowest-priority Defender tier applied when nothing is assigned'],
  ['Direct Send', 'Unauthenticated SMTP delivery to the tenant\'s MX from any host'],
  ['DLP / sensitivity label', 'Purview data loss prevention and classification'],
  ['SPF / DKIM / DMARC', 'Email authentication: authorised senders / signing / policy and reporting'],
  ['Cyber Essentials', 'NCSC-backed UK certification: firewalls, secure configuration, security update management, user access control, malware protection'],
], [2400, 6960]));

const doc = new Document({
  creator: 'T4 Digital Futures', title: 'M365 CIS v7 Review Kit — Runbook',
  styles: { default: { document: { run: { font: 'Calibri', size: 21 } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 32, bold: true, color: NAVY, font: 'Calibri' }, paragraph: { spacing: { before: 360, after: 160 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 26, bold: true, color: BLUE, font: 'Calibri' }, paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
      { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 22, bold: true, color: BLUE, font: 'Calibri' }, paragraph: { spacing: { before: 200, after: 80 }, outlineLevel: 2 } },
    ] },
  numbering: { config: [
    { reference: 'bullets', levels: [ { level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } }, { level: 1, format: LevelFormat.BULLET, text: '–', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1000, hanging: 270 } } } } ] },
    { reference: 'steps1', levels: [ { level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 360 } } } } ] },
    { reference: 'steps7', levels: [ { level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 360 } } } } ] },
  ] },
  sections: [{
    properties: { page: { margin: { top: 1200, bottom: 1100, left: 1250, right: 1250 } } },
    headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: 'M365 CIS v7 Review Kit · Runbook', size: 16, color: '666666' })] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: 'Page ', size: 16, color: '666666' }), new TextRun({ children: [PageNumber.CURRENT], size: 16, color: '666666' }), new TextRun({ text: ' of ', size: 16, color: '666666' }), new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, color: '666666' })] })] }) },
    children,
  }],
});
Packer.toBuffer(doc).then(buf => { fs.mkdirSync('out/1-Runbook', { recursive: true }); fs.writeFileSync('out/1-Runbook/M365 CIS v7 Review Kit - Runbook.docx', buf); console.log('runbook written'); });
