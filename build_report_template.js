// Report template (docx) — same structure as the September 2026 client reviews, with placeholders
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell, WidthType, ShadingType, AlignmentType, BorderStyle, PageBreak, Header, Footer, PageNumber, TableOfContents, LevelFormat } = require('docx');
const NAVY = '1F3864', BLUE = '2E5597', GREY = 'C9C9C9', LIGHT = 'EEF3FB', PALE = 'F3F6FB', W = 9360;
const R = (t, o = {}) => new TextRun({ text: t, size: 21, ...o });
const G = (t) => new TextRun({ text: t, size: 20, italics: true, color: '7F7F7F' }); // guidance placeholder
const P = (ch, o = {}) => new Paragraph({ spacing: { after: 120 }, ...o, children: Array.isArray(ch) ? ch : [R(ch)] });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const bullet = (ch) => new Paragraph({ numbering: { reference: 'bullets', level: 0 }, spacing: { after: 60 }, children: Array.isArray(ch) ? ch : [R(ch)] });
const box = (ch) => new Table({ width: { size: W, type: WidthType.DXA }, columnWidths: [W], rows: [new TableRow({ children: [new TableCell({ width: { size: W, type: WidthType.DXA }, shading: { type: ShadingType.CLEAR, fill: LIGHT }, margins: { top: 100, bottom: 100, left: 160, right: 160 },
  borders: { top: { style: BorderStyle.SINGLE, size: 6, color: BLUE }, bottom: { style: BorderStyle.SINGLE, size: 6, color: BLUE }, left: { style: BorderStyle.SINGLE, size: 6, color: BLUE }, right: { style: BorderStyle.SINGLE, size: 6, color: BLUE } },
  children: [new Paragraph({ children: Array.isArray(ch) ? ch : [R(ch)] })] })] })] });
function table(headers, rows, widths, firstColShade = false) {
  const cell = (t, w, head, i) => new TableCell({ width: { size: w, type: WidthType.DXA }, margins: { top: 60, bottom: 60, left: 100, right: 100 },
    shading: head ? { type: ShadingType.CLEAR, fill: NAVY } : ((firstColShade && i === 0) ? { type: ShadingType.CLEAR, fill: PALE } : undefined),
    borders: { top: { style: BorderStyle.SINGLE, size: 4, color: GREY }, bottom: { style: BorderStyle.SINGLE, size: 4, color: GREY }, left: { style: BorderStyle.SINGLE, size: 4, color: GREY }, right: { style: BorderStyle.SINGLE, size: 4, color: GREY } },
    children: [new Paragraph({ spacing: { after: 0 }, children: [new TextRun({ text: String(t), size: 19, bold: head || (firstColShade && i === 0), color: head ? 'FFFFFF' : undefined })] })] });
  return new Table({ width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA }, columnWidths: widths, rows: [
    ...(headers ? [new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, widths[i], true, i)) })] : []),
    ...rows.map(r => new TableRow({ children: r.map((c, i) => cell(c, widths[i], false, i)) })) ] });
}
const sp = () => new Paragraph({ spacing: { after: 80 }, children: [] });
const c = [];
c.push(new Paragraph({ spacing: { before: 2600 }, children: [] }));
c.push(new Paragraph({ children: [new TextRun({ text: '<Client>', size: 56, bold: true, color: NAVY })] }));
c.push(new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: 'Microsoft 365 Tenant — Security Review', size: 32, color: BLUE })] }));
c.push(P('Assessment against the CIS Microsoft 365 Foundations Benchmark v7.0.0'));
c.push(new Paragraph({ spacing: { before: 500 }, children: [R('Prepared by')] }));
c.push(P([new TextRun({ text: '<Name>, <Title> — <Organisation>', size: 21, bold: true })]));
c.push(P('<Day Month Year>'));
c.push(P('Version 1.0 — for <Recipient name>, <Client>'));
c.push(P('Classification: Confidential — contains tenant identifiers, account names and configuration detail'));
c.push(new Paragraph({ children: [new PageBreak()] }));
c.push(H1('Revision history'));
c.push(table(['Version', 'Date', 'Author', 'Notes'], [['1.0', '<yyyy-mm-dd>', '<Name>, <Organisation>', 'First assessment of the <Client> tenant against CIS Microsoft 365 Foundations Benchmark v7.0.0 / Re-assessment superseding the <date> review']], [1200, 1400, 2600, 4160]));
c.push(sp());
c.push(box([new TextRun({ text: 'Read this first. ', size: 21, bold: true }), G('Five lines at most: first assessment or re-run; evidence date and method; the one or two findings that matter most; the single most important sequencing point (e.g. create break-glass accounts before enabling MFA).')]));
c.push(sp());
c.push(H1('Contents'));
c.push(new TableOfContents('Contents', { hyperlink: true, headingStyleRange: '1-2' }));
c.push(P([G('Right-click and Update Field after editing.')]));
c.push(new Paragraph({ children: [new PageBreak()] }));

c.push(H1('1. Executive summary'));
c.push(P([R('This review assesses the <Client> Microsoft 365 tenant (<tenant>.onmicrosoft.com) against the CIS Microsoft 365 Foundations Benchmark v7.0.0 — 160 recommendations across Level 1 and Level 2 profiles. '), G('First assessment, or supersedes the <date> review. '), R('All evidence was collected read-only on <date> through Microsoft Graph, Exchange Online, Purview, Teams, SharePoint Online and public DNS. No setting was changed.')]));
c.push(P('Of the 160 recommendations, <n> were assessed: <p> pass, <f> fail, <x> are partially met and <na> do not apply (licence not held or service not provisioned). <u> could not be read (Section 11). The pass rate on assessable controls is <r>%.'));
c.push(P([G('The single most important finding is not a subtle one: — then 4–7 bullets, plain English, each ending with its finding ID.')]));
c.push(bullet([G('<Finding in one or two sentences> (F-01).')]));
c.push(bullet([G('<Finding> (F-02).')]));
c.push(P('The <n> consolidated findings (<c> Critical, <h> High, <m> Medium, <l> Low) follow in Section 8, each with the CIS control IDs it closes, the observed configuration, the risk, the remediation and Microsoft Learn references. The accompanying workbook (<Client>-CIS-M365-v7-Findings-Register.xlsx) holds the full 160-row control register, the findings, the licensing and scope register and the remaining evidence gaps.'));
c.push(P([new TextRun({ text: 'A note on sequencing: ', size: 21, bold: true }), G('what must happen before what, in one sentence.')]));

c.push(H1('2. Posture scorecard'));
c.push(table(null, [['<n> / 10\nOverall posture', '<One paragraph characterising the tenant: what kind of organisation this is, what is working, what the score reflects and what would move it.>']], [2000, 7360], true));
c.push(sp()); c.push(P('Breakdown by area:')); c.push(P([G('Optional: one line per benchmark section with a word on where it stands.')]));

c.push(H1('3. CIS v7.0.0 compliance summary'));
c.push(P("Status per control is recorded in the workbook's Register sheet and reproduced in Appendix A. The table below summarises by benchmark section. 'Assessable' excludes controls that could not be read and those marked not applicable."));
c.push(table(['Section', 'Controls', 'Pass', 'Fail', 'Partial', 'N/A', 'Not assessed', 'Pass rate (assessable)'], [
  ['1 Microsoft 365 admin center', '15', '', '', '', '', '', ''], ['2 Microsoft Defender', '21', '', '', '', '', '', ''], ['3 Microsoft Purview', '5', '', '', '', '', '', ''], ['4 Microsoft Intune admin center', '2', '', '', '', '', '', ''],
  ['5 Microsoft Entra admin center', '63', '', '', '', '', '', ''], ['6 Exchange admin center', '13', '', '', '', '', '', ''], ['7 SharePoint admin center', '12', '', '', '', '', '', ''], ['8 Microsoft Teams admin center', '17', '', '', '', '', '', ''], ['9 Microsoft Fabric', '12', '', '', '', '', '', ''], ['Total', '160', '', '', '', '', '', '']], [2800, 900, 800, 800, 900, 800, 1200, 1160]));
c.push(sp());
c.push(table(['Profile level', 'Pass', 'Fail', 'Partial', 'Pass rate'], [['Level 1 (baseline)', '', '', '', ''], ['Level 2 (defence-in-depth)', '', '', '', '']], [3360, 1500, 1500, 1500, 1500]));
c.push(P([new TextRun({ text: 'Legend: ', size: 19, bold: true }), new TextRun({ text: 'Pass — evidenced compliant · Fail — evidenced non-compliant · Partial — met with a specific documented gap · N/A — licence not held, or the service is not provisioned in this tenant · Not assessed — setting could not be read (Section 11).', size: 19 })]));

c.push(H1('4. Severity model and methodology'));
c.push(P('CIS profiles (Level 1 / Level 2) say how important a control is in general; the severities below say how important each gap is in this tenant, given the other controls observed alongside it. Severity is deliberately contextual: an open setting matters more here than it would in a tenant that still had an identity perimeter behind it.'));
c.push(table(['Severity', 'Definition', 'Typical pattern in this review'], [
  ['Critical', 'Direct path to tenant compromise or large-scale data exposure with no compensating control.', '<pattern seen>'],
  ['High', 'Materially weakens defence-in-depth; one breached layer reaches sensitive data or privilege.', '<pattern seen>'],
  ['Medium', 'Specific weakness that can be chained, or fails a Level 1 baseline without immediate exposure.', '<pattern seen>'],
  ['Low', 'Hygiene, Level 2 hardening or non-load-bearing settings. Next review cycle.', '<pattern seen>']], [1300, 4300, 3760]));
c.push(sp());
c.push(P('Each control was tested against the CIS v7.0.0 audit procedure using the live value read from Microsoft Graph, the relevant PowerShell cmdlet, public DNS or the admin portal (Appendix A names the evidence for every assessed control). Where a setting could not be read it is marked Not assessed rather than inferred, and where a capability is not licensed or not provisioned it is marked N/A rather than Fail, so the pass rate is not distorted by things the tenant could not do. Recommendations are written in operational form so they can be lifted into change tickets, and every finding carries Microsoft Learn references verified as current on <date>, with the relevant NCSC guidance and Cyber Essentials control area.'));

c.push(H1("5. What's working well"));
c.push(P('<n> controls pass. It is worth being explicit about these, because a report with this many failures can read as though nothing is right — and that is not the case. The items below are working, and should be preserved through remediation rather than disturbed by it.'));
c.push(bullet([G('<Thing that works, with the control ID and evidence>')]));

c.push(H1('6. Tenant context'));
c.push(table(null, [['Tenant', '<tenant>.onmicrosoft.com (default domain <domain>)'], ['Tenant ID', '<guid>'], ['Accepted domains', '<list>'], ['Licensing observed', '<SKU (seats), …>'], ['Users', '<n> user objects — <e> enabled, <g> guests; <ga> Global Administrators'], ['Devices', '<n> registered devices — <m> managed, <c> compliant'], ['Collection method', 'Read-only delegated sign-in as <account> using Microsoft\'s first-party PowerShell clients on <date>. No app registration, secret or consent created. No setting changed.'], ['Benchmark', 'CIS Microsoft 365 Foundations Benchmark v7.0.0 (published 19 May 2026), 160 recommendations'], ['Supplementary evidence', 'Entra, Microsoft 365, SharePoint and Teams admin centres read directly for portal-only settings; public DNS for all mail-routing domains'], ['Findings', '<n> consolidated (<c> Critical, <h> High, <m> Medium, <l> Low)']], [2400, 6960], true));
c.push(sp());
c.push(box([new TextRun({ text: 'Scope note. ', size: 21, bold: true }), R('This review covers the <Client> tenant only. '), G('Name anything explicitly out of scope.')]));

c.push(H1('7. Findings at a glance'));
c.push(table(null, [['<c>\nCritical', '<h>\nHigh', '<m>\nMedium', '<l>\nLow']], [2340, 2340, 2340, 2340]));
c.push(sp());
c.push(table(['ID', 'Severity', 'Area', 'Finding', 'CIS controls'], [['F-01', 'Critical', '<Area>', '<One sentence>', '<ids>'], ['F-02', 'High', '', '', '']], [800, 1100, 1900, 3760, 1800]));

c.push(H1('8. Detailed findings'));
c.push(P([G('One table per finding, in the format below. Keep the row labels exactly; the register workbook mirrors them.')]));
c.push(table(null, [['F-01  [Critical]  <Finding title>', ''], ['Area', '<Area>'], ['CIS v7 controls', '<ids>'], ['Baseline', 'New — first assessment of this tenant / Open since <date> / Improved since <date>'], ['Observed', '<exact properties and values, one per line>'], ['Risk', '<2–3 sentences specific to this tenant>'], ['Recommendation', '<commands or click-paths, in order, that could be lifted into a change ticket>'], ['Microsoft Learn', '📘 <Title> — <url>'], ['NCSC / Cyber Essentials', '<CE control area> · <NCSC guidance title> — <url>'], ['Approximate time', '<n> hr']], [2200, 7160], true));

c.push(H1('9. Licensing and scope register'));
c.push(P('Which recommendations the tenant\'s current subscriptions prevent it from meeting, which are simply not provisioned, and which are available today at no cost. It is the concrete answer to "what would an uplift actually buy?" — and, just as usefully, what does not need buying at all.'));
c.push(table(['Ref', 'Control / capability', 'Licence required', 'Position in this tenant', 'Related finding(s)'], [['L-01', 'Conditional Access (all policies, CIS 5.2.2.x)', 'Entra ID P1', '<position>', '<ids>'], ['L-02', '', '', '', '']], [800, 3300, 1800, 2260, 1200]));
c.push(sp());
c.push(box([G('Call out the one line that matters most — often the free capability the tenant is not using.')]));

c.push(H1('10. Remediation roadmap'));
c.push(P('Times are approximate, for a familiar Entra/Exchange administrator working from Graph, Exchange Online and SharePoint Online PowerShell; they exclude change approval and user communications. Owners are to be confirmed. The lanes are sequenced deliberately.'));
for (const lane of ['Day 0 — make it safe to change', 'Day 1 — close the Critical findings', 'Week 1 — close the High findings', 'Month 1 — harden and classify', 'Quarter 1 — Level 2 and licensing decisions']) {
  c.push(H2(lane)); c.push(table(['ID', 'Approx. time', 'Owner', 'Task'], [['F-0x', '<n> min', 'TBC', '<task>']], [900, 1300, 1000, 6160]));
}
c.push(sp()); c.push(P([G('Total estimated effort: about <n> hours Day 0, … — roughly <n> consultant-days to reach the end of Month 1. The first <n> hours carry most of the risk reduction in this report.')]));

c.push(H1('11. Methodology, scope and evidence gaps'));
c.push(H2('Method'));
c.push(P('The 160 v7.0.0 recommendations were loaded from the benchmark\'s machine-readable control definitions (ID, profile, audit and remediation procedure, references). Each was then tested against a live value read on <date>. Evidence was collected read-only through a delegated interactive sign-in as <account> using Microsoft\'s first-party PowerShell clients, so no application registration, client secret or admin consent was created in the client tenant for the purposes of this review. Settings that neither Graph nor PowerShell exposes were read directly in the admin portals, and each such control records the portal path and the date it was read. No setting was changed at any point.'));
c.push(H2('In scope')); c.push(bullet([G('One bullet per workload listing what was read (counts where useful).')]));
c.push(H2('Not assessed — evidence required (<n> controls)')); c.push(table(['Section', 'Controls not assessed'], [['<section>', '<ids and why>']], [3000, 6360]));
c.push(H2('Not applicable rather than failed')); c.push(P([G('Explain the N/A decisions and any caveat (e.g. Fabric position holds only while self-service sign-up stays enabled).')]));
c.push(H2('Out of scope')); c.push(P('Real-time signal (sign-in risk events, alert history, Secure Score trend), Defender for Endpoint / Identity / Cloud Apps tuning, endpoint configuration baselines, the content of mailboxes and SharePoint sites, and other tenants.'));

c.push(H1('Appendix A — Full control register (CIS v7.0.0)'));
c.push(P("One row per recommendation. 'Evidence' names the live value read — the Graph property, PowerShell cmdlet output, DNS record or admin-portal setting. The workbook carries the same table with the full remediation text and Microsoft Learn hyperlinks."));
c.push(table(['ID', 'Recommendation', 'L', 'Status', 'Evidence', 'Finding'], [['1.1.1', 'Administrative accounts are cloud-only', 'L1', '', '', ''], ['…', '', '', '', '', '']], [800, 3000, 500, 900, 3360, 800]));
c.push(H1('Appendix B — Glossary'));
c.push(table(['Term', 'Definition'], [['CIS / L1 / L2', 'Center for Internet Security benchmark; Level 1 = baseline every tenant should meet; Level 2 = defence-in-depth, may affect usability.'], ['Security Defaults', 'A free, tenant-wide Microsoft preset that forces MFA registration, requires MFA for admins and blocks legacy authentication.'], ['Conditional Access (CA)', 'Policy engine that evaluates signals (user, device, location, risk) and grants, limits or blocks access. Requires Entra ID P1.'], ['Entra ID P1 / P2', 'Licence tiers. P1 brings Conditional Access; P2 adds Privileged Identity Management, Identity Protection and access reviews.'], ['Break-glass', 'Emergency-access account excluded from Conditional Access, unlicensed, cloud-only, with monitored sign-ins.'], ['PIM / JIT', 'Privileged Identity Management — just-in-time, time-bound activation of admin roles with approval and audit.'], ['Preset security policy', 'Microsoft-maintained Standard and Strict bundles of Defender for Office 365 and EOP settings.'], ['Direct Send', 'Unauthenticated SMTP delivery straight to the tenant\'s MX record from any host on the internet.'], ['DMARC / SPF / DKIM', 'Email authentication: policy for unaligned mail / authorised sending hosts / cryptographic signing of outbound mail.'], ['LAPS', 'Windows Local Administrator Password Solution — rotates and escrows local admin passwords in Entra ID.']], [2400, 6960]));
c.push(H1('Appendix C — UK Cyber Essentials alignment'));
c.push(P([R('Mapping of the findings to the five Cyber Essentials control areas (firewalls and internet gateways, secure configuration, security update management, user access control, malware protection). Cyber Essentials Plus additionally requires a hands-on assessment of endpoint configuration, which is outside this tenant review. '), G('State whether, on this evidence, the tenant would pass a Cyber Essentials assessment and which area is the binding constraint.')]));
c.push(table(['Cyber Essentials control area', 'Findings', 'Position'], [['User access control', '<ids>', '<one line>'], ['Secure configuration', '', ''], ['Malware protection', '', ''], ['Security update management', '', ''], ['Firewalls and internet gateways', '', '']], [3000, 2000, 4360]));
c.push(H1('Appendix D — Microsoft Secure Score mapping'));
c.push(P('Each finding maps to one or more Secure Score improvement actions. Point values vary by licence and change over time, so they are deliberately not estimated here — read the live values in the Defender portal and use this table to attribute the uplift. Secure Score at collection: <n> / <max> on <date>.'));
c.push(table(['Finding', 'Secure Score improvement action(s)'], [['F-01', '<action names as shown in the Defender portal>']], [1500, 7860]));
c.push(H1('Appendix E — NCSC guidance references'));
c.push(table(['NCSC guidance', 'URL', 'Related findings'], [['Multi-factor authentication for online services', 'https://www.ncsc.gov.uk/guidance/multi-factor-authentication-online-services', ''], ['Email security and anti-spoofing', 'https://www.ncsc.gov.uk/collection/email-security-and-anti-spoofing', ''], ['Phishing attacks: defending your organisation', 'https://www.ncsc.gov.uk/guidance/phishing', ''], ['Secure system administration', 'https://www.ncsc.gov.uk/collection/secure-system-administration', ''], ['Device Security Guidance', 'https://www.ncsc.gov.uk/collection/device-security-guidance', ''], ['Cloud security principles', 'https://www.ncsc.gov.uk/collection/cloud/the-cloud-security-principles', ''], ['Cyber Essentials', 'https://www.ncsc.gov.uk/cyberessentials/overview', '']], [3200, 4360, 1800]));

const doc = new Document({ creator: 'T4 Digital Futures', title: '<Client> — Microsoft 365 Security Review (CIS v7.0.0)',
  styles: { default: { document: { run: { font: 'Calibri', size: 21 } } }, paragraphStyles: [
    { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 32, bold: true, color: NAVY, font: 'Calibri' }, paragraph: { spacing: { before: 360, after: 160 }, outlineLevel: 0 } },
    { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 26, bold: true, color: BLUE, font: 'Calibri' }, paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } } ] },
  numbering: { config: [{ reference: 'bullets', levels: [{ level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] }] },
  sections: [{ properties: { page: { margin: { top: 1200, bottom: 1100, left: 1250, right: 1250 } } },
    headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: '<Client> — Microsoft 365 Security Review · CIS v7.0.0 · Confidential', size: 16, color: '666666' })] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ text: '<Organisation> · Page ', size: 16, color: '666666' }), new TextRun({ children: [PageNumber.CURRENT], size: 16, color: '666666' }), new TextRun({ text: ' of ', size: 16, color: '666666' }), new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, color: '666666' })] })] }) },
    children: c }] });
Packer.toBuffer(doc).then(b => { fs.mkdirSync('out/3-Templates', { recursive: true }); fs.writeFileSync('out/3-Templates/M365-Security-Review-Report-Template.docx', b); console.log('report template written'); });
