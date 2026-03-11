const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

/**
 * Professional Security Report Generator using Typst
 * Produces informative, objective PDF documents for security teams
 */
class PDFGenerator {
  constructor() {
    this.colors = {
      primary: 'rgb(26, 54, 93)',
      secondary: 'rgb(45, 55, 72)',
      accent: 'rgb(49, 130, 206)',
      highlight: 'rgb(156, 39, 176)',
      muted: 'rgb(113, 128, 150)',
    };
  }

  async generateReport(findings, config) {
    const timestamp = new Date();
    const dateStr = timestamp.toISOString().split('T')[0];

    // Create results folder if it doesn't exist
    const resultsDir = path.join(process.cwd(), 'results');
    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const typstFile = path.join(resultsDir, `report-${dateStr}.typ`);
    const pdfFile = path.join(resultsDir, `okta-security-report-${dateStr}.pdf`);
    const rawFile = path.join(resultsDir, `okta-security-raw-${dateStr}.txt`);

    const stats = this.calculateStatistics(findings);
    const typstContent = this.generateTypstDocument(findings, config, stats, timestamp);

    fs.writeFileSync(typstFile, typstContent, 'utf8');

    // Generate raw text file with all events for deep investigation
    const rawContent = this.generateRawTextFile(findings, config, stats, timestamp);
    fs.writeFileSync(rawFile, rawContent, 'utf8');

    try {
      execSync(`typst compile "${typstFile}" "${pdfFile}"`, { stdio: 'pipe' });
      fs.unlinkSync(typstFile);
      return { pdfFile, rawFile };
    } catch (error) {
      throw new Error(`Typst compilation failed: ${error.message}`);
    }
  }

  generateRawTextFile(findings, config, stats, timestamp) {
    const domain = config.okta?.domain || 'Unknown';
    const sinceRaw = config.query?.since;
    let analysisPeriod = 'Last 90 days';
    if (sinceRaw) {
      const sinceDate = new Date(sinceRaw);
      analysisPeriod = `${sinceDate.toISOString()} to ${timestamp.toISOString()}`;
    }

    let content = '';
    content += '='.repeat(80) + '\n';
    content += 'OKTA SECURITY ASSESSMENT - RAW EVENT DATA\n';
    content += '='.repeat(80) + '\n\n';
    content += `Generated: ${timestamp.toISOString()}\n`;
    content += `Okta Domain: ${domain}\n`;
    content += `Analysis Period: ${analysisPeriod}\n`;
    content += `Total Checks: ${stats.totalChecks}\n`;
    content += `Findings with Events: ${stats.triggeredCount}\n`;
    content += `Total Events: ${stats.totalEvents}\n`;
    content += '\n' + '='.repeat(80) + '\n\n';

    // Iterate through all findings with events
    stats.triggered.forEach((finding, index) => {
      const typeLabel = finding.sourceType === 'hunt' ? 'HUNT' : 'DETECTION';
      content += '-'.repeat(80) + '\n';
      content += `[${typeLabel}] ${finding.title}\n`;
      content += '-'.repeat(80) + '\n';
      content += `Description: ${finding.description || 'N/A'}\n`;
      content += `MITRE Tactic: ${finding.threat?.Tactic || 'N/A'}\n`;
      content += `Events Count: ${finding.events?.length || 0}\n`;
      content += `Query: ${finding.query || 'N/A'}\n`;
      content += '\n';

      if (finding.events && finding.events.length > 0) {
        content += 'ALL EVENTS:\n';
        content += '~'.repeat(40) + '\n\n';

        finding.events.forEach((event, eventIdx) => {
          content += `--- Event ${eventIdx + 1} ---\n`;
          content += `Timestamp: ${event.published || 'N/A'}\n`;
          content += `UUID: ${event.uuid || 'N/A'}\n`;
          content += `EventType: ${event.eventType || 'N/A'}\n`;
          content += `DisplayMessage: ${event.displayMessage || 'N/A'}\n`;
          content += '\n';

          // Actor info
          content += '[Actor]\n';
          content += `  ID: ${event.actor?.id || 'N/A'}\n`;
          content += `  Type: ${event.actor?.type || 'N/A'}\n`;
          content += `  AlternateId: ${event.actor?.alternateId || 'N/A'}\n`;
          content += `  DisplayName: ${event.actor?.displayName || 'N/A'}\n`;
          content += '\n';

          // Client info
          content += '[Client]\n';
          content += `  IP Address: ${event.client?.ipAddress || 'N/A'}\n`;
          content += `  UserAgent (Raw): ${event.client?.userAgent?.rawUserAgent || 'N/A'}\n`;
          content += `  UserAgent (OS): ${event.client?.userAgent?.os || 'N/A'}\n`;
          content += `  UserAgent (Browser): ${event.client?.userAgent?.browser || 'N/A'}\n`;
          content += `  Device: ${event.client?.device || 'N/A'}\n`;
          content += `  Zone: ${event.client?.zone || 'N/A'}\n`;
          if (event.client?.geographicalContext) {
            const geo = event.client.geographicalContext;
            content += `  Geo City: ${geo.city || 'N/A'}\n`;
            content += `  Geo State: ${geo.state || 'N/A'}\n`;
            content += `  Geo Country: ${geo.country || 'N/A'}\n`;
            content += `  Geo Postal: ${geo.postalCode || 'N/A'}\n`;
          }
          content += '\n';

          // Outcome
          content += '[Outcome]\n';
          content += `  Result: ${event.outcome?.result || 'N/A'}\n`;
          content += `  Reason: ${event.outcome?.reason || 'N/A'}\n`;
          content += '\n';

          // Security Context
          if (event.securityContext) {
            content += '[Security Context]\n';
            content += `  ASNumber: ${event.securityContext.asNumber || 'N/A'}\n`;
            content += `  ASOrg: ${event.securityContext.asOrg || 'N/A'}\n`;
            content += `  ISP: ${event.securityContext.isp || 'N/A'}\n`;
            content += `  Domain: ${event.securityContext.domain || 'N/A'}\n`;
            content += `  IsProxy: ${event.securityContext.isProxy || 'N/A'}\n`;
            content += '\n';
          }

          // Debug Context
          if (event.debugContext?.debugData) {
            content += '[Debug Data]\n';
            const debugData = event.debugContext.debugData;
            Object.keys(debugData).forEach(key => {
              const value = debugData[key];
              if (typeof value === 'object') {
                content += `  ${key}: ${JSON.stringify(value)}\n`;
              } else {
                content += `  ${key}: ${value}\n`;
              }
            });
            content += '\n';
          }

          // Authentication Context
          if (event.authenticationContext) {
            content += '[Authentication Context]\n';
            const auth = event.authenticationContext;
            content += `  AuthenticationProvider: ${auth.authenticationProvider || 'N/A'}\n`;
            content += `  AuthenticationStep: ${auth.authenticationStep || 'N/A'}\n`;
            content += `  CredentialProvider: ${auth.credentialProvider || 'N/A'}\n`;
            content += `  CredentialType: ${auth.credentialType || 'N/A'}\n`;
            content += `  ExternalSessionId: ${auth.externalSessionId || 'N/A'}\n`;
            content += `  Interface: ${auth.interface || 'N/A'}\n`;
            content += '\n';
          }

          // Target (if any)
          if (event.target && event.target.length > 0) {
            content += '[Targets]\n';
            event.target.forEach((t, tIdx) => {
              content += `  Target ${tIdx + 1}:\n`;
              content += `    ID: ${t.id || 'N/A'}\n`;
              content += `    Type: ${t.type || 'N/A'}\n`;
              content += `    AlternateId: ${t.alternateId || 'N/A'}\n`;
              content += `    DisplayName: ${t.displayName || 'N/A'}\n`;
            });
            content += '\n';
          }

          // Transaction
          if (event.transaction) {
            content += '[Transaction]\n';
            content += `  ID: ${event.transaction.id || 'N/A'}\n`;
            content += `  Type: ${event.transaction.type || 'N/A'}\n`;
            content += '\n';
          }

          content += '\n';
        });
      }

      content += '\n';
    });

    // Add correlation analysis summary
    if (stats.riskUsers.length > 0 || stats.riskIPs.length > 0) {
      content += '='.repeat(80) + '\n';
      content += 'CORRELATION ANALYSIS SUMMARY\n';
      content += '='.repeat(80) + '\n\n';

      if (stats.riskUsers.length > 0) {
        content += 'TOP RISK USERS:\n';
        content += '-'.repeat(40) + '\n';
        stats.riskUsers.forEach((user, idx) => {
          content += `${idx + 1}. ${user.user}\n`;
          content += `   Risk Score: ${user.riskScore}\n`;
          content += `   Risk Level: ${user.riskLevel}\n`;
          content += `   Event Count: ${user.eventCount}\n`;
          content += `   Findings: ${Array.from(user.findings).join(', ')}\n`;
          content += `   IPs: ${Array.from(user.ips).join(', ')}\n`;
          content += '\n';
        });
      }

      if (stats.riskIPs.length > 0) {
        content += '\nTOP RISK IPs:\n';
        content += '-'.repeat(40) + '\n';
        stats.riskIPs.forEach((ip, idx) => {
          content += `${idx + 1}. ${ip.ip}\n`;
          content += `   Risk Score: ${ip.riskScore}\n`;
          content += `   Risk Level: ${ip.riskLevel}\n`;
          content += `   Event Count: ${ip.eventCount}\n`;
          content += `   Findings: ${Array.from(ip.findings).join(', ')}\n`;
          content += `   Users: ${Array.from(ip.users).join(', ')}\n`;
          content += '\n';
        });
      }
    }

    content += '\n' + '='.repeat(80) + '\n';
    content += 'END OF RAW EVENT DATA\n';
    content += '='.repeat(80) + '\n';

    return content;
  }

  calculateStatistics(findings) {
    const results = findings.detectionResults || [];
    const analysis = findings.correlationAnalysis || {};

    const totalChecks = results.length;
    const detectionsCount = results.filter(d => d.sourceType === 'detection').length;
    const huntsCount = results.filter(d => d.sourceType === 'hunt').length;
    const triggered = results.filter(d => d.events?.length > 0);
    const totalEvents = results.reduce((sum, d) => sum + (d.events?.length || 0), 0);

    const riskUsers = analysis.topRiskUsers || [];
    const riskIPs = analysis.topRiskIPs || [];

    // Group findings by MITRE tactic
    const byTactic = {};
    triggered.forEach(f => {
      const tactic = f.threat?.Tactic || 'Uncategorized';
      if (!byTactic[tactic]) byTactic[tactic] = [];
      byTactic[tactic].push(f);
    });

    return {
      totalChecks,
      detectionsCount,
      huntsCount,
      triggeredCount: triggered.length,
      totalEvents,
      riskUsers,
      riskIPs,
      triggered,
      byTactic,
      usersInMultiple: riskUsers.filter(u => u.findings.size > 1),
      ipsInMultiple: riskIPs.filter(ip => ip.findings.size > 1)
    };
  }

  escapeTypst(text) {
    if (!text) return '';
    return String(text)
      .replace(/\\/g, '\\\\')
      .replace(/#/g, '\\#')
      .replace(/\$/g, '\\$')
      .replace(/@/g, '\\@')
      .replace(/\[/g, '\\[')
      .replace(/\]/g, '\\]')
      .replace(/\{/g, '\\{')
      .replace(/\}/g, '\\}')
      .replace(/</g, '\\<')
      .replace(/>/g, '\\>')
      .replace(/_/g, '\\_')
      .replace(/\*/g, '\\*')
      .replace(/`/g, '\\`')
      .replace(/~/g, '\\~')
      .replace(/\^/g, '\\^');
  }

  generateTypstDocument(findings, config, stats, timestamp) {
    const domain = this.escapeTypst(config.okta?.domain || 'Unknown');

    // Format the analysis period as a readable date range
    const sinceRaw = config.query?.since;
    let analysisPeriod;
    if (sinceRaw) {
      const sinceDate = new Date(sinceRaw);
      const sinceFormatted = sinceDate.toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric'
      });
      const nowFormatted = timestamp.toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric'
      });
      analysisPeriod = `${sinceFormatted} to ${nowFormatted}`;
    } else {
      analysisPeriod = 'Last 90 days';
    }
    const since = this.escapeTypst(analysisPeriod);

    const dateFormatted = timestamp.toLocaleDateString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
    });

    return `
// Okta Security Report - Generated with Typst

#set document(
  title: "Okta Security Assessment Report",
  author: "Okta Security Health Check"
)

#set page(
  paper: "a4",
  margin: (x: 2.5cm, y: 2.5cm),
  header: context {
    if counter(page).get().first() > 1 [
      #set text(size: 9pt, fill: rgb(113, 128, 150))
      #grid(
        columns: (1fr, 1fr),
        align(left)[Okta Security Assessment],
        align(right)[${this.escapeTypst(dateFormatted)}]
      )
      #line(length: 100%, stroke: 0.5pt + rgb(226, 232, 240))
    ]
  },
  footer: context {
    set text(size: 9pt, fill: rgb(113, 128, 150))
    grid(
      columns: (1fr, 1fr, 1fr),
      align(left)[Confidential],
      align(center)[Page #counter(page).display("1 of 1", both: true)],
      align(right)[${domain}]
    )
  }
)

#set text(
  font: "Helvetica Neue",
  size: 10pt,
  fill: rgb(45, 55, 72)
)

#set par(justify: true, leading: 0.8em)
#set heading(numbering: none)

#show heading.where(level: 1): it => {
  set text(size: 18pt, weight: "bold", fill: rgb(26, 54, 93))
  block(above: 1.5em, below: 1em)[#it.body]
}

#show heading.where(level: 2): it => {
  set text(size: 14pt, weight: "bold", fill: rgb(26, 54, 93))
  block(above: 1.2em, below: 0.8em)[#it.body]
}

#show heading.where(level: 3): it => {
  set text(size: 12pt, weight: "bold", fill: rgb(45, 55, 72))
  block(above: 1em, below: 0.6em)[#it.body]
}

// Custom components
#let metric-box(label, value, color: rgb(49, 130, 206)) = {
  box(
    width: 100%,
    stroke: rgb(226, 232, 240),
    radius: 4pt,
    inset: 12pt
  )[
    #box(width: 100%, height: 3pt, fill: color, radius: (top: 4pt))
    #v(-8pt)
    #set text(size: 9pt, fill: rgb(113, 128, 150))
    #label
    #v(2pt)
    #set text(size: 20pt, weight: "bold", fill: color)
    #value
  ]
}

#let info-box(content) = {
  block(
    width: 100%,
    fill: rgb(247, 250, 252),
    stroke: rgb(226, 232, 240),
    inset: 12pt,
    radius: 4pt
  )[#content]
}

#let highlight-box(content, color: rgb(49, 130, 206)) = {
  block(
    width: 100%,
    fill: color.lighten(92%),
    stroke: (left: 4pt + color),
    inset: 12pt,
    radius: (right: 4pt)
  )[#content]
}

// ═══════════════════════════════════════════════════════════════════════════
// COVER PAGE
// ═══════════════════════════════════════════════════════════════════════════

#page(header: none, footer: none)[
  #set align(center)
  #v(2cm)

  #block(
    width: 100%,
    fill: rgb(26, 54, 93),
    inset: 20pt,
    radius: 8pt
  )[
    #set text(fill: white)
    #text(size: 28pt, weight: "bold")[OKTA SECURITY]
    #v(4pt)
    #text(size: 12pt)[Identity & Access Management Assessment]
  ]

  #v(2cm)

  #text(size: 32pt, weight: "bold", fill: rgb(26, 54, 93))[
    Security Findings Report
  ]

  #v(0.5cm)

  #text(size: 14pt, fill: rgb(113, 128, 150))[
    Detection Rules & Threat Hunt Results
  ]

  #v(2cm)

  // Key metrics
  #grid(
    columns: (1fr, 1fr, 1fr, 1fr),
    gutter: 12pt,
    metric-box("CHECKS RUN", "${stats.totalChecks}"),
    metric-box("WITH FINDINGS", "${stats.triggeredCount}"),
    metric-box("EVENTS FOUND", "${stats.totalEvents}"),
    metric-box("USERS ANALYZED", "${stats.riskUsers.length}")
  )

  #v(2cm)

  #set align(left)
  #info-box[
    #set text(size: 10pt)
    #grid(
      columns: (auto, 1fr),
      gutter: 8pt,
      [*Assessment Date:*], [${this.escapeTypst(dateFormatted)}],
      [*Okta Tenant:*], [${domain}],
      [*Analysis Period:*], [${since}],
      [*Report Generated:*], [${this.escapeTypst(timestamp.toLocaleString())}]
    )
  ]

  #v(1fr)

  #block(
    width: 100%,
    fill: rgb(26, 54, 93),
    inset: 10pt,
    radius: 4pt
  )[
    #set text(size: 9pt, fill: white, weight: "bold")
    #set align(center)
    CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY
  ]

  #v(0.5cm)

  #set text(size: 9pt, fill: rgb(113, 128, 150))
  Generated by Okta Security Health Check by Ivan Gotti (ivangotti\\@gmail.com)
]

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTIVE SUMMARY
// ═══════════════════════════════════════════════════════════════════════════

= Executive Summary

This report presents the results of an automated security assessment conducted against the Okta tenant *${domain}*. The assessment executed ${stats.totalChecks} security checks (${stats.detectionsCount} detection rules and ${stats.huntsCount} threat hunts) against the System Log API.

${this.generateCorrelationSummary(stats)}

// ═══════════════════════════════════════════════════════════════════════════
// DETAILED FINDINGS
// ═══════════════════════════════════════════════════════════════════════════

${this.generateDetailedFindings(stats, config)}

// ═══════════════════════════════════════════════════════════════════════════
// CORRELATION ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

${this.generateCorrelationSection(stats)}

// ═══════════════════════════════════════════════════════════════════════════
// APPENDIX
// ═══════════════════════════════════════════════════════════════════════════

= Appendix

== About This Assessment

This assessment was conducted using the Okta Security Health Check tool, which executes detection rules and threat hunting queries from the official Okta customer-detections repository. The tool queries the Okta System Log API to identify events matching known security-relevant patterns.

== Scoring Methodology

User and IP correlation scores are calculated based on:
- Number of different detection rules or hunts that returned events for the entity
- Total number of events associated with the entity
- Number of distinct IP addresses used by a user
- Number of distinct geographic locations
- Number of failed or denied authentication outcomes

These scores provide a relative ranking to help prioritize review of entities with more diverse or voluminous findings.

== Detection Sources

Detection rules and threat hunts are sourced from:
#link("https://github.com/okta/customer-detections")[github.com/okta/customer-detections]

== Disclaimer

#set text(size: 9pt, fill: rgb(113, 128, 150))
This report presents raw findings from automated security checks. Events returned by these checks may represent legitimate business activities, expected behavior, or potential security concerns depending on your organization's context. All findings should be reviewed and validated by qualified security personnel before taking any action. This tool does not make risk determinations — that assessment should be performed by your security team based on your organization's policies, threat model, and operational context.
`;
  }

  generateCorrelationSummary(stats) {
    if (stats.usersInMultiple.length === 0 && stats.ipsInMultiple.length === 0) {
      return '';
    }

    let content = `
== Cross-Detection Observations

`;

    if (stats.usersInMultiple.length > 0) {
      content += `*${stats.usersInMultiple.length} user(s)* appeared in events from multiple different detection rules or hunts. `;
    }

    if (stats.ipsInMultiple.length > 0) {
      content += `*${stats.ipsInMultiple.length} IP address(es)* appeared in events from multiple different detection rules or hunts.`;
    }

    content += `

These entities may warrant closer review as they are associated with diverse security-relevant activities.
`;

    return content;
  }

  generateCorrelationSection(stats) {
    if (stats.riskUsers.length === 0 && stats.riskIPs.length === 0) {
      return '';
    }

    let content = `= Correlation Analysis\n\n`;

    content += `The following tables show users and IP addresses ranked by the breadth and volume of their presence in the findings. The "Score" is a relative metric combining the number of distinct checks triggered, total events, and other factors.\n\n`;

    // Users table
    if (stats.riskUsers.length > 0) {
      content += `== Users by Finding Diversity\n\n`;

      content += `#table(
  columns: (1fr, auto, auto, auto, auto),
  stroke: rgb(226, 232, 240),
  inset: 8pt,
  fill: (_, row) => if row == 0 { rgb(247, 250, 252) } else { white },
  [*User*], [*Checks*], [*Events*], [*IPs*], [*Score*],
`;

      stats.riskUsers.slice(0, 10).forEach(user => {
        const userId = this.escapeTypst(user.userId.substring(0, 40));
        content += `  [${userId}], [${user.findings.size}], [${user.events.length}], [${user.ips.size}], [${user.riskScore}],\n`;
      });

      content += `)\n\n`;

      if (stats.riskUsers.length > 10) {
        content += `#text(size: 9pt, fill: rgb(113, 128, 150))[Showing top 10 of ${stats.riskUsers.length} users]\n\n`;
      }
    }

    // IPs table
    if (stats.riskIPs.length > 0) {
      content += `== IP Addresses by Finding Diversity\n\n`;

      content += `#table(
  columns: (1fr, auto, auto, auto, auto),
  stroke: rgb(226, 232, 240),
  inset: 8pt,
  fill: (_, row) => if row == 0 { rgb(247, 250, 252) } else { white },
  [*IP Address*], [*Checks*], [*Events*], [*Users*], [*Score*],
`;

      stats.riskIPs.slice(0, 10).forEach(ip => {
        content += `  [${this.escapeTypst(ip.ipAddress)}], [${ip.findings.size}], [${ip.events.length}], [${ip.users.size}], [${ip.riskScore}],\n`;
      });

      content += `)\n\n`;

      if (stats.riskIPs.length > 10) {
        content += `#text(size: 9pt, fill: rgb(113, 128, 150))[Showing top 10 of ${stats.riskIPs.length} IP addresses]\n\n`;
      }
    }

    return content;
  }

  generateDetailedFindings(stats, config) {
    if (stats.triggered.length === 0) {
      return '';
    }

    // Get sample events limit from config (default: 3, "all" for all events)
    const sampleEventsSetting = config.report?.sampleEvents;
    const showAllEvents = sampleEventsSetting === 'all' || sampleEventsSetting === 'ALL';
    const sampleLimit = showAllEvents ? Infinity : (parseInt(sampleEventsSetting) || 3);

    let content = `= Detailed Findings\n\n`;

    stats.triggered.forEach((finding, index) => {
      const typeLabel = finding.sourceType === 'hunt' ? 'HUNT' : 'DETECTION';
      const typeColor = finding.sourceType === 'hunt' ? 'rgb(156, 39, 176)' : 'rgb(49, 130, 206)';
      const title = this.escapeTypst(finding.title);
      const description = this.escapeTypst(finding.description || 'No description available');
      const tacticRaw = finding.threat?.Tactic;
      const tactic = this.escapeTypst(
        Array.isArray(tacticRaw) ? tacticRaw.join(', ') : (tacticRaw || 'Uncategorized')
      );

      content += `
== ${index + 1}. #text(fill: ${typeColor})[[${typeLabel}]] ${title}

#info-box[
  ${description}
]

#table(
  columns: (auto, 1fr),
  stroke: none,
  inset: 4pt,
  [*Events Found:*], [${finding.events?.length || 0}],
  [*MITRE Tactic:*], [${tactic}],
)

`;

      // Sample events with detailed security attributes
      if (finding.events && finding.events.length > 0) {
        const eventsToShow = showAllEvents ? finding.events.length : Math.min(sampleLimit, finding.events.length);
        const sectionTitle = showAllEvents ? 'All Events' : 'Sample Events';
        content += `=== ${sectionTitle}\n\n`;

        // Show detailed view for events based on config
        finding.events.slice(0, sampleLimit).forEach((event, idx) => {
          const timestamp = new Date(event.published).toLocaleString('en-US', {
            month: 'short', day: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'
          });

          content += `
#block(
  width: 100%,
  stroke: rgb(226, 232, 240),
  inset: 10pt,
  radius: 4pt,
  fill: rgb(252, 252, 253)
)[
  *Event ${idx + 1}* — ${this.escapeTypst(timestamp)}

  #table(
    columns: (auto, 1fr),
    stroke: none,
    inset: 3pt,
    [*Actor:*], [${this.escapeTypst(event.actor?.alternateId || 'N/A')}],
    [*IP Address:*], [${this.escapeTypst(event.client?.ipAddress || 'N/A')}],
    [*Result:*], [${this.escapeTypst(event.outcome?.result || 'N/A')}],
    [*Reason:*], [${this.escapeTypst(event.outcome?.reason || 'N/A')}],
`;

          // Add threat-specific attributes
          const debugData = event.debugContext?.debugData;
          if (debugData) {
            if (debugData.threatDetections) {
              content += `    [*ThreatDetections:*], [${this.escapeTypst(debugData.threatDetections)}],\n`;
            }
            if (debugData.requestUri) {
              content += `    [*RequestUri:*], [${this.escapeTypst(debugData.requestUri)}],\n`;
            }
          }

          if (event.client?.userAgent?.rawUserAgent) {
            const ua = event.client.userAgent.rawUserAgent;
            const shortUA = ua.length > 80 ? ua.substring(0, 77) + '...' : ua;
            content += `    [*RawUserAgent:*], [${this.escapeTypst(shortUA)}],\n`;
          }

          if (event.securityContext?.asOrg) {
            content += `    [*ASOrg:*], [${this.escapeTypst(event.securityContext.asOrg)}],\n`;
          }

          content += `  )
]

`;
        });

        if (!showAllEvents && finding.events.length > sampleLimit) {
          content += `#text(size: 9pt, fill: rgb(113, 128, 150), style: "italic")[Showing ${sampleLimit} of ${finding.events.length} events]\n\n`;
        }

        // Add field explanations
        content += `
=== Understanding Event Attributes

#set text(size: 9pt)

- *Result:* The final action taken by security controls (e.g., DENY or ALLOW). This tells you immediately whether the attempt was successful or blocked.

- *Reason:* The high-level categorization of why the result was triggered. Identifies the attack type, such as "Password Spray" rather than a standard bad password.

- *ThreatDetections:* Specific behavioral rules or heuristics that fired. Shows which security parameters caught the malicious activity.

- *RequestUri:* The specific web path or API endpoint targeted. Shows exactly where the adversary is probing your perimeter.

- *RawUserAgent:* The software, browser, or script used. Anomalous agents (like curl or python scripts) indicate automated tooling or bot activity.

- *ASOrg:* The company or ISP that owns the IP address space. Attacks from cloud providers (AWS, DigitalOcean) confirm the attacker is using rented or compromised servers.

#set text(size: 10pt)

`;
      }

      // False positives
      if (finding.false_positives && finding.false_positives.length > 0) {
        content += `\n=== Known False Positives\n\n`;
        finding.false_positives.forEach(fp => {
          content += `- ${this.escapeTypst(fp)}\n`;
        });
      }

      content += `\n`;
    });

    return content;
  }
}

module.exports = PDFGenerator;
