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
    const typstFile = path.join(process.cwd(), `report-${dateStr}.typ`);
    const pdfFile = path.join(process.cwd(), `okta-security-report-${dateStr}.pdf`);

    const stats = this.calculateStatistics(findings);
    const typstContent = this.generateTypstDocument(findings, config, stats, timestamp);

    fs.writeFileSync(typstFile, typstContent, 'utf8');

    try {
      execSync(`typst compile "${typstFile}" "${pdfFile}"`, { stdio: 'pipe' });
      fs.unlinkSync(typstFile);
      return pdfFile;
    } catch (error) {
      throw new Error(`Typst compilation failed: ${error.message}`);
    }
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

${this.generateDetailedFindings(stats)}

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

  generateDetailedFindings(stats) {
    if (stats.triggered.length === 0) {
      return '';
    }

    let content = `= Detailed Findings\n\n`;

    stats.triggered.forEach((finding, index) => {
      const typeLabel = finding.sourceType === 'hunt' ? 'HUNT' : 'DETECTION';
      const typeColor = finding.sourceType === 'hunt' ? 'rgb(156, 39, 176)' : 'rgb(49, 130, 206)';
      const title = this.escapeTypst(finding.title);
      const description = this.escapeTypst(finding.description || 'No description available');
      const tactic = this.escapeTypst(finding.threat?.Tactic || 'Uncategorized');
      const technique = this.escapeTypst(finding.threat?.Technique || 'N/A');

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
  [*MITRE Technique:*], [${technique}],
)

`;

      // Sample events
      if (finding.events && finding.events.length > 0) {
        content += `=== Sample Events\n\n`;
        content += `#table(
  columns: (auto, 1fr, auto, auto),
  stroke: rgb(226, 232, 240),
  inset: 6pt,
  fill: (_, row) => if row == 0 { rgb(247, 250, 252) } else { white },
  [*Time*], [*Actor*], [*IP*], [*Outcome*],
`;

        finding.events.slice(0, 5).forEach(event => {
          const timestamp = new Date(event.published).toLocaleString('en-US', {
            month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
          });
          const actor = this.escapeTypst((event.actor?.alternateId || 'N/A').substring(0, 30));
          const ip = this.escapeTypst(event.client?.ipAddress || 'N/A');
          const outcome = event.outcome?.result || 'N/A';

          content += `  [${this.escapeTypst(timestamp)}], [${actor}], [${ip}], [${outcome}],\n`;
        });

        content += `)\n`;

        if (finding.events.length > 5) {
          content += `\n#text(size: 9pt, fill: rgb(113, 128, 150), style: "italic")[Showing 5 of ${finding.events.length} events]\n`;
        }
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
