const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

/**
 * Professional Security Report Generator
 * Designed for CISOs (strategic) and Security Teams (tactical)
 */
class PDFGenerator {
  constructor() {
    this.colors = {
      primary: '#1a365d',      // Dark blue
      secondary: '#2d3748',    // Dark gray
      accent: '#3182ce',       // Blue accent
      critical: '#c53030',     // Red
      high: '#dd6b20',         // Orange
      moderate: '#d69e2e',     // Yellow
      low: '#38a169',          // Green
      text: '#2d3748',         // Dark text
      muted: '#718096',        // Gray text
      background: '#f7fafc',   // Light background
      white: '#ffffff',
      border: '#e2e8f0'
    };
  }

  async generateReport(findings, config) {
    const timestamp = new Date();
    const dateStr = timestamp.toISOString().split('T')[0];
    const filename = `okta-security-report-${dateStr}.pdf`;
    const filepath = path.join(process.cwd(), filename);

    return new Promise((resolve, reject) => {
      try {
        if (!findings || typeof findings !== 'object') {
          throw new Error('Invalid findings object');
        }
        if (!Array.isArray(findings.detectionResults)) {
          findings.detectionResults = [];
        }

        const doc = new PDFDocument({
          size: 'A4',
          margins: { top: 50, bottom: 50, left: 50, right: 50 },
          bufferPages: true
        });

        const stream = fs.createWriteStream(filepath);
        doc.pipe(stream);

        // Calculate all statistics upfront
        const stats = this.calculateStatistics(findings);

        // Generate report sections
        this.addCoverPage(doc, timestamp, config, stats);
        this.addExecutiveSummary(doc, findings, stats);
        this.addRiskDashboard(doc, findings, stats);
        this.addCriticalFindings(doc, findings, stats);
        this.addStrategicRecommendations(doc, findings, stats);

        // Tactical section for security teams
        this.addTacticalAnalysis(doc, findings, stats);
        this.addIOCSection(doc, findings);
        this.addDetailedFindings(doc, findings);
        this.addAppendix(doc, findings, config);

        // Add page numbers
        this.addPageNumbers(doc);

        doc.end();

        stream.on('finish', () => resolve(filepath));
        stream.on('error', (error) => reject(error));
      } catch (error) {
        reject(error);
      }
    });
  }

  calculateStatistics(findings) {
    const results = findings.detectionResults || [];
    const analysis = findings.correlationAnalysis || {};

    const totalChecks = results.length;
    const detectionsCount = results.filter(d => d.sourceType === 'detection').length;
    const huntsCount = results.filter(d => d.sourceType === 'hunt').length;
    const triggered = results.filter(d => d.events?.length > 0);
    const totalEvents = results.reduce((sum, d) => sum + (d.events?.length || 0), 0);

    // Risk users analysis
    const riskUsers = analysis.topRiskUsers || [];
    const criticalUsers = riskUsers.filter(u => u.riskLevel === 'CRITICAL').length;
    const highUsers = riskUsers.filter(u => u.riskLevel === 'HIGH').length;

    // Risk IPs analysis
    const riskIPs = analysis.topRiskIPs || [];
    const criticalIPs = riskIPs.filter(ip => ip.riskLevel === 'CRITICAL').length;
    const highIPs = riskIPs.filter(ip => ip.riskLevel === 'HIGH').length;

    // Categorize findings by severity
    const categorized = this.categorizeFindingsBySeverity(triggered);

    return {
      totalChecks,
      detectionsCount,
      huntsCount,
      triggeredCount: triggered.length,
      totalEvents,
      criticalUsers,
      highUsers,
      criticalIPs,
      highIPs,
      riskUsers,
      riskIPs,
      triggered,
      categorized,
      overallRisk: this.calculateOverallRisk(criticalUsers, highUsers, criticalIPs, triggered.length)
    };
  }

  categorizeFindingsBySeverity(triggered) {
    const critical = [];
    const high = [];
    const moderate = [];
    const low = [];

    triggered.forEach(finding => {
      const eventCount = finding.events?.length || 0;
      const tactic = finding.threat?.Tactic;

      // Categorize based on tactic and event count
      const isPersistence = tactic?.includes('Persistence');
      const isCredentialAccess = tactic?.includes('Credential Access');
      const isPrivilegeEscalation = tactic?.includes('Privilege Escalation');
      const isDefenseEvasion = tactic?.includes('Defense Evasion');

      if (isPersistence || isPrivilegeEscalation || (isCredentialAccess && eventCount > 10)) {
        critical.push(finding);
      } else if (isCredentialAccess || isDefenseEvasion || eventCount > 5) {
        high.push(finding);
      } else if (eventCount > 2) {
        moderate.push(finding);
      } else {
        low.push(finding);
      }
    });

    return { critical, high, moderate, low };
  }

  calculateOverallRisk(criticalUsers, highUsers, criticalIPs, triggeredFindings) {
    if (criticalUsers > 0 || criticalIPs > 0) return 'CRITICAL';
    if (highUsers > 0 || triggeredFindings > 5) return 'HIGH';
    if (triggeredFindings > 2) return 'MODERATE';
    return 'LOW';
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // COVER PAGE
  // ═══════════════════════════════════════════════════════════════════════════

  addCoverPage(doc, timestamp, config, stats) {
    const pageWidth = doc.page.width - 100;

    // Header bar
    doc.rect(0, 0, doc.page.width, 120).fill(this.colors.primary);

    // Company/Tool name
    doc.fontSize(28)
       .fillColor(this.colors.white)
       .font('Helvetica-Bold')
       .text('OKTA SECURITY', 50, 40);

    doc.fontSize(14)
       .font('Helvetica')
       .text('Identity & Access Management Security Assessment', 50, 75);

    // Risk indicator on cover
    const riskColor = this.getRiskColor(stats.overallRisk);
    doc.rect(doc.page.width - 180, 30, 130, 70)
       .fillAndStroke(this.colors.white, this.colors.white);

    doc.fontSize(10)
       .fillColor(this.colors.primary)
       .font('Helvetica')
       .text('RISK LEVEL', doc.page.width - 175, 40);

    doc.fontSize(20)
       .fillColor(riskColor)
       .font('Helvetica-Bold')
       .text(stats.overallRisk, doc.page.width - 175, 58);

    // Main title area
    doc.moveDown(8);

    doc.fontSize(36)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Security Assessment Report', 50, 180, { align: 'center', width: pageWidth });

    doc.fontSize(16)
       .fillColor(this.colors.muted)
       .font('Helvetica')
       .text('Comprehensive Security Posture Analysis', 50, 230, { align: 'center', width: pageWidth });

    // Key metrics boxes
    doc.y = 300;
    this.addMetricBox(doc, 50, 300, 120, 'CHECKS RUN', stats.totalChecks.toString(), this.colors.accent);
    this.addMetricBox(doc, 185, 300, 120, 'FINDINGS', stats.triggeredCount.toString(),
      stats.triggeredCount > 0 ? this.colors.high : this.colors.low);
    this.addMetricBox(doc, 320, 300, 120, 'EVENTS', stats.totalEvents.toString(), this.colors.primary);
    this.addMetricBox(doc, 455, 300, 90, 'RISK USERS',
      (stats.criticalUsers + stats.highUsers).toString(),
      stats.criticalUsers > 0 ? this.colors.critical : this.colors.muted);

    // Report details
    doc.y = 420;

    doc.fontSize(12)
       .fillColor(this.colors.text)
       .font('Helvetica-Bold')
       .text('Report Details', 50);

    doc.moveDown(0.5);
    doc.fontSize(10).font('Helvetica').fillColor(this.colors.muted);

    doc.text(`Assessment Date: ${timestamp.toLocaleDateString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
    })}`);
    doc.text(`Okta Tenant: ${config.okta?.domain || 'Not specified'}`);
    doc.text(`Analysis Period: ${config.query?.since || 'Last 90 days'}`);
    doc.text(`Report Generated: ${timestamp.toLocaleString()}`);

    // Classification banner
    doc.rect(50, 700, pageWidth, 30).fill(this.colors.primary);
    doc.fontSize(10)
       .fillColor(this.colors.white)
       .font('Helvetica-Bold')
       .text('CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY', 50, 710, { align: 'center', width: pageWidth });

    // Footer
    doc.fontSize(9)
       .fillColor(this.colors.muted)
       .font('Helvetica')
       .text('Generated by Okta Security Health Check', 50, 760, { align: 'center', width: pageWidth });
  }

  addMetricBox(doc, x, y, width, label, value, color) {
    const height = 70;

    doc.rect(x, y, width, height)
       .fillAndStroke(this.colors.white, this.colors.border);

    doc.rect(x, y, width, 4).fill(color);

    doc.fontSize(9)
       .fillColor(this.colors.muted)
       .font('Helvetica')
       .text(label, x + 10, y + 15, { width: width - 20 });

    doc.fontSize(24)
       .fillColor(color)
       .font('Helvetica-Bold')
       .text(value, x + 10, y + 35, { width: width - 20 });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EXECUTIVE SUMMARY (For CISO)
  // ═══════════════════════════════════════════════════════════════════════════

  addExecutiveSummary(doc, findings, stats) {
    doc.addPage();

    this.addSectionHeader(doc, 'EXECUTIVE SUMMARY', 'Strategic Overview for Leadership');

    // Risk Assessment Box
    const riskColor = this.getRiskColor(stats.overallRisk);
    doc.rect(50, doc.y, 495, 80).fillAndStroke('#fafafa', this.colors.border);
    doc.rect(50, doc.y, 8, 80).fill(riskColor);

    const boxY = doc.y;
    doc.fontSize(12)
       .fillColor(this.colors.text)
       .font('Helvetica-Bold')
       .text('Overall Security Posture', 70, boxY + 15);

    doc.fontSize(24)
       .fillColor(riskColor)
       .font('Helvetica-Bold')
       .text(stats.overallRisk, 70, boxY + 35);

    doc.fontSize(10)
       .fillColor(this.colors.muted)
       .font('Helvetica')
       .text(this.getRiskDescription(stats.overallRisk), 70, boxY + 62, { width: 460 });

    doc.y = boxY + 95;

    // Key Findings Summary
    doc.fontSize(14)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Key Findings');

    doc.moveDown(0.5);

    // Business Impact Summary
    const impacts = this.assessBusinessImpact(stats);
    impacts.forEach(impact => {
      doc.fontSize(10)
         .fillColor(impact.color)
         .font('Helvetica-Bold')
         .text(`● ${impact.title}`, { continued: true })
         .fillColor(this.colors.text)
         .font('Helvetica')
         .text(`: ${impact.description}`);
      doc.moveDown(0.3);
    });

    doc.moveDown(1);

    // Quick Stats Table
    doc.fontSize(14)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Assessment Metrics');

    doc.moveDown(0.5);

    this.addStatsTable(doc, [
      ['Metric', 'Value', 'Status'],
      ['Security Checks Executed', `${stats.totalChecks}`, '✓'],
      ['Detections Run', `${stats.detectionsCount}`, '✓'],
      ['Threat Hunts Run', `${stats.huntsCount}`, '✓'],
      ['Checks with Findings', `${stats.triggeredCount}`, stats.triggeredCount > 5 ? '⚠' : '✓'],
      ['Total Security Events', `${stats.totalEvents}`, stats.totalEvents > 100 ? '⚠' : '✓'],
      ['Critical Risk Users', `${stats.criticalUsers}`, stats.criticalUsers > 0 ? '🔴' : '✓'],
      ['High Risk Users', `${stats.highUsers}`, stats.highUsers > 0 ? '🟠' : '✓'],
    ]);

    // Immediate Attention Required
    if (stats.criticalUsers > 0 || stats.categorized.critical.length > 0) {
      doc.moveDown(1);

      doc.rect(50, doc.y, 495, 60).fillAndStroke('#fff5f5', this.colors.critical);
      const alertY = doc.y;

      doc.fontSize(12)
         .fillColor(this.colors.critical)
         .font('Helvetica-Bold')
         .text('⚠ IMMEDIATE ATTENTION REQUIRED', 60, alertY + 10);

      doc.fontSize(10)
         .fillColor(this.colors.text)
         .font('Helvetica')
         .text(`${stats.criticalUsers} user account(s) and ${stats.categorized.critical.length} finding(s) require immediate investigation. See Critical Findings section for details.`, 60, alertY + 30, { width: 475 });

      doc.y = alertY + 70;
    }
  }

  assessBusinessImpact(stats) {
    const impacts = [];

    if (stats.criticalUsers > 0) {
      impacts.push({
        title: 'Account Compromise Risk',
        description: `${stats.criticalUsers} user account(s) show signs of potential compromise across multiple security checks.`,
        color: this.colors.critical
      });
    }

    if (stats.categorized.critical.length > 0) {
      impacts.push({
        title: 'Persistence Threats Detected',
        description: `${stats.categorized.critical.length} finding(s) indicate potential persistent access attempts or privilege escalation.`,
        color: this.colors.critical
      });
    }

    if (stats.highUsers > 0) {
      impacts.push({
        title: 'Suspicious Activity',
        description: `${stats.highUsers} user account(s) exhibit suspicious authentication patterns requiring review.`,
        color: this.colors.high
      });
    }

    if (stats.triggeredCount === 0) {
      impacts.push({
        title: 'Clean Security Posture',
        description: 'No security findings detected. Your Okta environment appears well-secured.',
        color: this.colors.low
      });
    }

    return impacts;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RISK DASHBOARD
  // ═══════════════════════════════════════════════════════════════════════════

  addRiskDashboard(doc, findings, stats) {
    doc.addPage();

    this.addSectionHeader(doc, 'RISK DASHBOARD', 'Visual Risk Analysis');

    // Risk Distribution
    doc.fontSize(12)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Finding Severity Distribution');

    doc.moveDown(0.5);

    const barWidth = 400;
    const barHeight = 25;
    const total = Math.max(stats.triggeredCount, 1);

    const categories = [
      { label: 'Critical', count: stats.categorized.critical.length, color: this.colors.critical },
      { label: 'High', count: stats.categorized.high.length, color: this.colors.high },
      { label: 'Moderate', count: stats.categorized.moderate.length, color: this.colors.moderate },
      { label: 'Low', count: stats.categorized.low.length, color: this.colors.low }
    ];

    categories.forEach((cat, i) => {
      const y = doc.y + (i * 40);
      const width = (cat.count / total) * barWidth;

      doc.fontSize(10).fillColor(this.colors.text).font('Helvetica-Bold')
         .text(cat.label, 50, y);

      doc.rect(120, y - 2, barWidth, barHeight).fill('#f0f0f0');
      if (width > 0) {
        doc.rect(120, y - 2, Math.max(width, 5), barHeight).fill(cat.color);
      }

      doc.fontSize(10).fillColor(this.colors.text).font('Helvetica')
         .text(`${cat.count} (${Math.round((cat.count/total)*100)}%)`, 530, y);
    });

    doc.y += 180;

    // Top Risk Users Table
    if (stats.riskUsers.length > 0) {
      doc.fontSize(12)
         .fillColor(this.colors.primary)
         .font('Helvetica-Bold')
         .text('Top 5 Risk Users');

      doc.moveDown(0.5);

      const userRows = [['User', 'Risk Level', 'Score', 'Detections', 'IPs']];
      stats.riskUsers.slice(0, 5).forEach(user => {
        userRows.push([
          user.userId.substring(0, 30) + (user.userId.length > 30 ? '...' : ''),
          user.riskLevel,
          user.riskScore.toString(),
          user.findings.size.toString(),
          user.ips.size.toString()
        ]);
      });

      this.addColoredTable(doc, userRows);
    }

    // Top Risk IPs Table
    if (stats.riskIPs.length > 0) {
      doc.moveDown(1);

      doc.fontSize(12)
         .fillColor(this.colors.primary)
         .font('Helvetica-Bold')
         .text('Top 5 Risk IP Addresses');

      doc.moveDown(0.5);

      const ipRows = [['IP Address', 'Risk Level', 'Score', 'Users', 'Events']];
      stats.riskIPs.slice(0, 5).forEach(ip => {
        ipRows.push([
          ip.ipAddress,
          ip.riskLevel,
          ip.riskScore.toString(),
          ip.users.size.toString(),
          ip.events.length.toString()
        ]);
      });

      this.addColoredTable(doc, ipRows);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CRITICAL FINDINGS
  // ═══════════════════════════════════════════════════════════════════════════

  addCriticalFindings(doc, findings, stats) {
    if (stats.categorized.critical.length === 0 && stats.criticalUsers === 0) return;

    doc.addPage();

    this.addSectionHeader(doc, 'CRITICAL FINDINGS', 'Requires Immediate Attention');

    // Alert banner
    doc.rect(50, doc.y, 495, 40).fill(this.colors.critical);
    doc.fontSize(11)
       .fillColor(this.colors.white)
       .font('Helvetica-Bold')
       .text('🚨 The following findings require immediate investigation and response', 60, doc.y + 12, { width: 475 });

    doc.y += 55;

    // Critical detections
    stats.categorized.critical.forEach((finding, index) => {
      if (doc.y > 650) doc.addPage();

      this.addFindingCard(doc, finding, index + 1, 'CRITICAL');
    });

    // Critical risk users
    if (stats.criticalUsers > 0) {
      if (doc.y > 550) doc.addPage();

      doc.fontSize(14)
         .fillColor(this.colors.critical)
         .font('Helvetica-Bold')
         .text('Critical Risk Users');

      doc.moveDown(0.5);

      stats.riskUsers.filter(u => u.riskLevel === 'CRITICAL').forEach(user => {
        this.addUserRiskCard(doc, user);
      });
    }
  }

  addFindingCard(doc, finding, index, severity) {
    const cardHeight = 120;
    const color = this.getRiskColor(severity);

    doc.rect(50, doc.y, 495, cardHeight).fillAndStroke('#fafafa', this.colors.border);
    doc.rect(50, doc.y, 5, cardHeight).fill(color);

    const startY = doc.y;

    // Title
    const typeLabel = finding.sourceType === 'hunt' ? '[HUNT]' : '[DETECTION]';
    doc.fontSize(11)
       .fillColor(color)
       .font('Helvetica-Bold')
       .text(`${index}. ${typeLabel} ${finding.title}`, 65, startY + 10, { width: 470 });

    // Description
    doc.fontSize(9)
       .fillColor(this.colors.muted)
       .font('Helvetica')
       .text(finding.description?.substring(0, 200) + '...' || 'No description available', 65, startY + 30, { width: 470 });

    // Metrics
    doc.fontSize(9)
       .fillColor(this.colors.text)
       .font('Helvetica-Bold')
       .text(`Events: ${finding.events?.length || 0}`, 65, startY + 70)
       .text(`MITRE ATT&CK: ${finding.threat?.Tactic || 'N/A'}`, 200, startY + 70);

    // Action required
    doc.fontSize(9)
       .fillColor(color)
       .font('Helvetica-Bold')
       .text('→ Immediate investigation required', 65, startY + 95);

    doc.y = startY + cardHeight + 10;
  }

  addUserRiskCard(doc, user) {
    const color = this.getRiskColor(user.riskLevel);

    doc.rect(50, doc.y, 495, 80).fillAndStroke('#fafafa', this.colors.border);
    doc.rect(50, doc.y, 5, 80).fill(color);

    const startY = doc.y;

    doc.fontSize(11)
       .fillColor(this.colors.text)
       .font('Helvetica-Bold')
       .text(user.userId, 65, startY + 10);

    doc.fontSize(9)
       .fillColor(color)
       .font('Helvetica-Bold')
       .text(`Risk Score: ${user.riskScore}`, 65, startY + 30);

    doc.fontSize(9)
       .fillColor(this.colors.muted)
       .font('Helvetica')
       .text(`${user.events.length} events | ${user.ips.size} IPs | ${user.findings.size} detections triggered`, 65, startY + 50);

    doc.y = startY + 90;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STRATEGIC RECOMMENDATIONS
  // ═══════════════════════════════════════════════════════════════════════════

  addStrategicRecommendations(doc, findings, stats) {
    doc.addPage();

    this.addSectionHeader(doc, 'STRATEGIC RECOMMENDATIONS', 'Prioritized Action Plan');

    const recommendations = this.generateRecommendations(stats);

    // Immediate Actions (24-48 hours)
    if (recommendations.immediate.length > 0) {
      doc.fontSize(12)
         .fillColor(this.colors.critical)
         .font('Helvetica-Bold')
         .text('🚨 Immediate Actions (24-48 hours)');

      doc.moveDown(0.3);

      recommendations.immediate.forEach((rec, i) => {
        doc.fontSize(10)
           .fillColor(this.colors.text)
           .font('Helvetica')
           .text(`${i + 1}. ${rec}`, { indent: 20 });
        doc.moveDown(0.2);
      });

      doc.moveDown(0.5);
    }

    // Short-term (1-2 weeks)
    if (recommendations.shortTerm.length > 0) {
      doc.fontSize(12)
         .fillColor(this.colors.high)
         .font('Helvetica-Bold')
         .text('⚠ Short-term Actions (1-2 weeks)');

      doc.moveDown(0.3);

      recommendations.shortTerm.forEach((rec, i) => {
        doc.fontSize(10)
           .fillColor(this.colors.text)
           .font('Helvetica')
           .text(`${i + 1}. ${rec}`, { indent: 20 });
        doc.moveDown(0.2);
      });

      doc.moveDown(0.5);
    }

    // Long-term (1+ months)
    if (recommendations.longTerm.length > 0) {
      doc.fontSize(12)
         .fillColor(this.colors.accent)
         .font('Helvetica-Bold')
         .text('📋 Long-term Improvements (1+ months)');

      doc.moveDown(0.3);

      recommendations.longTerm.forEach((rec, i) => {
        doc.fontSize(10)
           .fillColor(this.colors.text)
           .font('Helvetica')
           .text(`${i + 1}. ${rec}`, { indent: 20 });
        doc.moveDown(0.2);
      });
    }
  }

  generateRecommendations(stats) {
    const recommendations = {
      immediate: [],
      shortTerm: [],
      longTerm: []
    };

    // Immediate based on findings
    if (stats.criticalUsers > 0) {
      recommendations.immediate.push(`Investigate ${stats.criticalUsers} critical risk user account(s) for potential compromise`);
      recommendations.immediate.push('Consider temporary account suspension for critical risk users pending investigation');
    }

    if (stats.categorized.critical.length > 0) {
      recommendations.immediate.push('Review all critical severity findings and initiate incident response if warranted');
    }

    if (stats.criticalIPs > 0) {
      recommendations.immediate.push(`Block or investigate ${stats.criticalIPs} critical risk IP address(es)`);
    }

    // Short-term
    if (stats.highUsers > 0) {
      recommendations.shortTerm.push(`Review ${stats.highUsers} high-risk user accounts and enforce MFA re-enrollment if needed`);
    }

    if (stats.triggeredCount > 0) {
      recommendations.shortTerm.push('Review and tune authentication policies based on findings');
      recommendations.shortTerm.push('Implement geographic-based access restrictions if not already in place');
    }

    recommendations.shortTerm.push('Ensure all admin accounts have phishing-resistant MFA enabled');
    recommendations.shortTerm.push('Review API token permissions and revoke unused tokens');

    // Long-term
    recommendations.longTerm.push('Implement continuous security monitoring with automated alerting');
    recommendations.longTerm.push('Establish regular security assessment schedule (monthly/quarterly)');
    recommendations.longTerm.push('Develop incident response playbooks for common Okta security scenarios');
    recommendations.longTerm.push('Consider implementing Okta ThreatInsight for enhanced threat detection');

    return recommendations;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TACTICAL ANALYSIS (For Security Teams)
  // ═══════════════════════════════════════════════════════════════════════════

  addTacticalAnalysis(doc, findings, stats) {
    doc.addPage();

    this.addSectionHeader(doc, 'TACTICAL ANALYSIS', 'Detailed Investigation Guidance for Security Teams');

    doc.fontSize(10)
       .fillColor(this.colors.muted)
       .font('Helvetica-Oblique')
       .text('This section provides technical details and investigation steps for security analysts.', 50);

    doc.moveDown(1);

    // Investigation Priorities
    doc.fontSize(12)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Investigation Priorities');

    doc.moveDown(0.5);

    let priority = 1;

    // Critical users first
    stats.riskUsers.filter(u => u.riskLevel === 'CRITICAL').forEach(user => {
      doc.fontSize(10)
         .fillColor(this.colors.critical)
         .font('Helvetica-Bold')
         .text(`P${priority++}: Investigate user "${user.userId}"`);

      doc.fontSize(9)
         .fillColor(this.colors.text)
         .font('Helvetica')
         .text(`   • Risk Score: ${user.riskScore} | Events: ${user.events.length} | IPs: ${user.ips.size}`, { indent: 10 })
         .text(`   • Triggered: ${Array.from(user.findings).join(', ')}`, { indent: 10 });

      doc.moveDown(0.3);
    });

    // High users
    stats.riskUsers.filter(u => u.riskLevel === 'HIGH').slice(0, 3).forEach(user => {
      doc.fontSize(10)
         .fillColor(this.colors.high)
         .font('Helvetica-Bold')
         .text(`P${priority++}: Review user "${user.userId}"`);

      doc.fontSize(9)
         .fillColor(this.colors.text)
         .font('Helvetica')
         .text(`   • Risk Score: ${user.riskScore} | Events: ${user.events.length}`, { indent: 10 });

      doc.moveDown(0.3);
    });

    // Investigation steps
    doc.moveDown(1);
    doc.fontSize(12)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Recommended Investigation Steps');

    doc.moveDown(0.5);

    const steps = [
      '1. Review user session logs in Okta Admin Console for suspicious activity',
      '2. Check for password changes or MFA modifications in the timeframe',
      '3. Verify geographic locations match expected user behavior',
      '4. Cross-reference IP addresses with threat intelligence feeds',
      '5. Interview user if account compromise is suspected',
      '6. Check for lateral movement to other systems/applications',
      '7. Document findings and escalate as per incident response procedures'
    ];

    steps.forEach(step => {
      doc.fontSize(9)
         .fillColor(this.colors.text)
         .font('Helvetica')
         .text(step, { indent: 10 });
      doc.moveDown(0.2);
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // IOC SECTION
  // ═══════════════════════════════════════════════════════════════════════════

  addIOCSection(doc, findings) {
    const analysis = findings.correlationAnalysis;
    if (!analysis) return;

    doc.addPage();

    this.addSectionHeader(doc, 'INDICATORS OF COMPROMISE (IOCs)', 'Technical Indicators for Threat Hunting');

    // Suspicious IPs
    if (analysis.topRiskIPs?.length > 0) {
      doc.fontSize(12)
         .fillColor(this.colors.primary)
         .font('Helvetica-Bold')
         .text('Suspicious IP Addresses');

      doc.moveDown(0.3);
      doc.fontSize(9)
         .fillColor(this.colors.muted)
         .font('Helvetica')
         .text('Consider blocking or monitoring these IPs:');

      doc.moveDown(0.3);

      analysis.topRiskIPs.slice(0, 10).forEach(ip => {
        const color = this.getRiskColor(ip.riskLevel);
        doc.fontSize(9)
           .fillColor(color)
           .font('Helvetica-Bold')
           .text(`• ${ip.ipAddress}`, { continued: true })
           .fillColor(this.colors.muted)
           .font('Helvetica')
           .text(` - ${ip.riskLevel} risk, ${ip.users.size} user(s), ${ip.events.length} event(s)`);
      });

      doc.moveDown(1);
    }

    // Suspicious Users
    if (analysis.topRiskUsers?.length > 0) {
      doc.fontSize(12)
         .fillColor(this.colors.primary)
         .font('Helvetica-Bold')
         .text('Accounts Requiring Review');

      doc.moveDown(0.3);

      analysis.topRiskUsers.slice(0, 10).forEach(user => {
        const color = this.getRiskColor(user.riskLevel);
        doc.fontSize(9)
           .fillColor(color)
           .font('Helvetica-Bold')
           .text(`• ${user.userId}`, { continued: true })
           .fillColor(this.colors.muted)
           .font('Helvetica')
           .text(` - ${user.riskLevel} risk, score ${user.riskScore}`);
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DETAILED FINDINGS
  // ═══════════════════════════════════════════════════════════════════════════

  addDetailedFindings(doc, findings) {
    const results = findings.detectionResults || [];
    const triggered = results.filter(d => d.events?.length > 0);

    if (triggered.length === 0) return;

    doc.addPage();

    this.addSectionHeader(doc, 'DETAILED FINDINGS', 'Complete Detection and Hunt Results');

    triggered.forEach((finding, index) => {
      if (doc.y > 600) doc.addPage();

      const typeLabel = finding.sourceType === 'hunt' ? '[HUNT]' : '[DETECTION]';
      const typeColor = finding.sourceType === 'hunt' ? '#9C27B0' : this.colors.accent;

      // Finding header
      doc.fontSize(11)
         .fillColor(typeColor)
         .font('Helvetica-Bold')
         .text(`${index + 1}. ${typeLabel} ${finding.title}`);

      doc.moveDown(0.3);

      // Description
      if (finding.description) {
        doc.fontSize(9)
           .fillColor(this.colors.muted)
           .font('Helvetica')
           .text(finding.description, { width: 495 });
        doc.moveDown(0.3);
      }

      // Metrics line
      doc.fontSize(9)
         .fillColor(this.colors.text)
         .font('Helvetica')
         .text(`Events: ${finding.events.length} | MITRE ATT&CK: ${finding.threat?.Tactic || 'N/A'}`);

      doc.moveDown(0.3);

      // Sample events (first 3)
      doc.fontSize(9)
         .fillColor(this.colors.primary)
         .font('Helvetica-Bold')
         .text('Sample Events:');

      finding.events.slice(0, 3).forEach(event => {
        const timestamp = new Date(event.published).toLocaleString();
        doc.fontSize(8)
           .fillColor(this.colors.muted)
           .font('Helvetica')
           .text(`  • ${timestamp} | ${event.actor?.alternateId || 'N/A'} | ${event.client?.ipAddress || 'N/A'} | ${event.outcome?.result || 'N/A'}`);
      });

      if (finding.events.length > 3) {
        doc.fontSize(8)
           .fillColor(this.colors.muted)
           .font('Helvetica-Oblique')
           .text(`  ... and ${finding.events.length - 3} more event(s)`);
      }

      doc.moveDown(1);
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // APPENDIX
  // ═══════════════════════════════════════════════════════════════════════════

  addAppendix(doc, findings, config) {
    doc.addPage();

    this.addSectionHeader(doc, 'APPENDIX', 'Additional Information');

    // Methodology
    doc.fontSize(12)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Assessment Methodology');

    doc.moveDown(0.3);
    doc.fontSize(9)
       .fillColor(this.colors.text)
       .font('Helvetica')
       .text('This assessment was conducted using the Okta Security Health Check tool, which executes detection rules and threat hunting queries from the official Okta customer-detections repository against the Okta System Log API.')
       .moveDown(0.3)
       .text('Risk scores are calculated based on:')
       .text('• Number of different security findings triggered', { indent: 10 })
       .text('• Total security events per entity', { indent: 10 })
       .text('• Multiple IP addresses or locations per user', { indent: 10 })
       .text('• Failed/denied authentication attempts', { indent: 10 });

    doc.moveDown(1);

    // Risk Level Definitions
    doc.fontSize(12)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Risk Level Definitions');

    doc.moveDown(0.3);

    const riskDefs = [
      { level: 'CRITICAL', score: '150+', action: 'Immediate investigation required within 24 hours' },
      { level: 'HIGH', score: '100-149', action: 'Prompt review recommended within 48 hours' },
      { level: 'MODERATE', score: '50-99', action: 'Monitor closely, investigate within 1 week' },
      { level: 'LOW', score: '<50', action: 'Routine monitoring, no immediate action required' }
    ];

    riskDefs.forEach(def => {
      doc.fontSize(9)
         .fillColor(this.getRiskColor(def.level))
         .font('Helvetica-Bold')
         .text(`${def.level} (Score ${def.score}):`, { continued: true })
         .fillColor(this.colors.text)
         .font('Helvetica')
         .text(` ${def.action}`);
      doc.moveDown(0.2);
    });

    // Disclaimer
    doc.moveDown(1);
    doc.fontSize(10)
       .fillColor(this.colors.primary)
       .font('Helvetica-Bold')
       .text('Disclaimer');

    doc.moveDown(0.3);
    doc.fontSize(8)
       .fillColor(this.colors.muted)
       .font('Helvetica')
       .text('This report is provided for informational purposes only. Findings should be validated and investigated in the context of your specific environment. False positives may occur. Always follow your organization\'s incident response procedures before taking action on any findings.');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HELPER METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  addSectionHeader(doc, title, subtitle) {
    doc.rect(50, doc.y, 495, 50).fill(this.colors.primary);

    doc.fontSize(16)
       .fillColor(this.colors.white)
       .font('Helvetica-Bold')
       .text(title, 60, doc.y + 10);

    if (subtitle) {
      doc.fontSize(10)
         .font('Helvetica')
         .text(subtitle, 60, doc.y + 30);
    }

    doc.y += 65;
  }

  addStatsTable(doc, rows) {
    const colWidths = [250, 100, 80];
    const startX = 50;
    let y = doc.y;

    rows.forEach((row, rowIndex) => {
      let x = startX;
      const isHeader = rowIndex === 0;

      row.forEach((cell, cellIndex) => {
        doc.fontSize(isHeader ? 9 : 9)
           .fillColor(isHeader ? this.colors.primary : this.colors.text)
           .font(isHeader ? 'Helvetica-Bold' : 'Helvetica')
           .text(cell, x, y, { width: colWidths[cellIndex] });
        x += colWidths[cellIndex];
      });

      y += 18;
    });

    doc.y = y + 10;
  }

  addColoredTable(doc, rows) {
    const colWidths = [150, 70, 50, 70, 60];
    const startX = 50;
    let y = doc.y;

    rows.forEach((row, rowIndex) => {
      let x = startX;
      const isHeader = rowIndex === 0;

      row.forEach((cell, cellIndex) => {
        let color = this.colors.text;
        if (cellIndex === 1 && !isHeader) {
          color = this.getRiskColor(cell);
        }

        doc.fontSize(8)
           .fillColor(isHeader ? this.colors.primary : color)
           .font(isHeader ? 'Helvetica-Bold' : 'Helvetica')
           .text(cell, x, y, { width: colWidths[cellIndex] });
        x += colWidths[cellIndex];
      });

      y += 16;
    });

    doc.y = y + 10;
  }

  addPageNumbers(doc) {
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      doc.fontSize(8)
         .fillColor(this.colors.muted)
         .text(`Page ${i + 1} of ${pages.count}`, 50, doc.page.height - 30, { align: 'center', width: doc.page.width - 100 });
    }
  }

  getRiskColor(level) {
    switch (level) {
      case 'CRITICAL': return this.colors.critical;
      case 'HIGH': return this.colors.high;
      case 'MODERATE': return this.colors.moderate;
      case 'LOW': return this.colors.low;
      default: return this.colors.muted;
    }
  }

  getRiskDescription(level) {
    switch (level) {
      case 'CRITICAL': return 'Multiple critical security threats detected requiring immediate investigation and response.';
      case 'HIGH': return 'Significant security concerns identified. Prompt review and remediation recommended.';
      case 'MODERATE': return 'Some security events detected. Review findings and monitor closely.';
      case 'LOW': return 'Minimal security concerns. Environment appears well-secured with no immediate threats.';
      default: return 'Unable to determine risk level.';
    }
  }
}

module.exports = PDFGenerator;
