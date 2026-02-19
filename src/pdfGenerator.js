const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

class PDFGenerator {
  constructor() {
    this.pageMargin = 50;
  }

  async generateReport(findings, config) {
    const timestamp = new Date();
    const dateStr = timestamp.toISOString().split('T')[0];
    const filename = `okta-security-scan-${dateStr}.pdf`;
    const filepath = path.join(process.cwd(), filename);

    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({
          size: 'A4',
          margins: {
            top: this.pageMargin,
            bottom: this.pageMargin,
            left: this.pageMargin,
            right: this.pageMargin
          }
        });

        const stream = fs.createWriteStream(filepath);
        doc.pipe(stream);

        // Generate report content
        this.addTitlePage(doc, timestamp, config);
        this.addExecutiveSummary(doc, findings);
        this.addFindingsDetail(doc, findings);
        this.addFooter(doc);

        doc.end();

        stream.on('finish', () => {
          resolve(filepath);
        });

        stream.on('error', (error) => {
          reject(error);
        });
      } catch (error) {
        reject(error);
      }
    });
  }

  addTitlePage(doc, timestamp, config) {
    // Title
    doc.fontSize(32)
       .fillColor('#1976D2')
       .font('Helvetica-Bold')
       .text('Okta Security Health Check', { align: 'center' });

    doc.moveDown(1);

    // Subtitle
    doc.fontSize(18)
       .fillColor('#555')
       .font('Helvetica')
       .text('Security Detection Report', { align: 'center' });

    doc.moveDown(3);

    // Scan details box
    const boxTop = doc.y;
    doc.roundedRect(this.pageMargin, boxTop, doc.page.width - (this.pageMargin * 2), 120, 5)
       .fillAndStroke('#F5F5F5', '#E0E0E0');

    doc.fillColor('#333')
       .fontSize(12)
       .font('Helvetica-Bold')
       .text('Scan Date:', this.pageMargin + 20, boxTop + 20);

    doc.font('Helvetica')
       .text(timestamp.toLocaleString('en-US', {
         dateStyle: 'full',
         timeStyle: 'long'
       }), this.pageMargin + 120, boxTop + 20);

    doc.font('Helvetica-Bold')
       .text('Okta Tenant:', this.pageMargin + 20, boxTop + 50);

    doc.font('Helvetica')
       .text(config.okta.domain, this.pageMargin + 120, boxTop + 50);

    doc.font('Helvetica-Bold')
       .text('Query Period:', this.pageMargin + 20, boxTop + 80);

    const since = config.query?.since || 'Last 90 days';
    doc.font('Helvetica')
       .text(since, this.pageMargin + 120, boxTop + 80);

    doc.moveDown(4);

    // Add a separator line
    doc.moveTo(this.pageMargin, doc.y)
       .lineTo(doc.page.width - this.pageMargin, doc.y)
       .stroke('#E0E0E0');
  }

  addExecutiveSummary(doc, findings) {
    doc.addPage();

    // Section title
    doc.fontSize(24)
       .fillColor('#1976D2')
       .font('Helvetica-Bold')
       .text('Executive Summary', { underline: false });

    doc.moveDown(1.5);

    // Calculate statistics
    const totalDetections = findings.detectionResults.length;
    const detectionsWithFindings = findings.detectionResults.filter(d => d.events.length > 0).length;
    const totalEvents = findings.detectionResults.reduce((sum, d) => sum + d.events.length, 0);

    // Summary boxes
    const boxY = doc.y;
    const boxWidth = (doc.page.width - (this.pageMargin * 2) - 20) / 3;
    const boxHeight = 80;

    // Box 1 - Total Detections
    this.drawSummaryBox(doc, this.pageMargin, boxY, boxWidth, boxHeight,
                        totalDetections.toString(), 'Detections Executed', '#4CAF50');

    // Box 2 - Findings
    this.drawSummaryBox(doc, this.pageMargin + boxWidth + 10, boxY, boxWidth, boxHeight,
                        detectionsWithFindings.toString(), 'Detections Triggered', '#FF9800');

    // Box 3 - Total Events
    this.drawSummaryBox(doc, this.pageMargin + (boxWidth * 2) + 20, boxY, boxWidth, boxHeight,
                        totalEvents.toString(), 'Total Events', '#F44336');

    doc.y = boxY + boxHeight + 30;

    // Risk level assessment
    doc.fontSize(14)
       .fillColor('#333')
       .font('Helvetica-Bold')
       .text('Risk Assessment:', this.pageMargin);

    doc.moveDown(0.5);

    let riskLevel, riskColor, riskText;
    if (detectionsWithFindings === 0) {
      riskLevel = 'LOW';
      riskColor = '#4CAF50';
      riskText = 'No security threats detected. Your Okta environment appears secure.';
    } else if (detectionsWithFindings <= 3) {
      riskLevel = 'MODERATE';
      riskColor = '#FF9800';
      riskText = 'Some security events detected. Review findings to ensure they are legitimate.';
    } else {
      riskLevel = 'HIGH';
      riskColor = '#F44336';
      riskText = 'Multiple security threats detected. Immediate review recommended.';
    }

    doc.fontSize(20)
       .fillColor(riskColor)
       .font('Helvetica-Bold')
       .text(riskLevel, { continued: false });

    doc.fontSize(12)
       .fillColor('#555')
       .font('Helvetica')
       .text(riskText, { continued: false });

    doc.moveDown(2);

    // Key findings summary
    if (detectionsWithFindings > 0) {
      doc.fontSize(14)
         .fillColor('#333')
         .font('Helvetica-Bold')
         .text('Key Findings:');

      doc.moveDown(0.5);

      const findingsWithEvents = findings.detectionResults
        .filter(d => d.events.length > 0)
        .sort((a, b) => b.events.length - a.events.length);

      findingsWithEvents.forEach((finding, index) => {
        if (index > 0) doc.moveDown(0.3);

        doc.fontSize(11)
           .fillColor('#1976D2')
           .font('Helvetica-Bold')
           .text(`• ${finding.title}`, { indent: 20, continued: true });

        doc.fillColor('#666')
           .font('Helvetica')
           .text(` - ${finding.events.length} event(s)`, { continued: false });
      });
    }
  }

  drawSummaryBox(doc, x, y, width, height, value, label, color) {
    // Draw box
    doc.roundedRect(x, y, width, height, 5)
       .fillAndStroke('#FAFAFA', '#E0E0E0');

    // Draw value
    doc.fontSize(28)
       .fillColor(color)
       .font('Helvetica-Bold')
       .text(value, x, y + 20, { width: width, align: 'center' });

    // Draw label
    doc.fontSize(10)
       .fillColor('#666')
       .font('Helvetica')
       .text(label, x, y + 55, { width: width, align: 'center' });
  }

  addFindingsDetail(doc, findings) {
    const findingsWithEvents = findings.detectionResults.filter(d => d.events.length > 0);

    if (findingsWithEvents.length === 0) {
      doc.addPage();
      doc.fontSize(18)
         .fillColor('#4CAF50')
         .font('Helvetica-Bold')
         .text('✓ No Security Findings', { align: 'center' });

      doc.moveDown(1);
      doc.fontSize(12)
         .fillColor('#666')
         .font('Helvetica')
         .text('All security detections passed without triggering any alerts.', { align: 'center' });

      return;
    }

    findingsWithEvents.forEach((finding, index) => {
      doc.addPage();

      // Finding title
      doc.fontSize(18)
         .fillColor('#1976D2')
         .font('Helvetica-Bold')
         .text(`${index + 1}. ${finding.title}`);

      doc.moveDown(0.5);

      // Description
      if (finding.description) {
        doc.fontSize(10)
           .fillColor('#666')
           .font('Helvetica')
           .text(finding.description, { align: 'justify' });

        doc.moveDown(1);
      }

      // Threat information
      if (finding.threat) {
        const tactics = Array.isArray(finding.threat.Tactic)
          ? finding.threat.Tactic.join(', ')
          : finding.threat.Tactic;

        doc.fontSize(10)
           .fillColor('#333')
           .font('Helvetica-Bold')
           .text('MITRE ATT&CK Tactic: ', { continued: true });

        doc.font('Helvetica')
           .fillColor('#666')
           .text(tactics || 'N/A');

        doc.moveDown(1);
      }

      // Event count badge
      doc.fontSize(10)
         .fillColor('#333')
         .font('Helvetica-Bold')
         .text('Events Found: ', { continued: true });

      doc.fillColor('#F44336')
         .text(finding.events.length.toString());

      doc.moveDown(1.5);

      // Events table header
      doc.fontSize(11)
         .fillColor('#FFF')
         .font('Helvetica-Bold');

      const tableTop = doc.y;
      doc.rect(this.pageMargin, tableTop, doc.page.width - (this.pageMargin * 2), 25)
         .fill('#1976D2');

      doc.text('Event Details', this.pageMargin + 10, tableTop + 7);

      doc.y = tableTop + 30;

      // Display events (limit to first 10)
      const eventsToShow = finding.events.slice(0, 10);
      eventsToShow.forEach((event, eventIndex) => {
        // Check if we need a new page
        if (doc.y > doc.page.height - 150) {
          doc.addPage();
        }

        const eventY = doc.y;

        // Event box
        doc.roundedRect(this.pageMargin, eventY, doc.page.width - (this.pageMargin * 2), 'auto', 3)
           .stroke('#E0E0E0');

        doc.fontSize(9)
           .fillColor('#333')
           .font('Helvetica-Bold')
           .text(`Event ${eventIndex + 1}`, this.pageMargin + 10, eventY + 10);

        doc.moveDown(0.3);

        // Event details
        const leftColumn = this.pageMargin + 10;
        const rightColumn = this.pageMargin + 300;
        let currentY = doc.y;

        doc.fontSize(9)
           .fillColor('#666')
           .font('Helvetica');

        // Time
        doc.text('Time:', leftColumn, currentY, { continued: true });
        doc.font('Helvetica-Bold')
           .fillColor('#333')
           .text(` ${new Date(event.published).toLocaleString()}`, { continued: false });
        currentY += 12;

        // Actor
        if (event.actor?.alternateId) {
          doc.font('Helvetica')
             .fillColor('#666')
             .text('Actor:', leftColumn, currentY, { continued: true });
          doc.font('Helvetica-Bold')
             .fillColor('#333')
             .text(` ${event.actor.alternateId}`, { continued: false });
          currentY += 12;
        }

        // IP Address
        if (event.client?.ipAddress) {
          doc.font('Helvetica')
             .fillColor('#666')
             .text('IP Address:', leftColumn, currentY, { continued: true });
          doc.font('Helvetica-Bold')
             .fillColor('#333')
             .text(` ${event.client.ipAddress}`, { continued: false });
          currentY += 12;
        }

        // Location
        if (event.client?.geographicalContext) {
          const geo = event.client.geographicalContext;
          const location = [geo.city, geo.state, geo.country].filter(Boolean).join(', ');
          if (location) {
            doc.font('Helvetica')
               .fillColor('#666')
               .text('Location:', leftColumn, currentY, { continued: true });
            doc.font('Helvetica-Bold')
               .fillColor('#333')
               .text(` ${location}`, { continued: false });
            currentY += 12;
          }
        }

        // Outcome
        if (event.outcome) {
          doc.font('Helvetica')
             .fillColor('#666')
             .text('Outcome:', leftColumn, currentY, { continued: true });

          const outcomeColor = event.outcome.result === 'SUCCESS' ? '#4CAF50' :
                               event.outcome.result === 'FAILURE' ? '#F44336' : '#666';
          doc.font('Helvetica-Bold')
             .fillColor(outcomeColor)
             .text(` ${event.outcome.result}`, { continued: false });
          currentY += 12;
        }

        doc.y = currentY + 10;
        doc.moveDown(0.5);
      });

      if (finding.events.length > 10) {
        doc.fontSize(9)
           .fillColor('#999')
           .font('Helvetica-Oblique')
           .text(`... and ${finding.events.length - 10} more event(s)`, { align: 'center' });
      }

      // False positives
      if (finding.false_positives && finding.false_positives.length > 0) {
        doc.moveDown(1);
        doc.fontSize(10)
           .fillColor('#333')
           .font('Helvetica-Bold')
           .text('False Positives to Consider:');

        doc.fontSize(9)
           .fillColor('#666')
           .font('Helvetica');

        finding.false_positives.forEach(fp => {
          doc.text(`• ${fp}`, { indent: 15 });
        });
      }
    });
  }

  addFooter(doc) {
    const pages = doc.bufferedPageRange();

    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);

      // Footer line
      doc.moveTo(this.pageMargin, doc.page.height - 40)
         .lineTo(doc.page.width - this.pageMargin, doc.page.height - 40)
         .stroke('#E0E0E0');

      // Footer text
      doc.fontSize(8)
         .fillColor('#999')
         .font('Helvetica')
         .text(
           'Generated by Okta Security Health Check',
           this.pageMargin,
           doc.page.height - 30,
           { align: 'left' }
         );

      doc.text(
        `Page ${i + 1} of ${pages.count}`,
        this.pageMargin,
        doc.page.height - 30,
        { align: 'right' }
      );
    }
  }
}

module.exports = PDFGenerator;
