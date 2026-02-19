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
        // Validate findings structure
        if (!findings || typeof findings !== 'object') {
          throw new Error('Invalid findings object');
        }
        if (!Array.isArray(findings.detectionResults)) {
          findings.detectionResults = [];
        }

        const doc = new PDFDocument({
          size: 'A4',
          margins: {
            top: 50,
            bottom: 50,
            left: 50,
            right: 50
          }
        });

        const stream = fs.createWriteStream(filepath);
        doc.pipe(stream);

        // Generate report content
        this.addTitlePage(doc, timestamp, config);
        this.addExecutiveSummary(doc, findings);
        this.addFindingsDetail(doc, findings);

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

    // Scan details
    doc.fontSize(12)
       .fillColor('#333')
       .font('Helvetica-Bold')
       .text('Scan Date:');

    doc.fontSize(11)
       .font('Helvetica')
       .fillColor('#666')
       .text(timestamp.toLocaleString(), { indent: 20 });

    doc.moveDown(0.5);

    doc.fontSize(12)
       .fillColor('#333')
       .font('Helvetica-Bold')
       .text('Okta Tenant:');

    doc.fontSize(11)
       .font('Helvetica')
       .fillColor('#666')
       .text(config.okta?.domain || 'Unknown', { indent: 20 });

    doc.moveDown(0.5);

    doc.fontSize(12)
       .fillColor('#333')
       .font('Helvetica-Bold')
       .text('Query Period:');

    const since = config.query?.since || 'Last 90 days';
    doc.fontSize(11)
       .font('Helvetica')
       .fillColor('#666')
       .text(since, { indent: 20 });
  }

  addExecutiveSummary(doc, findings) {
    doc.addPage();

    // Section title
    doc.fontSize(24)
       .fillColor('#1976D2')
       .font('Helvetica-Bold')
       .text('Executive Summary');

    doc.moveDown(1.5);

    // Calculate statistics
    const detectionResults = findings.detectionResults || [];
    const totalDetections = detectionResults.length;
    const detectionsWithFindings = detectionResults.filter(d => d.events && d.events.length > 0).length;
    const totalEvents = detectionResults.reduce((sum, d) => sum + (d.events ? d.events.length : 0), 0);

    // Statistics
    doc.fontSize(14)
       .fillColor('#333')
       .font('Helvetica-Bold')
       .text('Scan Results:');

    doc.moveDown(0.5);

    doc.fontSize(11)
       .fillColor('#666')
       .font('Helvetica')
       .text(`• Total Detections Executed: ${totalDetections}`)
       .text(`• Detections Triggered: ${detectionsWithFindings}`)
       .text(`• Total Events Found: ${totalEvents}`);

    doc.moveDown(1.5);

    // Risk level
    let riskLevel, riskColor, riskText;
    if (detectionsWithFindings === 0) {
      riskLevel = 'LOW RISK';
      riskColor = '#4CAF50';
      riskText = 'No security threats detected. Your Okta environment appears secure.';
    } else if (detectionsWithFindings <= 3) {
      riskLevel = 'MODERATE RISK';
      riskColor = '#FF9800';
      riskText = 'Some security events detected. Review findings to ensure they are legitimate.';
    } else {
      riskLevel = 'HIGH RISK';
      riskColor = '#F44336';
      riskText = 'Multiple security threats detected. Immediate review recommended.';
    }

    doc.fontSize(14)
       .fillColor('#333')
       .font('Helvetica-Bold')
       .text('Risk Assessment:');

    doc.moveDown(0.5);

    doc.fontSize(18)
       .fillColor(riskColor)
       .font('Helvetica-Bold')
       .text(riskLevel);

    doc.fontSize(11)
       .fillColor('#666')
       .font('Helvetica')
       .text(riskText);

    doc.moveDown(2);

    // Key findings
    if (detectionsWithFindings > 0) {
      doc.fontSize(14)
         .fillColor('#333')
         .font('Helvetica-Bold')
         .text('Key Findings:');

      doc.moveDown(0.5);

      const findingsWithEvents = detectionResults
        .filter(d => d.events && d.events.length > 0)
        .sort((a, b) => b.events.length - a.events.length);

      findingsWithEvents.forEach((finding) => {
        doc.fontSize(11)
           .fillColor('#1976D2')
           .font('Helvetica-Bold')
           .text(`• ${finding.title}`, { indent: 20 });

        doc.fontSize(10)
           .fillColor('#666')
           .font('Helvetica')
           .text(`${finding.events.length} event(s) found`, { indent: 30 });
      });
    }
  }

  addFindingsDetail(doc, findings) {
    const detectionResults = findings.detectionResults || [];
    const findingsWithEvents = detectionResults.filter(d => d.events && d.events.length > 0);

    if (findingsWithEvents.length === 0) {
      doc.addPage();
      doc.fontSize(18)
         .fillColor('#4CAF50')
         .font('Helvetica-Bold')
         .text('No Security Findings', { align: 'center' });

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
      if (finding.threat && finding.threat.Tactic) {
        const tactics = Array.isArray(finding.threat.Tactic)
          ? finding.threat.Tactic.join(', ')
          : finding.threat.Tactic;

        doc.fontSize(10)
           .fillColor('#333')
           .font('Helvetica-Bold')
           .text(`MITRE ATT&CK Tactic: ${tactics}`);

        doc.moveDown(1);
      }

      // Event count
      doc.fontSize(11)
         .fillColor('#333')
         .font('Helvetica-Bold')
         .text(`Events Found: ${finding.events.length}`);

      doc.moveDown(1);

      // Events header
      doc.fontSize(12)
         .fillColor('#1976D2')
         .font('Helvetica-Bold')
         .text('Event Details:');

      doc.moveDown(0.5);

      // Display events (limit to first 10)
      const eventsToShow = finding.events.slice(0, 10);
      eventsToShow.forEach((event, eventIndex) => {
        // Check if we need a new page
        if (doc.y > 700) {
          doc.addPage();
        }

        doc.fontSize(10)
           .fillColor('#333')
           .font('Helvetica-Bold')
           .text(`Event ${eventIndex + 1}:`);

        doc.fontSize(9)
           .fillColor('#666')
           .font('Helvetica');

        // Time
        if (event.published) {
          doc.text(`  Time: ${new Date(event.published).toLocaleString()}`);
        }

        // Event Type
        if (event.eventType) {
          doc.text(`  Event Type: ${event.eventType}`);
        }

        // Actor
        if (event.actor?.alternateId) {
          doc.text(`  Actor: ${event.actor.alternateId}`);
        }

        // IP Address
        if (event.client?.ipAddress) {
          doc.text(`  IP Address: ${event.client.ipAddress}`);
        }

        // Location
        if (event.client?.geographicalContext) {
          const geo = event.client.geographicalContext;
          const location = [geo.city, geo.state, geo.country].filter(Boolean).join(', ');
          if (location) {
            doc.text(`  Location: ${location}`);
          }
        }

        // Outcome
        if (event.outcome) {
          doc.text(`  Outcome: ${event.outcome.result}`);
          if (event.outcome.reason) {
            doc.text(`  Reason: ${event.outcome.reason}`);
          }
        }

        doc.moveDown(0.5);
      });

      if (finding.events.length > 10) {
        doc.fontSize(9)
           .fillColor('#999')
           .font('Helvetica-Oblique')
           .text(`... and ${finding.events.length - 10} more event(s)`);
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
          doc.text(`  • ${fp}`);
        });
      }
    });

    // Footer
    doc.addPage();
    doc.fontSize(12)
       .fillColor('#666')
       .font('Helvetica')
       .text('End of Report', { align: 'center' });

    doc.moveDown(1);

    doc.fontSize(9)
       .fillColor('#999')
       .text(`Generated by Okta Security Health Check on ${new Date().toLocaleString()}`, { align: 'center' });
  }
}

module.exports = PDFGenerator;
