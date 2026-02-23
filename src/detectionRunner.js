const chalk = require('chalk');
const PDFGenerator = require('./pdfGenerator');
const CorrelationAnalyzer = require('./correlationAnalyzer');
const gui = require('./terminalGui');

class DetectionRunner {
  constructor(oktaClient, config) {
    this.oktaClient = oktaClient;
    this.config = config;
    this.pdfGenerator = new PDFGenerator();
    this.correlationAnalyzer = new CorrelationAnalyzer();
  }

  async runAllDetections(detections) {
    const executable = detections.filter(d => d.queryType === 'OIE');
    const detectionCount = executable.filter(d => d.sourceType === 'detection').length;
    const huntCount = executable.filter(d => d.sourceType === 'hunt').length;

    gui.section('Okta Security Detection Scanner');
    gui.log(`{green-fg}🚀 Running ${executable.length} security checks (${detectionCount} detections, ${huntCount} hunts)...{/green-fg}\n`);

    const results = {
      total: executable.length,
      success: 0,
      failed: 0,
      withFindings: 0,
      totalFindings: 0,
      detectionResults: []
    };

    for (let i = 0; i < executable.length; i++) {
      const detection = executable[i];
      try {
        const detectionResult = await this.runDetectionWithEvents(detection, i + 1, executable.length);
        results.success++;

        results.detectionResults.push(detectionResult);

        if (detectionResult.events.length > 0) {
          results.withFindings++;
          results.totalFindings += detectionResult.events.length;
        }
      } catch (error) {
        results.failed++;
        gui.error(`Error: ${error.message}\n`);

        // Still add to results even if failed
        results.detectionResults.push({
          title: detection.title,
          description: detection.description,
          threat: detection.threat,
          false_positives: detection.false_positives,
          events: [],
          error: error.message
        });
      }

      // Small delay between detections
      await this.sleep(200);
    }

    // Perform correlation analysis
    const correlationAnalysis = this.correlationAnalyzer.analyzeFindings(results.detectionResults);
    results.correlationAnalysis = correlationAnalysis;

    // Generate PDF report
    gui.section('Generating PDF Report');
    gui.progress('Creating PDF document');

    try {
      const pdfPath = await this.pdfGenerator.generateReport(results, this.config);
      gui.success(`PDF report generated: ${pdfPath}`);
    } catch (error) {
      gui.error(`Failed to generate PDF: ${error.message}`);
    }

    return results;
  }

  async runDetectionWithEvents(detection, index, total) {
    gui.detection(index, total, detection.title, detection.sourceType);

    // Description
    if (detection.description) {
      gui.log('\n{white-fg}📝 Description:{/white-fg}');
      const desc = detection.description.trim().split('\n').map(line => '  ' + line).join('\n');
      gui.log(`{gray-fg}${desc}{/gray-fg}`);
    }

    // Execute query
    gui.progress('Executing query');

    let events = [];
    try {
      events = await this.oktaClient.querySystemLog(
        detection.query,
        this.config.query?.since,
        this.config.query?.limit || 100
      );
    } catch (error) {
      gui.error(`Error: ${error.message}`);
      gui.warning('⊘ Skipping this detection due to query error\n');

      // Return empty result for this detection
      return {
        title: detection.title,
        sourceType: detection.sourceType,
        description: detection.description,
        threat: detection.threat,
        false_positives: detection.false_positives,
        events: [],
        error: error.message
      };
    }

    gui.log(`\n{bold}{white-fg}📊 Results: ${events.length} event(s) found{/white-fg}{/bold}`);
    gui.finding(events.length);

    if (events.length > 0) {
      // Show first few events
      const displayCount = Math.min(events.length, 5);
      for (let i = 0; i < displayCount; i++) {
        gui.event(i + 1, events[i]);
      }

      if (events.length > displayCount) {
        gui.log(`{gray-fg}  ... and ${events.length - displayCount} more event(s){/gray-fg}\n`);
      }

      // Analysis
      gui.log('\n{white-fg}🔍 Analysis:{/white-fg}');
      gui.log(`{yellow-fg}  ⚠️  ${events.length} event(s) matching this detection pattern{/yellow-fg}`);
      gui.log(`{gray-fg}  Review these events to determine if they represent genuine security concerns{/gray-fg}`);
    }

    // False positives
    if (detection.false_positives) {
      gui.log('\n{white-fg}⚡ False Positives:{/white-fg}');
      const fps = Array.isArray(detection.false_positives)
        ? detection.false_positives
        : [detection.false_positives];
      fps.forEach(fp => {
        gui.log(`{gray-fg}  - ${fp.trim()}{/gray-fg}`);
      });
    }

    // Return detection result with events
    return {
      title: detection.title,
      sourceType: detection.sourceType,
      description: detection.description,
      threat: detection.threat,
      false_positives: detection.false_positives,
      events: events
    };
  }

  async runDetection(detection, index, total) {
    const result = await this.runDetectionWithEvents(detection, index, total);
    return result.events.length;
  }

  printSummary(results) {
    console.log(chalk.bold.cyan('\n' + '='.repeat(80)));
    console.log(chalk.bold.cyan('SECURITY SCAN SUMMARY'));
    console.log(chalk.bold.cyan('='.repeat(80)));
    console.log(chalk.white(`\nDetections Executed: ${results.total}`));
    console.log(chalk.green(`✓ Successful: ${results.success}`));
    if (results.failed > 0) {
      console.log(chalk.red(`✗ Failed: ${results.failed}`));
    }

    console.log(chalk.bold.white(`\nSecurity Findings: ${results.withFindings} detection(s) triggered`));
    console.log(chalk.yellow(`Total Events: ${results.totalFindings}`));

    if (results.findings.length > 0) {
      console.log(chalk.bold.yellow('\n⚠️  DETECTIONS WITH FINDINGS:\n'));

      results.findings.forEach((finding, i) => {
        console.log(chalk.yellow(`${i + 1}. ${finding.title}`));
        console.log(chalk.white(`   Events Found: ${finding.count}`));

        if (finding.threat) {
          if (finding.threat.Tactic) {
            const tactics = Array.isArray(finding.threat.Tactic)
              ? finding.threat.Tactic.join(', ')
              : finding.threat.Tactic;
            console.log(chalk.gray(`   Tactic: ${tactics}`));
          }
        }
        console.log('');
      });

      console.log(chalk.bold.yellow('⚠️  Action Required: Review the findings above for potential security issues'));
      console.log(chalk.gray('   Scroll up to see detailed event information for each detection\n'));
    } else {
      console.log(chalk.bold.green('\n✓ No security findings detected - All detections passed'));
      console.log(chalk.gray('   Your Okta environment shows no signs of the monitored security threats\n'));
    }

    console.log(chalk.cyan('='.repeat(80) + '\n'));
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = DetectionRunner;
