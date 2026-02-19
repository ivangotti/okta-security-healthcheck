const chalk = require('chalk');
const PDFGenerator = require('./pdfGenerator');

class DetectionRunner {
  constructor(oktaClient, config) {
    this.oktaClient = oktaClient;
    this.config = config;
    this.pdfGenerator = new PDFGenerator();
  }

  async runAllDetections(detections) {
    const executable = detections.filter(d => d.queryType === 'OIE');

    console.log(chalk.bold.cyan('\n' + '='.repeat(80)));
    console.log(chalk.bold.cyan('Okta Security Detection Scanner'));
    console.log(chalk.bold.cyan('='.repeat(80)));
    console.log(chalk.green(`Running ${executable.length} security detections...\n`));

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
        console.log(chalk.red(`Error: ${error.message}\n`));

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

    // Generate PDF report
    console.log(chalk.bold.cyan('\n' + '='.repeat(80)));
    console.log(chalk.cyan('Generating PDF report...'));

    try {
      const pdfPath = await this.pdfGenerator.generateReport(results, this.config);
      console.log(chalk.green(`✓ PDF report generated: ${pdfPath}`));
    } catch (error) {
      console.log(chalk.red(`✗ Failed to generate PDF: ${error.message}`));
    }

    console.log(chalk.bold.cyan('='.repeat(80) + '\n'));

    return results;
  }

  async runDetectionWithEvents(detection, index, total) {
    console.log(chalk.bold.cyan('\n' + '='.repeat(80)));
    console.log(chalk.bold.cyan(`[${index}/${total}] ${detection.title}`));
    console.log(chalk.bold.cyan('='.repeat(80)));

    // Description
    if (detection.description) {
      console.log(chalk.white('\nDescription:'));
      const desc = detection.description.trim().split('\n').map(line => '  ' + line).join('\n');
      console.log(chalk.gray(desc));
    }

    // Execute query
    console.log(chalk.white('\nExecuting query...'));

    const events = await this.oktaClient.querySystemLog(
      detection.query,
      this.config.query?.since,
      this.config.query?.limit || 100
    );

    console.log(chalk.bold.white(`\nResults: ${events.length} event(s) found`));

    if (events.length > 0) {
      console.log(chalk.bold.yellow('\n⚠️  FINDINGS DETECTED\n'));

      // Show first few events
      const displayCount = Math.min(events.length, 5);
      for (let i = 0; i < displayCount; i++) {
        this.displayEvent(events[i], i + 1);
      }

      if (events.length > displayCount) {
        console.log(chalk.gray(`  ... and ${events.length - displayCount} more event(s)\n`));
      }

      // Analysis
      console.log(chalk.white('Analysis:'));
      console.log(chalk.yellow(`  ⚠️  ${events.length} event(s) matching this detection pattern`));
      console.log(chalk.gray(`  Review these events to determine if they represent genuine security concerns`));
    } else {
      console.log(chalk.green('\n✓ No events found - This detection did not trigger\n'));
    }

    // False positives
    if (detection.false_positives) {
      console.log(chalk.white('False Positives:'));
      const fps = Array.isArray(detection.false_positives)
        ? detection.false_positives
        : [detection.false_positives];
      fps.forEach(fp => {
        console.log(chalk.gray('  - ' + fp.trim()));
      });
    }

    console.log(chalk.cyan('='.repeat(80)));

    // Return detection result with events
    return {
      title: detection.title,
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

  displayEvent(event, index) {
    console.log(chalk.bold.yellow(`Event ${index}:`));
    console.log(`  ${chalk.bold.cyan('Time:')} ${chalk.white(event.published)}`);
    console.log(`  ${chalk.bold.cyan('Event Type:')} ${chalk.white(event.eventType)}`);

    if (event.actor && event.actor.alternateId) {
      console.log(`  ${chalk.bold.cyan('Actor:')} ${chalk.white(event.actor.alternateId)}`);
    }

    if (event.client) {
      if (event.client.ipAddress) {
        console.log(`  ${chalk.bold.cyan('IP Address:')} ${chalk.white(event.client.ipAddress)}`);
      }
      if (event.client.geographicalContext) {
        const geo = event.client.geographicalContext;
        const location = [geo.city, geo.state, geo.country]
          .filter(Boolean)
          .join(', ');
        if (location) {
          console.log(`  ${chalk.bold.cyan('Location:')} ${chalk.white(location)}`);
        }
      }
    }

    if (event.outcome) {
      const outcomeColor = event.outcome.result === 'SUCCESS' ? chalk.green :
                          event.outcome.result === 'FAILURE' ? chalk.red : chalk.white;
      console.log(`  ${chalk.bold.cyan('Outcome:')} ${outcomeColor(event.outcome.result)}`);
      if (event.outcome.reason) {
        console.log(`  ${chalk.bold.cyan('Reason:')} ${chalk.white(event.outcome.reason)}`);
      }
    }

    if (event.target && event.target.length > 0) {
      const targetNames = event.target
        .map(t => t.displayName || t.alternateId)
        .filter(Boolean)
        .join(', ');
      if (targetNames) {
        console.log(`  ${chalk.bold.cyan('Target:')} ${chalk.white(targetNames)}`);
      }
    }

    console.log('');
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
